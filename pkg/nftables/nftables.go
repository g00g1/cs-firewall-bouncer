//go:build linux
// +build linux

package nftables

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/nftables"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
)

const (
	chunkSize      = 200
	defaultTimeout = "4h"
)

type nft struct {
	contexts          []*nftContext
	decisionsToAdd    []*models.Decision
	decisionsToDelete []*models.Decision
	DenyAction        string
	DenyLog           bool
	DenyLogPrefix     string
}

func NewNFTables(config *cfg.BouncerConfig) (*nft, error) {
	contexts := make([]*nftContext, len(config.Nftables.Targets))
	for i, target := range config.Nftables.Targets {
		contexts[i] = NewNFTContext(&target)
	}

	ret := &nft{
		contexts:      contexts,
		DenyAction:    config.DenyAction,
		DenyLog:       config.DenyLog,
		DenyLogPrefix: config.DenyLogPrefix,
	}

	return ret, nil
}

func (n *nft) Init() error {
	log.Debug("nftables: Init()")

	for _, context := range n.contexts {
		if err := context.init(n.DenyLog, n.DenyLogPrefix, n.DenyAction); err != nil {
			return err
		}
	}

	log.Infof("nftables initiated")

	return nil
}

func (n *nft) Add(decision *models.Decision) error {
	n.decisionsToAdd = append(n.decisionsToAdd, decision)
	return nil
}

func (n *nft) getBannedState() (map[string]struct{}, error) {
	banned := make(map[string]struct{})
	for _, context := range n.contexts {
		if err := context.setBanned(banned); err != nil {
			return nil, err
		}
	}

	return banned, nil
}

func (n *nft) reset() {
	n.decisionsToAdd = make([]*models.Decision, 0)
	n.decisionsToDelete = make([]*models.Decision, 0)
}

func (n *nft) commitDeletedDecisions() error {
	banned, err := n.getBannedState()
	if err != nil {
		return fmt.Errorf("failed to get current state: %w", err)
	}

	ip4 := []nftables.SetElement{}
	ip6 := []nftables.SetElement{}

	var (
		intervalStart []byte
		intervalEnd   []byte
		setElement    nftables.SetElement
	)

	n.decisionsToDelete = normalizedDecisions(n.decisionsToDelete)

	for _, decision := range n.decisionsToDelete {
		cidr := netip.MustParsePrefix(*decision.Value)
		if _, ok := banned[cidr.String()]; !ok {
			log.Debugf("not deleting %s since it's not in the set", cidr.String())
			continue
		}

		log.Tracef("adding %s to buffer", cidr.String())

		intervalStart = cidr.Addr().AsSlice()
		intervalEnd = getPrefixLastAddr(&cidr).AsSlice()
		setElement = nftables.SetElement{Key: intervalStart, KeyEnd: intervalEnd}

		if cidr.Addr().Is6() {
			ip6 = append(ip6, setElement)
		} else if cidr.Addr().Is4() {
			ip4 = append(ip4, setElement)
		}
	}

	for _, context := range n.contexts {
		if context.version == "ip" && len(ip4) > 0 {
			log.Debugf("removing %d %s elements from set", len(ip4), "ip")
			if err := context.deleteElements(ip4); err != nil {
				return err
			}
		} else if context.version == "ip6" && len(ip6) > 0 {
			log.Debugf("removing %d %s elements from set", len(ip6), "ip6")
			if err := context.deleteElements(ip6); err != nil {
				return err
			}
		}
	}

	return nil
}

func (n *nft) commitAddedDecisions() error {
	banned, err := n.getBannedState()
	if err != nil {
		return fmt.Errorf("failed to get current state: %w", err)
	}

	ip4 := []nftables.SetElement{}
	ip6 := []nftables.SetElement{}

	var (
		intervalStart []byte
		intervalEnd   []byte
		setElement    nftables.SetElement
	)

	n.decisionsToAdd = normalizedDecisions(n.decisionsToAdd)

	for _, decision := range n.decisionsToAdd {
		cidr := netip.MustParsePrefix(*decision.Value)
		if _, ok := banned[cidr.String()]; ok {
			log.Debugf("not adding %s since it's already in the set", cidr.String())
			continue
		}

		t, _ := time.ParseDuration(*decision.Duration)

		log.Tracef("adding %s to buffer", cidr.String())

		intervalStart = cidr.Addr().AsSlice()
		intervalEnd = getPrefixLastAddr(&cidr).AsSlice()
		setElement = nftables.SetElement{Key: intervalStart, KeyEnd: intervalEnd, Timeout: t}

		if cidr.Addr().Is6() {
			ip6 = append(ip6, setElement)
		} else if cidr.Addr().Is4() {
			ip4 = append(ip4, setElement)
		}
	}

	for _, context := range n.contexts {
		if context.version == "ip" && len(ip4) > 0 {
			if err := context.addElements(ip4); err != nil {
				return err
			}
		} else if context.version == "ip6" && len(ip6) > 0 {
			if err := context.addElements(ip6); err != nil {
				return err
			}
		}
	}

	return nil
}

// FIXME: added decisions got lost on failing to delete decisions
func (n *nft) Commit() error {
	defer n.reset()

	if err := n.commitDeletedDecisions(); err != nil {
		return err
	}

	if err := n.commitAddedDecisions(); err != nil {
		return err
	}

	return nil
}

// remove duplicates, normalize decision timeouts, keep the longest decision when dups are present.
func normalizedDecisions(decisions []*models.Decision) []*models.Decision {
	vals := make(map[string]time.Duration)
	finalDecisions := make([]*models.Decision, 0)

	var (
		scope    string
		rawValue []string
	)

	for _, d := range decisions {
		switch scope = strings.ToLower(*d.Scope); scope {
		case "ip":
		case "range":
			break
		default:
			continue
		}

		if scope == "ip" {
			rawValue = strings.Split(*d.Value, "/")

			if len(rawValue) >= 2 {
				rawValue[1] = "32"

				if len(rawValue) > 2 {
					rawValue = rawValue[:1]
				}
			} else {
				rawValue = append(rawValue, "32")
			}

			*d.Value = strings.Join(rawValue, "")
		}

		if _, err := netip.ParsePrefix(*d.Value); err != nil {
			continue
		}

		t, err := time.ParseDuration(*d.Duration)
		if err != nil {
			t, _ = time.ParseDuration(defaultTimeout)
		}

		vals[*d.Value] = maxTime(t, vals[*d.Value])
	}

	// FIXME: aggregate final prefixes to prevent collisions
	for cidr, duration := range vals {
		d := duration.String()
		i := cidr // copy it because we don't same value for all decisions as `cidr` is same pointer :)

		finalDecisions = append(finalDecisions, &models.Decision{
			Duration: &d,
			Value:    &i,
		})
	}

	return finalDecisions
}

func getPrefixLastAddr(net *netip.Prefix) netip.Addr {
	ipNet := net.Addr()      // prefix's first IP address
	netBits := net.Bits()    // length of the prefix (i.e. 24 bits)
	ipBits := ipNet.BitLen() // size of the IP address (i.e. 32 bits)
	mask := ipBits - netBits
	rawIp := ipNet.AsSlice()

	for i := (ipBits / 8) - 1; mask > 0; i-- {
		rawIp[i] |= 0xFF & ((1 << min(8, mask)) - 1)
		mask -= 8
	}

	ipNetLast, _ := netip.AddrFromSlice(rawIp)

	return ipNetLast
}

func (n *nft) Delete(decision *models.Decision) error {
	n.decisionsToDelete = append(n.decisionsToDelete, decision)
	return nil
}

func (n *nft) ShutDown() error {
	for _, context := range n.contexts {
		if err := context.shutDown(); err != nil {
			return err
		}
	}

	return nil
}

func maxTime(a time.Duration, b time.Duration) time.Duration {
	if a > b {
		return a
	}

	return b
}
