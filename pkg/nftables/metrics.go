//go:build linux
// +build linux

package nftables

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

type Counter struct {
	Nftables []struct {
		Rule struct {
			Expr []struct {
				Counter *struct {
					Packets int `json:"packets"`
					Bytes   int `json:"bytes"`
				} `json:"counter,omitempty"`
			} `json:"expr"`
		} `json:"rule,omitempty"`
	} `json:"nftables"`
}

type Set struct {
	Nftables []struct {
		Set struct {
			Elem []struct {
				Elem struct{} `json:"elem"`
			} `json:"elem"`
		} `json:"set,omitempty"`
	} `json:"nftables"`
}

func (c *nftContext) collectDroppedPackets(path string, chain string) (int, int, error) {
	cmd := exec.Command(path, "-j", "list", "chain", c.ipFamily(), c.tableName, chain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("while running %s: %w", cmd.String(), err)
	}

	parsedOut := Counter{}
	if err := json.Unmarshal(out, &parsedOut); err != nil {
		return 0, 0, err
	}

	for _, r := range parsedOut.Nftables {
		for _, expr := range r.Rule.Expr {
			if expr.Counter != nil {
				return expr.Counter.Packets, expr.Counter.Bytes, nil
			}
		}
	}

	return 0, 0, nil
}

func (c *nftContext) ipFamily() string {
	return c.version
}

func (c *nftContext) collectActiveBannedIPs(path string) (int, error) {
	cmd := exec.Command(path, "-j", "list", "set", c.ipFamily(), c.tableName, c.blacklist)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("while running %s: %w", cmd.String(), err)
	}

	set := Set{}
	if err := json.Unmarshal(out, &set); err != nil {
		return 0, err
	}

	ret := 0
	for _, r := range set.Nftables {
		ret += len(r.Set.Elem)
	}

	return ret, nil
}

func (c *nftContext) collectDropped(path string, droppedPackets *int, droppedBytes *int, banned *int) {
	if c.conn == nil {
		return
	}

	if c.setOnly {
		pkt, byt, err := c.collectDroppedPackets(path, c.chainName)
		if err != nil {
			log.Errorf("can't collect dropped packets for %s from nft: %s", c.version, err)
		}
		*droppedPackets += pkt
		*droppedBytes += byt
	} else {
		pkt, byt, err := c.collectDroppedPackets(path, c.chainName+"-"+c.hook)
		if err != nil {
			log.Errorf("can't collect dropped packets for %s from nft: %s", c.version, err)
		}
		*droppedPackets += pkt
		*droppedBytes += byt
	}

	tmpBanned, err := c.collectActiveBannedIPs(path)
	if err != nil {
		log.Errorf("can't collect total banned IPs for %s from nft: %s", c.version, err)
	} else {
		*banned += tmpBanned
	}
}

func (n *nft) CollectMetrics() {
	path, err := exec.LookPath("nft")
	if err != nil {
		log.Error("can't monitor dropped packets: ", err)
		return
	}

	cmd := exec.Command(path, "-j", "list", "tables")
	_, err = cmd.CombinedOutput()
	if err != nil {
		log.Warningf("nft -j is not supported (requires 0.9.7), nftables metrics are disabled")
		return
	}

	t := time.NewTicker(metrics.MetricCollectionInterval)

	for range t.C {
		var ip4DroppedPackets, ip4DroppedBytes, bannedIP4,
			ip6DroppedPackets, ip6DroppedBytes, bannedIP6 int

		for _, context := range n.contexts {
			if context.version == "ip" {
				context.collectDropped(path, &ip4DroppedPackets, &ip4DroppedBytes, &bannedIP4)
			} else if context.version == "ip6" {
				context.collectDropped(path, &ip6DroppedPackets, &ip6DroppedBytes, &bannedIP6)
			}
		}

		metrics.TotalDroppedPackets.Set(float64(ip4DroppedPackets + ip6DroppedPackets))
		metrics.TotalDroppedBytes.Set(float64(ip6DroppedBytes + ip4DroppedBytes))
		metrics.TotalActiveBannedIPs.Set(float64(bannedIP4 + bannedIP6))
	}
}
