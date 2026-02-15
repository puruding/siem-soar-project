// Package matcher provides Radix tree for IP address and CIDR matching.
package matcher

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/siem-soar-platform/services/ti/internal/ioc"
)

// RadixNode represents a node in the radix tree.
type RadixNode struct {
	left   *RadixNode // 0 bit
	right  *RadixNode // 1 bit
	ioc    *ioc.IOC
	prefix *net.IPNet
	isEnd  bool
}

// RadixTree implements a radix tree for IP/CIDR matching.
type RadixTree struct {
	root4 *RadixNode // IPv4 root
	root6 *RadixNode // IPv6 root
	count atomic.Int64
	mu    sync.RWMutex
}

// NewRadixTree creates a new radix tree.
func NewRadixTree() *RadixTree {
	return &RadixTree{
		root4: &RadixNode{},
		root6: &RadixNode{},
	}
}

// Insert adds an IP or CIDR to the radix tree.
func (rt *RadixTree) Insert(ipStr string, i *ioc.IOC) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Parse IP or CIDR
	ip, ipNet, err := rt.parseIPOrCIDR(ipStr)
	if err != nil {
		return false
	}

	// Get the appropriate root
	root := rt.root4
	if ip.To4() == nil {
		root = rt.root6
	}

	// Get bits to insert
	bits := rt.ipToBits(ip, ipNet)
	prefixLen, _ := ipNet.Mask.Size()

	// Traverse/create nodes
	node := root
	for i := 0; i < prefixLen; i++ {
		bit := bits[i]
		if bit == 0 {
			if node.left == nil {
				node.left = &RadixNode{}
			}
			node = node.left
		} else {
			if node.right == nil {
				node.right = &RadixNode{}
			}
			node = node.right
		}
	}

	node.isEnd = true
	node.ioc = i
	node.prefix = ipNet
	rt.count.Add(1)

	return true
}

// Search finds an exact IP match.
func (rt *RadixTree) Search(ipStr string) *ioc.IOC {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Get the appropriate root
	root := rt.root4
	ipv4 := ip.To4()
	if ipv4 == nil {
		root = rt.root6
	} else {
		ip = ipv4
	}

	// Get bits
	bits := rt.ipToBits(ip, nil)

	// Traverse tree
	node := root
	for _, bit := range bits {
		if bit == 0 {
			if node.left == nil {
				return nil
			}
			node = node.left
		} else {
			if node.right == nil {
				return nil
			}
			node = node.right
		}

		if node.isEnd && node.prefix != nil {
			// Check exact match
			if node.prefix.IP.Equal(ip) {
				ones, _ := node.prefix.Mask.Size()
				if ones == len(bits)*8 {
					return node.ioc
				}
			}
		}
	}

	if node.isEnd {
		return node.ioc
	}

	return nil
}

// SearchCIDR finds a CIDR that contains the given IP.
func (rt *RadixTree) SearchCIDR(ipStr string) *ioc.IOC {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Get the appropriate root
	root := rt.root4
	ipv4 := ip.To4()
	if ipv4 == nil {
		root = rt.root6
	} else {
		ip = ipv4
	}

	// Get bits
	bits := rt.ipToBits(ip, nil)

	// Traverse tree, tracking the most specific match
	var bestMatch *ioc.IOC
	node := root

	for _, bit := range bits {
		// Record match if this node is an endpoint
		if node.isEnd && node.ioc != nil {
			bestMatch = node.ioc
		}

		if bit == 0 {
			if node.left == nil {
				break
			}
			node = node.left
		} else {
			if node.right == nil {
				break
			}
			node = node.right
		}
	}

	// Check final node
	if node.isEnd && node.ioc != nil {
		bestMatch = node.ioc
	}

	return bestMatch
}

// Delete removes an IP or CIDR from the radix tree.
func (rt *RadixTree) Delete(ipStr string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	ip, ipNet, err := rt.parseIPOrCIDR(ipStr)
	if err != nil {
		return false
	}

	// Get the appropriate root
	root := rt.root4
	if ip.To4() == nil {
		root = rt.root6
	}

	bits := rt.ipToBits(ip, ipNet)
	prefixLen, _ := ipNet.Mask.Size()

	// Find and delete
	node := root
	var path []*RadixNode
	var pathBits []byte

	for i := 0; i < prefixLen; i++ {
		path = append(path, node)
		pathBits = append(pathBits, bits[i])

		if bits[i] == 0 {
			if node.left == nil {
				return false
			}
			node = node.left
		} else {
			if node.right == nil {
				return false
			}
			node = node.right
		}
	}

	if !node.isEnd {
		return false
	}

	node.isEnd = false
	node.ioc = nil
	node.prefix = nil
	rt.count.Add(-1)

	// Cleanup empty nodes
	for i := len(path) - 1; i >= 0; i-- {
		parent := path[i]
		bit := pathBits[i]

		var child *RadixNode
		if bit == 0 {
			child = parent.left
		} else {
			child = parent.right
		}

		// Remove child if it's empty
		if child != nil && !child.isEnd && child.left == nil && child.right == nil {
			if bit == 0 {
				parent.left = nil
			} else {
				parent.right = nil
			}
		} else {
			break
		}
	}

	return true
}

// Contains checks if an IP is in the radix tree (exact or CIDR match).
func (rt *RadixTree) Contains(ipStr string) bool {
	if rt.Search(ipStr) != nil {
		return true
	}
	return rt.SearchCIDR(ipStr) != nil
}

// Count returns the number of entries.
func (rt *RadixTree) Count() int64 {
	return rt.count.Load()
}

// Clear removes all entries from the radix tree.
func (rt *RadixTree) Clear() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.root4 = &RadixNode{}
	rt.root6 = &RadixNode{}
	rt.count.Store(0)
}

// List returns all IOCs in the radix tree.
func (rt *RadixTree) List() []*ioc.IOC {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var results []*ioc.IOC
	results = append(results, rt.collectIOCs(rt.root4)...)
	results = append(results, rt.collectIOCs(rt.root6)...)
	return results
}

func (rt *RadixTree) parseIPOrCIDR(ipStr string) (net.IP, *net.IPNet, error) {
	// Try parsing as CIDR
	ip, ipNet, err := net.ParseCIDR(ipStr)
	if err == nil {
		return ip, ipNet, nil
	}

	// Try parsing as IP
	ip = net.ParseIP(ipStr)
	if ip == nil {
		return nil, nil, err
	}

	// Create a /32 or /128 network
	ipv4 := ip.To4()
	if ipv4 != nil {
		ipNet = &net.IPNet{
			IP:   ipv4,
			Mask: net.CIDRMask(32, 32),
		}
	} else {
		ipNet = &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		}
	}

	return ip, ipNet, nil
}

func (rt *RadixTree) ipToBits(ip net.IP, ipNet *net.IPNet) []byte {
	// Normalize IP
	ipv4 := ip.To4()
	if ipv4 != nil {
		ip = ipv4
	}

	// Convert to bits
	var bits []byte
	for _, b := range ip {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) != 0 {
				bits = append(bits, 1)
			} else {
				bits = append(bits, 0)
			}
		}
	}

	return bits
}

func (rt *RadixTree) collectIOCs(node *RadixNode) []*ioc.IOC {
	if node == nil {
		return nil
	}

	var results []*ioc.IOC

	if node.isEnd && node.ioc != nil {
		results = append(results, node.ioc)
	}

	results = append(results, rt.collectIOCs(node.left)...)
	results = append(results, rt.collectIOCs(node.right)...)

	return results
}

// LPMResult represents a longest prefix match result.
type LPMResult struct {
	IOC       *ioc.IOC
	PrefixLen int
}

// LongestPrefixMatch finds the longest matching prefix for an IP.
func (rt *RadixTree) LongestPrefixMatch(ipStr string) *LPMResult {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	root := rt.root4
	ipv4 := ip.To4()
	if ipv4 == nil {
		root = rt.root6
	} else {
		ip = ipv4
	}

	bits := rt.ipToBits(ip, nil)

	var bestMatch *LPMResult
	node := root
	prefixLen := 0

	for _, bit := range bits {
		if node.isEnd && node.ioc != nil {
			bestMatch = &LPMResult{
				IOC:       node.ioc,
				PrefixLen: prefixLen,
			}
		}

		if bit == 0 {
			if node.left == nil {
				break
			}
			node = node.left
		} else {
			if node.right == nil {
				break
			}
			node = node.right
		}
		prefixLen++
	}

	if node.isEnd && node.ioc != nil {
		bestMatch = &LPMResult{
			IOC:       node.ioc,
			PrefixLen: prefixLen,
		}
	}

	return bestMatch
}

// SearchCIDRRange finds all IOCs that match a given CIDR range.
func (rt *RadixTree) SearchCIDRRange(cidr string) []*ioc.IOC {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	root := rt.root4
	if ipNet.IP.To4() == nil {
		root = rt.root6
	}

	bits := rt.ipToBits(ipNet.IP, ipNet)
	prefixLen, _ := ipNet.Mask.Size()

	// Navigate to the prefix node
	node := root
	for i := 0; i < prefixLen; i++ {
		if bits[i] == 0 {
			if node.left == nil {
				return nil
			}
			node = node.left
		} else {
			if node.right == nil {
				return nil
			}
			node = node.right
		}
	}

	// Collect all IOCs under this prefix
	return rt.collectIOCs(node)
}
