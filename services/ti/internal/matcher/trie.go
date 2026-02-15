// Package matcher provides Trie data structure for domain matching.
package matcher

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/siem-soar-platform/services/ti/internal/ioc"
)

// TrieNode represents a node in the trie.
type TrieNode struct {
	children map[string]*TrieNode
	ioc      *ioc.IOC
	isEnd    bool
}

// Trie implements a thread-safe trie for domain matching.
type Trie struct {
	root  *TrieNode
	count atomic.Int64
	mu    sync.RWMutex
}

// NewTrie creates a new Trie.
func NewTrie() *Trie {
	return &Trie{
		root: &TrieNode{
			children: make(map[string]*TrieNode),
		},
	}
}

// Insert adds a domain to the trie.
// Domains are stored in reverse order for suffix matching.
func (t *Trie) Insert(domain string, i *ioc.IOC) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Normalize and reverse domain for suffix matching
	parts := t.splitDomain(domain)

	node := t.root
	for _, part := range parts {
		if node.children == nil {
			node.children = make(map[string]*TrieNode)
		}
		if _, ok := node.children[part]; !ok {
			node.children[part] = &TrieNode{
				children: make(map[string]*TrieNode),
			}
		}
		node = node.children[part]
	}

	node.isEnd = true
	node.ioc = i
	t.count.Add(1)
}

// Search finds an exact domain match.
func (t *Trie) Search(domain string) *ioc.IOC {
	t.mu.RLock()
	defer t.mu.RUnlock()

	parts := t.splitDomain(domain)

	node := t.root
	for _, part := range parts {
		if node.children == nil {
			return nil
		}
		if child, ok := node.children[part]; ok {
			node = child
		} else {
			return nil
		}
	}

	if node.isEnd {
		return node.ioc
	}
	return nil
}

// SearchSuffix finds a domain that is a suffix of the given domain.
// This enables matching subdomains (e.g., malware.evil.com matches evil.com).
func (t *Trie) SearchSuffix(domain string) *ioc.IOC {
	t.mu.RLock()
	defer t.mu.RUnlock()

	parts := t.splitDomain(domain)

	node := t.root
	var match *ioc.IOC

	for _, part := range parts {
		if node.children == nil {
			break
		}
		if child, ok := node.children[part]; ok {
			node = child
			if node.isEnd {
				match = node.ioc
			}
		} else {
			break
		}
	}

	return match
}

// SearchPrefix finds domains that start with the given prefix.
// This is the opposite of suffix matching.
func (t *Trie) SearchPrefix(prefix string) []*ioc.IOC {
	t.mu.RLock()
	defer t.mu.RUnlock()

	parts := t.splitDomain(prefix)

	node := t.root
	for _, part := range parts {
		if node.children == nil {
			return nil
		}
		if child, ok := node.children[part]; ok {
			node = child
		} else {
			return nil
		}
	}

	// Collect all IOCs under this node
	return t.collectIOCs(node)
}

// Delete removes a domain from the trie.
func (t *Trie) Delete(domain string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	parts := t.splitDomain(domain)
	return t.deleteRecursive(t.root, parts, 0)
}

// Contains checks if a domain exists in the trie.
func (t *Trie) Contains(domain string) bool {
	return t.Search(domain) != nil
}

// Count returns the number of domains in the trie.
func (t *Trie) Count() int64 {
	return t.count.Load()
}

// Clear removes all entries from the trie.
func (t *Trie) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.root = &TrieNode{
		children: make(map[string]*TrieNode),
	}
	t.count.Store(0)
}

// List returns all IOCs in the trie.
func (t *Trie) List() []*ioc.IOC {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.collectIOCs(t.root)
}

// splitDomain splits a domain into parts in reverse order.
// example.com -> ["com", "example"]
func (t *Trie) splitDomain(domain string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "www.")

	parts := strings.Split(domain, ".")

	// Reverse the parts for suffix matching
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	return parts
}

// deleteRecursive deletes a domain recursively.
func (t *Trie) deleteRecursive(node *TrieNode, parts []string, depth int) bool {
	if node == nil {
		return false
	}

	if depth == len(parts) {
		if !node.isEnd {
			return false
		}
		node.isEnd = false
		node.ioc = nil
		t.count.Add(-1)
		return len(node.children) == 0
	}

	part := parts[depth]
	child, exists := node.children[part]
	if !exists {
		return false
	}

	shouldDeleteChild := t.deleteRecursive(child, parts, depth+1)
	if shouldDeleteChild {
		delete(node.children, part)
		return !node.isEnd && len(node.children) == 0
	}

	return false
}

// collectIOCs collects all IOCs under a node.
func (t *Trie) collectIOCs(node *TrieNode) []*ioc.IOC {
	var results []*ioc.IOC

	if node.isEnd && node.ioc != nil {
		results = append(results, node.ioc)
	}

	for _, child := range node.children {
		results = append(results, t.collectIOCs(child)...)
	}

	return results
}

// CompressedTrie implements a Patricia trie (radix trie) for more memory-efficient storage.
type CompressedTrie struct {
	root  *CompressedNode
	count atomic.Int64
	mu    sync.RWMutex
}

// CompressedNode represents a node in the Patricia trie.
type CompressedNode struct {
	prefix   string
	children map[byte]*CompressedNode
	ioc      *ioc.IOC
	isEnd    bool
}

// NewCompressedTrie creates a new Patricia trie.
func NewCompressedTrie() *CompressedTrie {
	return &CompressedTrie{
		root: &CompressedNode{
			children: make(map[byte]*CompressedNode),
		},
	}
}

// Insert adds a domain to the Patricia trie.
func (t *CompressedTrie) Insert(domain string, i *ioc.IOC) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := t.normalizeKey(domain)
	t.insertRecursive(t.root, key, i)
	t.count.Add(1)
}

// Search finds an exact domain match.
func (t *CompressedTrie) Search(domain string) *ioc.IOC {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := t.normalizeKey(domain)
	node := t.searchRecursive(t.root, key)
	if node != nil && node.isEnd {
		return node.ioc
	}
	return nil
}

// SearchSuffix finds a domain suffix match.
func (t *CompressedTrie) SearchSuffix(domain string) *ioc.IOC {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := t.normalizeKey(domain)
	return t.searchSuffixRecursive(t.root, key)
}

// Count returns the number of entries.
func (t *CompressedTrie) Count() int64 {
	return t.count.Load()
}

func (t *CompressedTrie) normalizeKey(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "www.")

	// Reverse domain for suffix matching
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	return strings.Join(parts, ".")
}

func (t *CompressedTrie) insertRecursive(node *CompressedNode, key string, i *ioc.IOC) {
	if len(key) == 0 {
		node.isEnd = true
		node.ioc = i
		return
	}

	firstByte := key[0]
	child, exists := node.children[firstByte]

	if !exists {
		// Create new node with the entire remaining key
		newNode := &CompressedNode{
			prefix:   key,
			children: make(map[byte]*CompressedNode),
			isEnd:    true,
			ioc:      i,
		}
		node.children[firstByte] = newNode
		return
	}

	// Find common prefix length
	commonLen := t.commonPrefixLength(child.prefix, key)

	if commonLen == len(child.prefix) {
		// Key starts with child's prefix, continue down
		t.insertRecursive(child, key[commonLen:], i)
	} else {
		// Need to split the node
		// Create new intermediate node
		intermediate := &CompressedNode{
			prefix:   child.prefix[:commonLen],
			children: make(map[byte]*CompressedNode),
		}

		// Move existing child under intermediate
		child.prefix = child.prefix[commonLen:]
		intermediate.children[child.prefix[0]] = child

		// Replace in parent
		node.children[firstByte] = intermediate

		// Insert new key under intermediate
		if commonLen == len(key) {
			intermediate.isEnd = true
			intermediate.ioc = i
		} else {
			newNode := &CompressedNode{
				prefix:   key[commonLen:],
				children: make(map[byte]*CompressedNode),
				isEnd:    true,
				ioc:      i,
			}
			intermediate.children[key[commonLen]] = newNode
		}
	}
}

func (t *CompressedTrie) searchRecursive(node *CompressedNode, key string) *CompressedNode {
	if len(key) == 0 {
		return node
	}

	child, exists := node.children[key[0]]
	if !exists {
		return nil
	}

	if len(key) < len(child.prefix) {
		return nil
	}

	if key[:len(child.prefix)] != child.prefix {
		return nil
	}

	return t.searchRecursive(child, key[len(child.prefix):])
}

func (t *CompressedTrie) searchSuffixRecursive(node *CompressedNode, key string) *ioc.IOC {
	if len(key) == 0 {
		if node.isEnd {
			return node.ioc
		}
		return nil
	}

	var match *ioc.IOC
	if node.isEnd {
		match = node.ioc
	}

	child, exists := node.children[key[0]]
	if !exists {
		return match
	}

	// Check if key matches child prefix
	prefixLen := len(child.prefix)
	if len(key) < prefixLen {
		// Key is shorter than prefix, check partial match
		if key == child.prefix[:len(key)] && child.isEnd {
			return child.ioc
		}
		return match
	}

	if key[:prefixLen] != child.prefix {
		return match
	}

	result := t.searchSuffixRecursive(child, key[prefixLen:])
	if result != nil {
		return result
	}
	return match
}

func (t *CompressedTrie) commonPrefixLength(a, b string) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := 0; i < minLen; i++ {
		if a[i] != b[i] {
			return i
		}
	}

	return minLen
}
