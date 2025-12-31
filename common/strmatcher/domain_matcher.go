package strmatcher

import (
	"strings"
	"sync"
)

func breakDomain(domain string) []string {
	return strings.Split(domain, ".")
}

type node struct {
	values []uint32
	sub    map[string]*node
}

// DomainMatcherGroup is a IndexMatcher for a large set of Domain matchers.
// Visible for testing only.
type DomainMatcherGroup struct {
	root *node
}

func (g *DomainMatcherGroup) Add(domain string, value uint32) {
	if g.root == nil {
		g.root = new(node)
	}

	current := g.root
	parts := breakDomain(domain)
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if current.sub == nil {
			current.sub = make(map[string]*node)
		}
		next := current.sub[part]
		if next == nil {
			next = new(node)
			current.sub[part] = next
		}
		current = next
	}

	current.values = append(current.values, value)
}

func (g *DomainMatcherGroup) addMatcher(m domainMatcher, value uint32) {
	g.Add(string(m), value)
}

// matchesPool pools slice of slices to reduce allocations in Match()
// Most domain names have at most 8 parts (e.g., a.b.c.d.example.co.uk)
var matchesPool = sync.Pool{
	New: func() interface{} {
		s := make([][]uint32, 0, 8)
		return &s
	},
}

func (g *DomainMatcherGroup) Match(domain string) []uint32 {
	if domain == "" {
		return nil
	}

	current := g.root
	if current == nil {
		return nil
	}

	nextPart := func(idx int) int {
		for i := idx - 1; i >= 0; i-- {
			if domain[i] == '.' {
				return i
			}
		}
		return -1
	}

	// Get matches slice from pool to reduce allocations
	matchesPtr := matchesPool.Get().(*[][]uint32)
	matches := (*matchesPtr)[:0]

	idx := len(domain)
	for {
		if idx == -1 || current.sub == nil {
			break
		}

		nidx := nextPart(idx)
		part := domain[nidx+1 : idx]
		next := current.sub[part]
		if next == nil {
			break
		}
		current = next
		idx = nidx
		if len(current.values) > 0 {
			matches = append(matches, current.values)
		}
	}

	var result []uint32
	switch len(matches) {
	case 0:
		result = nil
	case 1:
		result = matches[0]
	default:
		// Pre-calculate total size to avoid multiple allocations
		totalSize := 0
		for _, m := range matches {
			totalSize += len(m)
		}
		result = make([]uint32, 0, totalSize)
		for idx := range matches {
			// Insert reversely, the subdomain that matches further ranks higher
			result = append(result, matches[len(matches)-1-idx]...)
		}
	}

	// Return matches slice to pool
	*matchesPtr = matches
	matchesPool.Put(matchesPtr)

	return result
}
