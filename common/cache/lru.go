package cache

import (
	"container/list"
	"sync"
)

// Lru simple, fast lru cache implementation
type Lru interface {
	Get(key interface{}) (value interface{}, ok bool)
	GetKeyFromValue(value interface{}) (key interface{}, ok bool)
	PeekKeyFromValue(value interface{}) (key interface{}, ok bool) // Peek means check but NOT bring to top
	Put(key, value interface{})
}

type lru struct {
	capacity       int
	list           *list.List
	keyToElement   map[interface{}]*list.Element
	valueToElement map[interface{}]*list.Element
	mu             sync.RWMutex
}

type lruElement struct {
	key   interface{}
	value interface{}
}

// NewLru initializes a lru cache
func NewLru(cap int) Lru {
	return &lru{
		capacity:       cap,
		list:           list.New(),
		keyToElement:   make(map[interface{}]*list.Element, cap),
		valueToElement: make(map[interface{}]*list.Element, cap),
	}
}

func (l *lru) Get(key interface{}) (value interface{}, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if element, ok := l.keyToElement[key]; ok {
		l.list.MoveToFront(element)
		return element.Value.(*lruElement).value, true
	}
	return nil, false
}

func (l *lru) GetKeyFromValue(value interface{}) (key interface{}, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if element, ok := l.valueToElement[value]; ok {
		l.list.MoveToFront(element)
		return element.Value.(*lruElement).key, true
	}
	return nil, false
}

func (l *lru) PeekKeyFromValue(value interface{}) (key interface{}, ok bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if element, ok := l.valueToElement[value]; ok {
		return element.Value.(*lruElement).key, true
	}
	return nil, false
}

func (l *lru) Put(key, value interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if element, ok := l.keyToElement[key]; ok {
		// Key exists, update value and move to front
		oldValue := element.Value.(*lruElement).value
		if oldValue != value {
			// Remove old value mapping if value changed
			delete(l.valueToElement, oldValue)
			l.valueToElement[value] = element
		}
		element.Value.(*lruElement).value = value
		l.list.MoveToFront(element)
		return
	}

	// New entry
	e := &lruElement{key, value}
	element := l.list.PushFront(e)
	l.keyToElement[key] = element
	l.valueToElement[value] = element

	// Evict if over capacity
	if l.list.Len() > l.capacity {
		toRemove := l.list.Back()
		if toRemove != nil {
			entry := toRemove.Value.(*lruElement)
			l.list.Remove(toRemove)
			delete(l.keyToElement, entry.key)
			delete(l.valueToElement, entry.value)
		}
	}
}
