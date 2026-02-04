/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package msg_matcher

import (
	"context"
	"net/netip"
	"sync"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
	"github.com/pmkol/mosdns-x/pkg/matcher/elem"
	"github.com/pmkol/mosdns-x/pkg/matcher/netlist"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const defaultCacheSize = 4096

type boolCache[K comparable] struct {
	mu   sync.RWMutex
	curr map[K]bool
	prev map[K]bool
}

func newBoolCache[K comparable]() *boolCache[K] {
	return &boolCache[K]{
		curr: make(map[K]bool, defaultCacheSize),
		prev: make(map[K]bool, defaultCacheSize),
	}
}

func (c *boolCache[K]) get(k K) (bool, bool) {
	c.mu.RLock()
	if v, ok := c.curr[k]; ok {
		c.mu.RUnlock()
		return v, true
	}
	if v, ok := c.prev[k]; ok {
		c.mu.RUnlock()
		c.set(k, v)
		return v, true
	}
	c.mu.RUnlock()
	return false, false
}

func (c *boolCache[K]) set(k K, v bool) {
	c.mu.Lock()
	if len(c.curr) >= defaultCacheSize {
		c.prev = c.curr
		c.curr = make(map[K]bool, defaultCacheSize)
	}
	c.curr[k] = v
	c.mu.Unlock()
}


type ClientIPMatcher struct {
	ipMatcher netlist.Matcher
	cache *boolCache[netip.Addr]
}

func NewClientIPMatcher(ipMatcher netlist.Matcher) *ClientIPMatcher {
	return &ClientIPMatcher{
		ipMatcher: ipMatcher,
		cache: newBoolCache[netip.Addr](),
	}
}

func (m *ClientIPMatcher) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	clientAddr := qCtx.ReqMeta().GetClientAddr()
	if !clientAddr.IsValid() {
		return false, nil
	}

	if v, ok := m.cache.get(clientAddr); ok {
		return v, nil
	}

	matched, err = m.ipMatcher.Match(clientAddr)
	if err != nil {
		return false, err
	}

	m.cache.set(clientAddr, matched)
	return matched, nil
}


type ClientECSMatcher struct {
	ipMatcher netlist.Matcher
	cache *boolCache[netip.Addr]
}

func NewClientECSMatcher(ipMatcher netlist.Matcher) *ClientECSMatcher {
	return &ClientECSMatcher{
		ipMatcher: ipMatcher,
		cache: newBoolCache[netip.Addr](),
	}
}

func (m *ClientECSMatcher) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	ecs := dnsutils.GetMsgECS(qCtx.Q())
	if ecs == nil {
		return false, nil
	}
	addr, ok := netip.AddrFromSlice(ecs.Address)
	if !ok {
		return false, nil
	}

	if v, ok := m.cache.get(addr); ok {
		return v, nil
	}

	matched, err = m.ipMatcher.Match(addr)
	if err != nil {
		return false, err
	}

	m.cache.set(addr, matched)
	return matched, nil
}

type QNameMatcher struct {
	domainMatcher domain.Matcher[struct{}]
	cache *boolCache[string]
}

func NewQNameMatcher(domainMatcher domain.Matcher[struct{}]) *QNameMatcher {
	return &QNameMatcher{
		domainMatcher: domainMatcher,
		cache: newBoolCache[string](),
	}
}

func (m *QNameMatcher) Match(_ context.Context, qCtx *query_context.Context) (matched bool, _ error) {
	return m.MatchMsg(qCtx.Q()), nil
}

func (m *QNameMatcher) MatchMsg(msg *dns.Msg) bool {
	for i := range msg.Question {
		qName := msg.Question[i].Name

		if v, ok := m.cache.get(qName); ok {
			if v {
				return true
			}
			continue
		}

		_, matched := m.domainMatcher.Match(qName)

		m.cache.set(qName, matched)

		if matched {
			return true
		}
	}
	return false
}

type QTypeMatcher struct {
	elemMatcher *elem.IntMatcher
}

func NewQTypeMatcher(elemMatcher *elem.IntMatcher) *QTypeMatcher {
	return &QTypeMatcher{elemMatcher: elemMatcher}
}

func (m *QTypeMatcher) Match(_ context.Context, qCtx *query_context.Context) (matched bool, _ error) {
	return m.MatchMsg(qCtx.Q()), nil
}

func (m *QTypeMatcher) MatchMsg(msg *dns.Msg) bool {
	for i := range msg.Question {
		if m.elemMatcher.Match(int(msg.Question[i].Qtype)) {
			return true
		}
	}
	return false
}

type QClassMatcher struct {
	elemMatcher *elem.IntMatcher
}

func NewQClassMatcher(elemMatcher *elem.IntMatcher) *QClassMatcher {
	return &QClassMatcher{elemMatcher: elemMatcher}
}

func (m *QClassMatcher) Match(_ context.Context, qCtx *query_context.Context) (matched bool, _ error) {
	return m.MatchMsg(qCtx.Q()), nil
}

func (m *QClassMatcher) MatchMsg(msg *dns.Msg) bool {
	for i := range msg.Question {
		if m.elemMatcher.Match(int(msg.Question[i].Qclass)) {
			return true
		}
	}
	return false
}
