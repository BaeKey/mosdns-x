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

package dnsutils

import (
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/pool"
)

// GetMinimalTTL returns the minimal ttl of this msg.
// If msg m has no record, it returns 0.
func GetMinimalTTL(m *dns.Msg) uint32 {
	minTTL := ^uint32(0)
	hasRecord := false
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue // opt record ttl is not ttl.
			}
			hasRecord = true
			ttl := hdr.Ttl
			if ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	if !hasRecord { // no ttl applied
		return 0
	}
	return minTTL
}

// SetTTL updates all records' ttl to ttl, except opt record.
func SetTTL(m *dns.Msg, ttl uint32) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue // opt record ttl is not ttl.
			}
			hdr.Ttl = ttl
		}
	}
}

func ApplyMaximumTTL(m *dns.Msg, ttl uint32) {
	applyTTL(m, ttl, true)
}

func ApplyMinimalTTL(m *dns.Msg, ttl uint32) {
	applyTTL(m, ttl, false)
}

// SubtractTTL subtract delta from every m's RR.
// If RR's TTL is smaller than delta, SubtractTTL
// will return overflowed = true.
func SubtractTTL(m *dns.Msg, delta uint32) (overflowed bool) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue // opt record ttl is not ttl.
			}
			if ttl := hdr.Ttl; ttl > delta {
				hdr.Ttl = ttl - delta
			} else {
				hdr.Ttl = 1
				overflowed = true
			}
		}
	}
	return
}

func applyTTL(m *dns.Msg, ttl uint32, maximum bool) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue // opt record ttl is not ttl.
			}
			if maximum {
				if hdr.Ttl > ttl {
					hdr.Ttl = ttl
				}
			} else {
				if hdr.Ttl < ttl {
					hdr.Ttl = ttl
				}
			}
		}
	}
}

func uint16Conv(u uint16, m map[uint16]string) string {
	if s, ok := m[u]; ok {
		return s
	}
	return strconv.Itoa(int(u))
}

func QclassToString(u uint16) string {
	return uint16Conv(u, dns.ClassToString)
}

func QtypeToString(u uint16) string {
	return uint16Conv(u, dns.TypeToString)
}

func GenEmptyReply(q *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(q, rcode)
	r.RecursionAvailable = true

	var name string
	if len(q.Question) > 1 {
		name = q.Question[0].Name
	} else {
		name = "."
	}

	r.Ns = []dns.RR{FakeSOA(name)}
	return r
}

func FakeSOA(name string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns:      "fake-ns.mosdns.fake.root.",
		Mbox:    "fake-mbox.mosdns.fake.root.",
		Serial:  2021110400,
		Refresh: 1800,
		Retry:   900,
		Expire:  604800,
		Minttl:  86400,
	}
}


func writeCanonicalName(b *strings.Builder, name string) {
	var buf [255]byte
	
	off, err := dns.PackDomainName(name, buf[:], 0, nil, false)
	if err != nil {
		b.WriteString(strings.ToLower(name))
		return
	}

	packed := buf[:off]
	
	for i := 0; i < len(packed); i++ {
		c := packed[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
}

func GetMsgKey(m *dns.Msg, salt uint16) (string, error) {
	var b strings.Builder
	b.Grow(128)

	b.WriteByte(byte(salt >> 8))
	b.WriteByte(byte(salt))

	if len(m.Question) > 0 {
		q := m.Question[0]
		writeCanonicalName(&b, q.Name)
		
		writeUint16(&b, q.Qtype)
		writeUint16(&b, q.Qclass)
	}

	var opt *dns.OPT
	for _, extra := range m.Extra {
		if o, ok := extra.(*dns.OPT); ok {
			opt = o
			break
		}
	}

	var flags uint8
	if opt != nil && opt.Do() {
		flags |= 1 << 0
	}
	if m.CheckingDisabled {
		flags |= 1 << 1
	}
	if m.RecursionDesired {
		flags |= 1 << 2
	}
	b.WriteByte(flags)

	var ednsVersion uint8 = 0
	if opt != nil {
		ednsVersion = uint8((opt.Hdr.Ttl >> 16) & 0xFF)
	}
	b.WriteByte(ednsVersion)

	if opt != nil {
		for _, s := range opt.Option {
			if ecs, ok := s.(*dns.EDNS0_SUBNET); ok {
				if ecs.SourceNetmask > 0 {
					writeUint16(&b, ecs.Family)
					b.WriteByte(ecs.SourceNetmask)
					validBytes := int((ecs.SourceNetmask + 7) / 8)

					if validBytes > len(ecs.Address) {
						validBytes = len(ecs.Address)
					}

					for i := 0; i < validBytes; i++ {
						val := ecs.Address[i]
						if i == validBytes-1 {
							if remainder := ecs.SourceNetmask % 8; remainder != 0 {
								mask := byte(0xFF << (8 - remainder))
								val &= mask
							}
						}
						b.WriteByte(val)
					}
				}
				break
			}
		}
	}

	return b.String(), nil
}

func GetMsgKeyWithTag(m *dns.Msg, tag string) string {
	if len(m.Question) == 0 {
		return ""
	}

	q := m.Question[0]
	bufLen := len(q.Name) + 10 + len(tag)
	
	var b strings.Builder
	b.Grow(bufLen)

	writeCanonicalName(&b, q.Name)

	writeUint16(&b, q.Qtype)

	writeUint16(&b, q.Qclass)

	var opt *dns.OPT
	for _, extra := range m.Extra {
		if o, ok := extra.(*dns.OPT); ok {
			opt = o
			break
		}
	}

	// 压缩 Flags: DO + CD + RD -> 1 Byte
	var flags uint8
	if opt != nil && opt.Do() {
		flags |= 1 << 0 // Bit 0: DO
	}
	if m.CheckingDisabled {
		flags |= 1 << 1 // Bit 1: CD
	}
	if m.RecursionDesired {
		flags |= 1 << 2 // Bit 2: RD
	}
	b.WriteByte(flags)

	// EDNS Version -> 1 Byte
	var ednsVersion uint8 = 0
	if opt != nil {
		ednsVersion = uint8((opt.Hdr.Ttl >> 16) & 0xFF)
	}
	b.WriteByte(ednsVersion)

	if len(tag) > 0 {
		b.WriteString(tag)
	}

	return b.String()
}

func writeUint16(b *strings.Builder, v uint16) {
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v))
}

// GetMsgKeyWithBytesSalt unpacks m and appends salt to the string.
func GetMsgKeyWithBytesSalt(m *dns.Msg, salt []byte) (string, error) {
	wireMsg, buf, err := pool.PackBuffer(m)
	if err != nil {
		return "", err
	}
	defer buf.Release()

	wireMsg[0] = 0
	wireMsg[1] = 0

	sb := new(strings.Builder)
	sb.Grow(len(wireMsg) + len(salt))
	sb.Write(wireMsg)
	sb.Write(salt)

	return sb.String(), nil
}

// GetMsgKeyWithInt64Salt unpacks m and appends salt to the string.
func GetMsgKeyWithInt64Salt(m *dns.Msg, salt int64) (string, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(salt))
	return GetMsgKeyWithBytesSalt(m, b)
}
