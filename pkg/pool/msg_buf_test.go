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

package pool

import (
	"testing"

	"github.com/miekg/dns"
)

func TestPackBuffer_No_Allocation(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("123.", dns.TypeAAAA)
	wire, buf, err := PackBuffer(m)
	if err != nil {
		t.Fatal(err)
	}

	if cap(wire) != buf.Cap() {
		t.Fatalf("wire and buf have different cap, wire %d, buf %d", cap(wire), buf.Cap())
	}
}

func TestPackBuffer_Compress(t *testing.T) {
	m := new(dns.Msg)
	m.SetReply(new(dns.Msg).SetQuestion("www.example.com.", dns.TypeA))
	m.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{1, 2, 3, 4}},
		&dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{5, 6, 7, 8}},
		&dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{9, 10, 11, 12}},
	}

	m.Compress = false
	uncompressed, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}

	// PackBuffer should force compression on.
	m.Compress = false
	wire, buf, err := PackBuffer(m)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Release()

	if !m.Compress {
		t.Fatal("PackBuffer should enable Msg.Compress")
	}
	if len(wire) >= len(uncompressed) {
		t.Fatalf("compressed wire should be smaller: compressed=%d uncompressed=%d", len(wire), len(uncompressed))
	}
}

