package multiipmatcher

import (
	"context"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const MatcherName = "_has_multi_ip"

func init() {
	coremain.RegNewPersetPluginFunc(MatcherName, func(bp *coremain.BP) (coremain.Plugin, error) {
		return &hasMultiIP{BP: bp}, nil
	})
}

type hasMultiIP struct {
	*coremain.BP
}

var _ coremain.MatcherPlugin = (*hasMultiIP)(nil)

func (e *hasMultiIP) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	r := qCtx.R()
	
	if r == nil || len(r.Answer) <= 1 {
		return false, nil
	}

	count := 0
	for _, rr := range r.Answer {
		header := rr.Header()
		
		if header.Rrtype == dns.TypeA || header.Rrtype == dns.TypeAAAA {
			count++

			if count > 1 {
				return true, nil
			}
		}
	}

	return false, nil
}

func (e *hasMultiIP) Close() error {
	return nil
}