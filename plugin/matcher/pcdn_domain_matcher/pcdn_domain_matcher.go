package querymatcher

import (
	"context"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PCDNMatcherName = "_is_pcdn_domain"

func init() {
	coremain.RegNewPersetPluginFunc(PCDNMatcherName, func(bp *coremain.BP) (coremain.Plugin, error) {
		return &pcdnDomainMatcher{BP: bp}, nil
	})
}

type pcdnDomainMatcher struct {
	*coremain.BP
}

var _ coremain.MatcherPlugin = (*pcdnDomainMatcher)(nil)

func (m *pcdnDomainMatcher) Match(_ context.Context, qCtx *query_context.Context) (bool, error) {
	q := qCtx.Q()
	if len(q.Question) == 0 {
		return false, nil
	}

	qName := q.Question[0].Name

	dotCount := 0
	firstDotIndex := -1

	for i := 0; i < len(qName); i++ {
		if qName[i] == '.' {
			dotCount++
			if firstDotIndex == -1 {
				if i <= 10 {
					return false, nil
				}
				firstDotIndex = i
			}

			if dotCount >= 4 {
				return true, nil
			}
		}
	}

	return false, nil
}

func (m *pcdnDomainMatcher) Close() error {
	return nil
}