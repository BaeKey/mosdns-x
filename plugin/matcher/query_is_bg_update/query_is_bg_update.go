package query_is_bg_update

import (
	"context"

	"github.com/pmkol/mosdns-x/coremain"
    "github.com/pmkol/mosdns-x/pkg/ctxkey"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const (
	PluginName = "query_is_bg_update"
)

type bgUpdateMatcher struct {
	*coremain.BP
}

func (m *bgUpdateMatcher) Match(ctx context.Context, qCtx *query_context.Context) (bool, error) {
	if isBg, ok := ctx.Value(ctxkey.CtxKeyBgUpdate).(bool); ok && isBg {
		return true, nil
	}

	return false, nil
}

var _ coremain.MatcherPlugin = (*bgUpdateMatcher)(nil)

func init() {
	coremain.RegNewPersetPluginFunc(PluginName, func(bp *coremain.BP) (coremain.Plugin, error) {
		return &bgUpdateMatcher{BP: bp}, nil
	})
}