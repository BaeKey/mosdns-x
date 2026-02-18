package redirect_all

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "redirect_all"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*plugin)(nil)

type Args struct {
	Target   string `yaml:"target"`
	UseCNAME bool   `yaml:"use_cname"`
}

type plugin struct {
	*coremain.BP
	target   string
	useCNAME bool
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newPlugin(bp, args.(*Args))
}

func newPlugin(bp *coremain.BP, args *Args) (*plugin, error) {
	if args.Target == "" {
		return nil, fmt.Errorf("target domain required")
	}

	p := &plugin{
		BP:       bp,
		target:   dns.Fqdn(args.Target),
		useCNAME: args.UseCNAME,
	}

	bp.L().Info("redirect_all loaded",
		zap.String("target", p.target),
		zap.Bool("use_cname", p.useCNAME),
	)

	return p, nil
}

func (p *plugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	orgQName := q.Question[0].Name
	redirectTarget := p.target

	if strings.EqualFold(orgQName, redirectTarget) {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	q.Question[0].Name = redirectTarget

	err := executable_seq.ExecChainNode(ctx, qCtx, next)

	r := qCtx.R()
	if r == nil {
		q.Question[0].Name = orgQName
		return err
	}

	for i := range r.Question {
		if strings.EqualFold(r.Question[i].Name, redirectTarget) {
			r.Question[i].Name = orgQName
		}
	}

	if p.useCNAME {
		cnameTTL := uint32(300)
		if len(r.Answer) > 0 {
			cnameTTL = r.Answer[0].Header().Ttl
			for _, rr := range r.Answer {
				if t := rr.Header().Ttl; t < cnameTTL {
					cnameTTL = t
				}
			}
		}

		newAns := make([]dns.RR, 1, len(r.Answer)+1)
		newAns[0] = &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   orgQName,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    cnameTTL,
			},
			Target: redirectTarget,
		}
		
		newAns = append(newAns, r.Answer...)
		r.Answer = newAns

		replaceName := func(rrs []dns.RR) {
			for _, rr := range rrs {
				h := rr.Header()
				if strings.EqualFold(h.Name, redirectTarget) {
					h.Name = orgQName
				}
			}
		}
		replaceName(r.Ns)
		replaceName(r.Extra)

		return err
	}

	replaceName := func(rrs []dns.RR) {
		for _, rr := range rrs {
			h := rr.Header()
			if strings.EqualFold(h.Name, redirectTarget) {
				h.Name = orgQName
			}
		}
	}

	replaceName(r.Answer)
	replaceName(r.Ns)
	replaceName(r.Extra)

	return err
}

func (p *plugin) Close() error {
	return nil
}