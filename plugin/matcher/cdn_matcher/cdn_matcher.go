package cdnmatcher

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/BaeKey/mosdns-x/coremain"
	"github.com/BaeKey/mosdns-x/pkg/query_context"
)

const PluginType = "cdnmatcher"

// ----------------- 公共辅助 -----------------
func fnv1aHashIndex(s string, shardCount int) int {
	const offset32 = 2166136261
	const prime32 = 16777619
	hash := uint32(offset32)
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime32
	}
	return int(hash) % shardCount
}

func extractMainDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		parts := strings.Split(domain, ".")
		if len(parts) < 2 {
			return domain
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return etldPlusOne
}

func hasMultipleNetworks(ips []net.IP) bool {
	if len(ips) < 2 {
		return false
	}
	networks := make(map[string]struct{})
	for _, ip := range ips {
		if ip.To4() != nil {
			network := ip.Mask(net.CIDRMask(24, 32)).String()
			networks[network] = struct{}{}
		}
	}
	return len(networks) >= 2
}

// ----------------- Shard -----------------
type domainEntry struct {
	timestamp time.Time
}

type shard struct {
	mu      sync.RWMutex
	domains map[string]*domainEntry
}

// ----------------- CDN Matcher (含清理) -----------------
type CDNMatcher struct {
	shards     []*shard
	shardCount int
	ttl        time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func newCDNMatcher(shards []*shard, shardCount int, ttl time.Duration) *CDNMatcher {
	matcher := &CDNMatcher{
		shards:     shards,
		shardCount: shardCount,
		ttl:        ttl,
		stopCh:     make(chan struct{}),
	}
	matcher.wg.Add(1)
	go matcher.startCleaner()
	return matcher
}

func (m *CDNMatcher) startCleaner() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.ttl / 4)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			for _, sh := range m.shards {
				sh.mu.Lock()
				for domain, entry := range sh.domains {
					if now.Sub(entry.timestamp) > m.ttl {
						delete(sh.domains, domain)
					}
				}
				sh.mu.Unlock()
			}
		case <-m.stopCh:
			return
		}
	}
}

func (m *CDNMatcher) Match(ctx context.Context, qCtx *query_context.Context) (bool, error) {
	if len(qCtx.Q().Question) == 0 {
		return false, nil
	}
	domain := extractMainDomain(qCtx.Q().Question[0].Name)
	idx := fnv1aHashIndex(domain, m.shardCount)
	sh := m.shards[idx]

	sh.mu.Lock()
	defer sh.mu.Unlock()
	entry, ok := sh.domains[domain]
	if ok && time.Since(entry.timestamp) > m.ttl {
		delete(sh.domains, domain)
		ok = false
	}
	return ok, nil
}

func (m *CDNMatcher) Close() error {
	close(m.stopCh)
	m.wg.Wait()
	return nil
}

// ----------------- CDN Learner -----------------
type CDNLearner struct {
	shards        []*shard
	shardCount    int
	ipv4Threshold int
	maxCacheSize  int
}

func newCDNLearner(shards []*shard, shardCount, ipv4Threshold, maxCacheSize int) *CDNLearner {
	return &CDNLearner{
		shards:        shards,
		shardCount:    shardCount,
		ipv4Threshold: ipv4Threshold,
		maxCacheSize:  maxCacheSize,
	}
}

func (l *CDNLearner) getShardIndex(domain string) int {
	return fnv1aHashIndex(domain, l.shardCount)
}

func (l *CDNLearner) Learn(qCtx *query_context.Context) {
	resp := qCtx.R()
	if resp == nil || len(resp.Answer) == 0 || len(qCtx.Q().Question) == 0 {
		return
	}
	domain := extractMainDomain(qCtx.Q().Question[0].Name)

	var ipv4s []net.IP
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ipv4s = append(ipv4s, a.A)
		}
	}

	if !l.isCDNResponse(ipv4s) {
		return
	}

	sh := l.shards[l.getShardIndex(domain)]
	sh.mu.Lock()
	if _, exists := sh.domains[domain]; !exists && len(sh.domains) < l.maxCacheSize {
		sh.domains[domain] = &domainEntry{timestamp: time.Now()}
	}
	sh.mu.Unlock()
}

func (l *CDNLearner) isCDNResponse(ips []net.IP) bool {
	if len(ips) < l.ipv4Threshold {
		return false
	}
	return hasMultipleNetworks(ips) || len(ips) >= l.ipv4Threshold
}

// ----------------- CDN Plugin -----------------
type CDNPlugin struct {
	Matcher *CDNMatcher
	Learner *CDNLearner
	tag     string
}

var _ coremain.Plugin = (*CDNPlugin)(nil)

func (p *CDNPlugin) Close() error {
	p.Matcher.Close()
	return nil
}

func (p *CDNPlugin) Type() string {
	return PluginType
}

func (p *CDNPlugin) Tag() string {
	if p.tag == "" {
		return PluginType
	}
	return p.tag
}

func (p *CDNPlugin) Match(ctx context.Context, qCtx *query_context.Context) (bool, error) {
	return p.Matcher.Match(ctx, qCtx)
}

func (p *CDNPlugin) OnResponse(ctx context.Context, qCtx *query_context.Context) {
	p.Learner.Learn(qCtx)
}

// ----------------- Init -----------------
type Args struct {
	ShardCount    int           `yaml:"shard_count"`
	IPv4Threshold int           `yaml:"ipv4_threshold"`
	MaxCacheSize  int           `yaml:"max_cache_size"`
	TTL           time.Duration `yaml:"ttl"`
	Tag           string        `yaml:"tag"`
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)

	if cfg.ShardCount <= 0 {
		cfg.ShardCount = 31
	}
	if cfg.IPv4Threshold <= 0 {
		cfg.IPv4Threshold = 3
	}
	if cfg.MaxCacheSize <= 0 {
		cfg.MaxCacheSize = 100000
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}

	// 共享 shards
	shards := make([]*shard, cfg.ShardCount)
	for i := range shards {
		shards[i] = &shard{domains: make(map[string]*domainEntry)}
	}

	matcher := newCDNMatcher(shards, cfg.ShardCount, cfg.TTL)
	learner := newCDNLearner(shards, cfg.ShardCount, cfg.IPv4Threshold, cfg.MaxCacheSize)

	return &CDNPlugin{
		Matcher: matcher,
		Learner: learner,
		tag:     cfg.Tag,
	}, nil
}
