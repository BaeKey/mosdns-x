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
		// fallback: 手动提取可能的主域名
		parts := strings.Split(domain, ".")
		if len(parts) < 2 {
			return domain
		}
		// 返回最后两部分，如 "example.com"
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return etldPlusOne
}

// 检查IP是否在不同网段
func hasMultipleNetworks(ips []net.IP) bool {
	if len(ips) < 2 {
		return false
	}
	
	networks := make(map[string]struct{})
	for _, ip := range ips {
		if ip.To4() != nil {
			// IPv4: 使用/24网段
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

// ----------------- CDN Matcher -----------------
type CDNMatcher struct {
	shards     []*shard
	shardCount int
	ttl        time.Duration
}

func newCDNMatcher(shardCount int, ttl time.Duration) *CDNMatcher {
	shards := make([]*shard, shardCount)
	for i := range shards {
		shards[i] = &shard{domains: make(map[string]*domainEntry)}
	}
	
	matcher := &CDNMatcher{
		shards:     shards,
		shardCount: shardCount,
		ttl:        ttl,
	}
	
	// 启动清理协程
	go matcher.startCleaner()
	
	return matcher
}

// 定期清理过期数据
func (m *CDNMatcher) startCleaner() {
	ticker := time.NewTicker(m.ttl / 4) // 每1/4 TTL检查一次
	defer ticker.Stop()
	
	for range ticker.C {
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
	}
}

func (m *CDNMatcher) Match(ctx context.Context, qCtx *query_context.Context) (bool, error) {
	if len(qCtx.Q().Question) == 0 {
		return false, nil
	}
	domain := extractMainDomain(qCtx.Q().Question[0].Name)
	idx := fnv1aHashIndex(domain, m.shardCount)
	sh := m.shards[idx]
	sh.mu.RLock()
	entry, ok := sh.domains[domain]
	if ok {
		// 检查是否过期
		if time.Since(entry.timestamp) > m.ttl {
			sh.mu.RUnlock()
			// 异步删除过期数据
			go func() {
				sh.mu.Lock()
				delete(sh.domains, domain)
				sh.mu.Unlock()
			}()
			return false, nil
		}
	}
	sh.mu.RUnlock()
	return ok, nil
}

func (m *CDNMatcher) Close() error {
	return nil
}

// ----------------- CDN Learner -----------------
type CDNLearner struct {
	shards        []*shard
	shardCount    int
	ipv4Threshold int
	maxCacheSize  int
	ttl           time.Duration
}

func newCDNLearner(shardCount int, ipv4Threshold, maxCacheSize int, ttl time.Duration) *CDNLearner {
	learner := &CDNLearner{
		shardCount:    shardCount,
		shards:        make([]*shard, shardCount),
		ipv4Threshold: ipv4Threshold,
		maxCacheSize:  maxCacheSize,
		ttl:           ttl,
	}
	for i := range learner.shards {
		learner.shards[i] = &shard{domains: make(map[string]*domainEntry)}
	}
	return learner
}

func (l *CDNLearner) getShardIndex(domain string) int {
	return fnv1aHashIndex(domain, l.shardCount)
}

// 改进的学习逻辑
func (l *CDNLearner) Learn(qCtx *query_context.Context) {
	resp := qCtx.R()
	if resp == nil || len(resp.Answer) == 0 || len(qCtx.Q().Question) == 0 {
		return
	}
	domain := extractMainDomain(qCtx.Q().Question[0].Name)

	// 收集IPv4地址
	var ipv4s []net.IP
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ipv4s = append(ipv4s, a.A)
		}
	}
	
	// 改进的CDN判断逻辑
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

// 改进的CDN判断逻辑
func (l *CDNLearner) isCDNResponse(ips []net.IP) bool {
	if len(ips) < l.ipv4Threshold {
		return false
	}
	
	// 检查是否有多个不同网段的IP
	if hasMultipleNetworks(ips) {
		return true
	}
	
	// 检查IP数量是否达到阈值
	return len(ips) >= l.ipv4Threshold
}

// ----------------- CDN Plugin -----------------
type CDNPlugin struct {
	Matcher *CDNMatcher
	Learner *CDNLearner
	tag     string
}

var _ coremain.Plugin = (*CDNPlugin)(nil)

func (p *CDNPlugin) Close() error {
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

	// 设置默认值（使用质数）
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
		cfg.TTL = 24 * time.Hour // 默认24小时过期
	}

	matcher := newCDNMatcher(cfg.ShardCount, cfg.TTL)
	learner := newCDNLearner(cfg.ShardCount, cfg.IPv4Threshold, cfg.MaxCacheSize, cfg.TTL)

	return &CDNPlugin{
		Matcher: matcher,
		Learner: learner,
		tag:     cfg.Tag,
	}, nil
}