package cdnmatcher

import (
	"context"
	"os"
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
		lastDot := strings.LastIndex(domain, ".")
		if lastDot == -1 {
			return domain
		}
		secondLastDot := strings.LastIndex(domain[:lastDot], ".")
		if secondLastDot == -1 {
			return domain
		}
		return domain[secondLastDot+1:]
	}
	return etldPlusOne
}

// ----------------- Shard -----------------
type shard struct {
	mu      sync.RWMutex
	domains map[string]struct{}
}

// ----------------- CDN Matcher -----------------
type CDNMatcher struct {
	shards     []*shard
	shardCount int
}

func newCDNMatcher(shardCount int) *CDNMatcher {
	shards := make([]*shard, shardCount)
	for i := range shards {
		shards[i] = &shard{domains: make(map[string]struct{})}
	}
	return &CDNMatcher{
		shards:     shards,
		shardCount: shardCount,
	}
}

// MatcherPlugin 接口
func (m *CDNMatcher) Match(ctx context.Context, qCtx *query_context.Context) (bool, error) {
	if len(qCtx.Q().Question) == 0 {
		return false, nil
	}
	domain := extractMainDomain(qCtx.Q().Question[0].Name)
	idx := fnv1aHashIndex(domain, m.shardCount)
	sh := m.shards[idx]
	sh.mu.RLock()
	_, ok := sh.domains[domain]
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
	writeQueue    chan string
	flushInterval time.Duration
	cacheFile     string
	stopCh        chan struct{}
}

func newCDNLearner(shardCount int, ipv4Threshold, maxCacheSize int, flushInterval time.Duration, cacheFile string, queueSize int) *CDNLearner {
	learner := &CDNLearner{
		shardCount:    shardCount,
		shards:        make([]*shard, shardCount),
		ipv4Threshold: ipv4Threshold,
		maxCacheSize:  maxCacheSize,
		writeQueue:    make(chan string, queueSize),
		flushInterval: flushInterval,
		cacheFile:     cacheFile,
		stopCh:        make(chan struct{}),
	}
	for i := range learner.shards {
		learner.shards[i] = &shard{domains: make(map[string]struct{})}
	}
	go learner.startWriter()
	return learner
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

	ipv4Count := 0
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			ipv4Count++
		}
	}
	if ipv4Count <= l.ipv4Threshold {
		return
	}

	sh := l.shards[l.getShardIndex(domain)]
	sh.mu.Lock()
	if _, exists := sh.domains[domain]; !exists && len(sh.domains) < l.maxCacheSize {
		sh.domains[domain] = struct{}{}
		sh.mu.Unlock()
		select {
		case l.writeQueue <- domain:
		default:
		}
	} else {
		sh.mu.Unlock()
	}
}

func (l *CDNLearner) startWriter() {
	ticker := time.NewTicker(l.flushInterval)
	defer ticker.Stop()
	var buffer []string
	for {
		select {
		case <-l.stopCh:
			l.flush(buffer)
			return
		case domain := <-l.writeQueue:
			buffer = append(buffer, domain)
		case <-ticker.C:
			l.flush(buffer)
			buffer = buffer[:0]
		}
	}
}

func (l *CDNLearner) flush(batch []string) {
	if len(batch) == 0 {
		return
	}
	f, err := os.OpenFile(l.cacheFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	for _, d := range batch {
		f.WriteString(d + "\n")
	}
}

func (l *CDNLearner) StopWriter() {
	close(l.stopCh)
}

// ----------------- CDN Plugin -----------------
type CDNPlugin struct {
	Matcher *CDNMatcher
	Learner *CDNLearner
	tag     string
}

var _ coremain.Plugin = (*CDNPlugin)(nil)

func (p *CDNPlugin) Close() error {
	p.Learner.StopWriter()
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
	CacheFile     string        `yaml:"cache_file"`
	ShardCount    int           `yaml:"shard_count"`
	IPv4Threshold int           `yaml:"ipv4_threshold"`
	MaxCacheSize  int           `yaml:"max_cache_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	QueueSize     int           `yaml:"queue_size"`
	Tag           string        `yaml:"tag"`
}

// 注册插件类型
func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

// 初始化函数
func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)

	if cfg.ShardCount <= 0 {
		cfg.ShardCount = 32
	}
	if cfg.IPv4Threshold <= 0 {
		cfg.IPv4Threshold = 3
	}
	if cfg.MaxCacheSize <= 0 {
		cfg.MaxCacheSize = 100000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	if cfg.CacheFile == "" {
		cfg.CacheFile = "./cdn_cache.txt"
	}

	matcher := newCDNMatcher(cfg.ShardCount)
	learner := newCDNLearner(cfg.ShardCount, cfg.IPv4Threshold, cfg.MaxCacheSize, cfg.FlushInterval, cfg.CacheFile, cfg.QueueSize)

	return &CDNPlugin{
		Matcher: matcher,
		Learner: learner,
		tag:     cfg.Tag,
	}, nil
}