package ip_tagger

import (
    "context"
    "fmt"
    "io"
    "net"
    "net/http"
    "strings"
    "time"

    "go.uber.org/zap"
    "golang.org/x/sync/singleflight"

    "github.com/pmkol/mosdns-x/coremain"
    "github.com/pmkol/mosdns-x/pkg/ctxkey"
    "github.com/pmkol/mosdns-x/pkg/cache/mem_cache"
    "github.com/pmkol/mosdns-x/pkg/executable_seq"
    "github.com/pmkol/mosdns-x/pkg/query_context"
    "github.com/prometheus/client_golang/prometheus"
)

const PluginType = "ip_tagger"

const (
    ValFallback = "FAIL_FALLBACK"
    ValError    = "FAIL_ERROR"
)

const ErrorCacheTTL = 30 * time.Second

func init() {
    coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
    APIAddr   string `yaml:"api_addr"`
    Timeout   int    `yaml:"timeout"`
    CacheSize int    `yaml:"cache_size"`
    CacheTTL  int    `yaml:"cache_ttl"`
}

type IPTagger struct {
    *coremain.BP

    args   *Args
    client *http.Client
    cache  *mem_cache.MemCache
    sf     singleflight.Group
    baseURL   string
    tagCacheSize prometheus.GaugeFunc
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
    a := args.(*Args)
    if a.Timeout <= 0 {
        // 30ms超时
        a.Timeout = 30
    }
    if a.CacheSize <= 0 {
        a.CacheSize = 10240
    }
    if a.CacheTTL <= 0 {
        a.CacheTTL = 86400
    }

    transport := &http.Transport{
        MaxIdleConns:        10,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     30 * time.Second,
    }

    var baseURL string
    if strings.HasPrefix(a.APIAddr, "unix://") {
        socketPath := strings.TrimPrefix(a.APIAddr, "unix://")
        transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
            return net.Dial("unix", socketPath)
        }
        baseURL = "http://unix"
    } else {
        baseURL = strings.TrimRight(a.APIAddr, "/")
    }

    p := &IPTagger{
        BP: bp,
        args: a,
        baseURL: baseURL,
        client: &http.Client{
            Timeout:   time.Duration(a.Timeout) * time.Millisecond,
            Transport: transport,
        },
        cache: mem_cache.NewMemCache(a.CacheSize, 0),
    }

    p.tagCacheSize = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
        Name: "ip_tagger_cache_size",
        Help: "Number of IP tags currently cached.",
    }, func() float64 {
        return float64(p.cache.Len())
    })
    bp.GetMetricsReg().MustRegister(p.tagCacheSize)

    return p, nil
}

func (p *IPTagger) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
    clientAddr := qCtx.ReqMeta().GetClientAddr()
    if !clientAddr.IsValid() {
        return executable_seq.ExecChainNode(ctx, qCtx, next)
    }

    if clientAddr.IsLoopback() || clientAddr.IsPrivate() {
        if p.L().Core().Enabled(zap.DebugLevel) {
            p.L().Debug("skipping private/loopback address",
                zap.String("ip", clientAddr.String()),
            )
        }
        return executable_seq.ExecChainNode(ctx, qCtx, next)
    }

    var lookupKey string
    if clientAddr.Is4() {
        if prefix, err := clientAddr.Prefix(24); err == nil {
            lookupKey = prefix.Addr().String()
        } else {
            lookupKey = clientAddr.String()
        }
    } else {
        if prefix, err := clientAddr.Prefix(48); err == nil {
            lookupKey = prefix.Addr().String()
        } else {
            lookupKey = clientAddr.String()
        }
    }

    tag := p.getTag(lookupKey)

    if tag != "" && tag != ValFallback && tag != ValError {
        ctx = context.WithValue(ctx, ctxkey.CtxKeyIpResolverTag, tag)
        if p.L().Core().Enabled(zap.DebugLevel) {
            p.L().Debug("tagger hit",
                zap.String("ip", lookupKey),
                zap.String("tag", tag),
            )
        }
    } else if p.L().Core().Enabled(zap.DebugLevel) {
        reason := "unknown"
        if tag == ValFallback {
            reason = "explicit_fallback"
        } else if tag == ValError {
            reason = "circuit_break"
        }

        p.L().Debug("tagger bypass",
            zap.String("ip", lookupKey),
            zap.String("reason", reason),
        )
    }

    return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *IPTagger) getTag(ip string) string {
    val, _, expTime := p.cache.Get(ip)

    if val != nil {
        tag := string(val)
        now := time.Now()

        if tag == ValError {
            if now.Before(expTime) {
                return ValError
            }
            goto SynchronousFetch
        }

        if !now.Before(expTime) {
            go func() {
                p.sf.Do(ip+"_async", func() (interface{}, error) {
                    return p.fetchFromAPI(ip)
                })
            }()
        }
        return tag
    }

SynchronousFetch:
    res, err, _ := p.sf.Do(ip, func() (interface{}, error) {
        return p.fetchFromAPI(ip)
    })

    if err != nil {
        return ValError
    }

    return res.(string)
}

func (p *IPTagger) tryServeStale(ip string, now time.Time) (string, bool) {
    if val, _, _ := p.cache.Get(ip); val != nil {
        oldTag := string(val)
        if oldTag != ValError && oldTag != ValFallback {
            p.cache.Store(ip, val, now, now.Add(ErrorCacheTTL))
            return oldTag, true
        }
    }
    return "", false
}

func (p *IPTagger) fetchFromAPI(ip string) (string, error) {
    url := fmt.Sprintf("%s/%s", p.baseURL, ip)
    
    req, err := http.NewRequest(http.MethodGet, url, nil)
    if err != nil {
        p.L().Error("failed to create request", zap.Error(err))
        return ValError, err
    }
    
    if strings.HasPrefix(p.baseURL, "http://unix") {
        req.Host = "localhost"
    }

    resp, err := p.client.Do(req)
    now := time.Now()

    // 1. 网络请求层面的错误处理
    if err != nil {
        p.L().Error("api request failed", zap.String("ip", ip), zap.Error(err))
        
        if oldTag, ok := p.tryServeStale(ip, now); ok {
            return oldTag, nil
        }
        
        p.cache.Store(ip, []byte(ValError), now, now.Add(ErrorCacheTTL))
        return ValError, err
    }
    defer resp.Body.Close()

    // 2. HTTP 状态码错误处理
    if resp.StatusCode != http.StatusOK {
        // 如果状态码是202，说明没有缓存请求正在处理中
        if resp.StatusCode == http.StatusAccepted {
            // 一般请求上游在1s内可以拿到结果
            p.cache.Store(ip, []byte(ValFallback), now, now.Add(1*time.Second))
            return ValFallback, nil
        }

        // 其他状态码尝试使用旧缓存
        if oldTag, ok := p.tryServeStale(ip, now); ok {
            p.L().Warn("using stale cache due to status error",
                zap.String("ip", ip),
                zap.Int("status", resp.StatusCode),
                zap.String("tag", oldTag),
            )
            return oldTag, nil
        }

        // API 请求失败的结果缓存 30 秒
        p.cache.Store(ip, []byte(ValError), now, now.Add(ErrorCacheTTL))
        return ValError, fmt.Errorf("status code %d", resp.StatusCode)
    }

    // 请求状态码是200，读取响应内容
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        p.L().Error("failed to read response body", zap.String("ip", ip), zap.Error(err))
    
        if oldTag, ok := p.tryServeStale(ip, now); ok {
            return oldTag, nil
        }
        p.cache.Store(ip, []byte(ValError), now, now.Add(ErrorCacheTTL))
        return ValError, err
    }

    // 获取标签，正确标签举例：beijing_cmcc
    tag := strings.TrimSpace(string(body))

    if p.L().Core().Enabled(zap.DebugLevel) {
        p.L().Debug("api response raw",
            zap.String("ip", ip),
            zap.String("payload", tag),
        )
    }

    // 返回fallback是不再处理范围内，比如匹配不到国内省份或者运营商
    // 同样缓存配置的时间，默认 86400 秒（24h）
    if tag == "" || tag == "fallback" {
        ttl := time.Duration(p.args.CacheTTL) * time.Second
        p.cache.Store(ip, []byte(ValFallback), now, now.Add(ttl))
        return ValFallback, nil
    }

    // 正确结果，设置缓存有效期
    ttl := time.Duration(p.args.CacheTTL) * time.Second
    p.cache.Store(ip, []byte(tag), now, now.Add(ttl))
    return tag, nil
}

func (p *IPTagger) Close() error {
    if p.client != nil {
        p.client.CloseIdleConnections()
    }
    return p.cache.Close()
}