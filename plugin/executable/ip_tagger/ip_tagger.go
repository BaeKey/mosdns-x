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
	"github.com/pmkol/mosdns-x/pkg/cache/mem_cache"
	"github.com/pmkol/mosdns-x/pkg/ctxkey"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
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
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	a := args.(*Args)
	if a.Timeout <= 0 {
		a.Timeout = 5
	}
	if a.CacheSize <= 0 {
		a.CacheSize = 10240
	}
	if a.CacheTTL <= 0 {
		a.CacheTTL = 86400
	}

	transport := &http.Transport{
        MaxIdleConns:    100,
        IdleConnTimeout: 90 * time.Second,
    }

    if strings.HasPrefix(a.APIAddr, "unix://") {
        socketPath := strings.TrimPrefix(a.APIAddr, "unix://")
        transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
            return net.Dial("unix", socketPath)
        }
    }

    return &IPTagger{
        BP: bp,
        args: a,
        client: &http.Client{
            Timeout:   time.Duration(a.Timeout) * time.Millisecond,
            Transport: transport,
        },
        cache: mem_cache.NewMemCache(a.CacheSize, 0),
    }, nil
}

func (p *IPTagger) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
    clientAddr := qCtx.ReqMeta().GetClientAddr()
    if !clientAddr.IsValid() {
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

		if now.Before(expTime) {
			return tag
		}

		go p.asyncUpdate(ip)
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

func (p *IPTagger) asyncUpdate(ip string) {
	p.sf.Do(ip, func() (interface{}, error) {
		_, err := p.fetchFromAPI(ip)
		return nil, err
	})
}

func (p *IPTagger) fetchFromAPI(ip string) (string, error) {
    var req *http.Request
    var err error
    
    if strings.HasPrefix(p.args.APIAddr, "unix://") {
        url := fmt.Sprintf("http://unix/%s", ip)
        req, err = http.NewRequest(http.MethodGet, url, nil)
        if err == nil {
            req.Host = "localhost"
        }
    } else {
        url := fmt.Sprintf("%s/%s", strings.TrimRight(p.args.APIAddr, "/"), ip)
        req, err = http.NewRequest(http.MethodGet, url, nil)
    }

    if err != nil {
        p.L().Error("failed to create request", zap.Error(err))
        return ValError, err
    }

    resp, err := p.client.Do(req)

    now := time.Now()

	if err != nil {
		p.L().Error("api network error", zap.String("ip", ip), zap.Error(err))
		p.cache.Store(ip, []byte(ValError), now, now.Add(ErrorCacheTTL))
		return ValError, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusAccepted {
			p.cache.Store(ip, []byte(ValFallback), now, now.Add(1*time.Second))
			return "", nil
		}
		p.L().Error("api status error",
			zap.String("ip", ip),
			zap.Int("code", resp.StatusCode),
		)
		p.cache.Store(ip, []byte(ValError), now, now.Add(ErrorCacheTTL))
		return ValError, fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		p.L().Error("api read body error", zap.String("ip", ip), zap.Error(err))
		p.cache.Store(ip, []byte(ValError), now, now.Add(ErrorCacheTTL))
		return ValError, err
	}

	tag := string(body)

	if p.L().Core().Enabled(zap.DebugLevel) {
		p.L().Debug("api response raw",
			zap.String("ip", ip),
			zap.String("payload", tag),
		)
	}

	if tag == "" || tag == "fallback" {
		ttl := time.Duration(p.args.CacheTTL) * time.Second
		p.cache.Store(ip, []byte(ValFallback), now, now.Add(ttl))
		return ValFallback, nil
	}

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