package qname_validator

import (
	"context"
	"strings"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "qname_validator"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.MatcherPlugin = (*validator)(nil)

type Args struct {
	// 拦截单层域名 (如 "localhost.", "router.", "box.")
	CheckSingleLabel *bool `yaml:"check_single_label"`

	// 拦截含有非法字符的域名
	// 仅允许: a-z, 0-9, -, _, . 
	CheckInvalidChars *bool `yaml:"check_invalid_chars"`

	// 黑名单后缀列表 (如 "lan", "local", "internal")
	Suffixes []string `yaml:"suffixes"`

	// 限制生效的 QType (如 ["A", "AAAA"])
	// 填入 "ANY" 则匹配所有类型
	CheckedQTypes []string `yaml:"checked_qtypes"`
}

type validator struct {
	*coremain.BP
	checkSingleLabel  bool
	checkInvalidChars bool
	suffixes          []string
	checkedQTypes     []uint16
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	a := args.(*Args)
	v := &validator{BP: bp}

	if a.CheckSingleLabel == nil {
		def := true
		v.checkSingleLabel = def
	} else {
		v.checkSingleLabel = *a.CheckSingleLabel
	}

	if a.CheckInvalidChars == nil {
		def := true
		v.checkInvalidChars = def
	} else {
		v.checkInvalidChars = *a.CheckInvalidChars
	}

	v.suffixes = make([]string, 0, len(a.Suffixes))
	for _, s := range a.Suffixes {
		if s == "" {
			continue
		}
		s = strings.ToLower(s)
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		if !strings.HasSuffix(s, ".") {
			s = s + "."
		}
		v.suffixes = append(v.suffixes, s)
	}

	if len(a.CheckedQTypes) == 0 {
		v.checkedQTypes = []uint16{dns.TypeA, dns.TypeAAAA}
	} else {
		v.checkedQTypes = make([]uint16, 0, len(a.CheckedQTypes))
		for _, tStr := range a.CheckedQTypes {
			if tStr == "ANY" {
				v.checkedQTypes = nil
				break
			}
			if t, ok := dns.StringToType[strings.ToUpper(tStr)]; ok {
				v.checkedQTypes = append(v.checkedQTypes, t)
			}
		}
	}

	return v, nil
}

func (v *validator) Match(ctx context.Context, qCtx *query_context.Context) (bool, error) {
	q := qCtx.Q()
	if len(q.Question) == 0 {
		return false, nil
	}
	question := q.Question[0]

	if len(v.checkedQTypes) > 0 {
		typeMatched := false
		for _, t := range v.checkedQTypes {
			if question.Qtype == t {
				typeMatched = true
				break
			}
		}
		if !typeMatched {
			return false, nil
		}
	}

	qName := question.Name
	qLen := len(qName)

	if v.checkSingleLabel || v.checkInvalidChars {
		dotCount := 0
		
		for i := 0; i < qLen; i++ {
			b := qName[i]

			if b == '.' {
				dotCount++
			}

			if v.checkInvalidChars {
				isValid := false
				if b >= 'a' && b <= 'z' { isValid = true } else
				if b >= '0' && b <= '9' { isValid = true } else
				if b == '-' || b == '.' { isValid = true } else
				if b == '_'             { isValid = true } else 
				if b >= 'A' && b <= 'Z' { isValid = true }

				if !isValid {
					return true, nil
				}
			}
		}

		if v.checkSingleLabel && dotCount <= 1 {
			return true, nil
		}
	}

	if len(v.suffixes) > 0 {
		for _, s := range v.suffixes {
			if hasSuffixFold(qName, s) {
				return true, nil
			}

			if qLen == len(s)-1 && equalFold(qName, s[1:]) {
				return true, nil
			}
		}
	}

	return false, nil
}

func hasSuffixFold(s, suffix string) bool {
	sLen := len(s)
	sfLen := len(suffix)
	if sLen < sfLen {
		return false
	}
	// 仅比较尾部
	return equalFold(s[sLen-sfLen:], suffix)
}

func equalFold(src, target string) bool {
	if len(src) != len(target) {
		return false
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c >= 'A' && c <= 'Z' {
			c |= 0x20
		}
		if c != target[i] {
			return false
		}
	}
	return true
}