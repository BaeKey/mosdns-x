package ctxkey

type ipTagKey struct{}
type bgUpdateKey struct{}

var CtxKeyIpResolverTag = ipTagKey{}
var CtxKeyBgUpdate = bgUpdateKey{}