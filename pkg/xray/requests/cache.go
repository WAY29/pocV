package requests

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/WAY29/pocV/pkg/xray/structs"
	"github.com/WAY29/pocV/utils"
	"github.com/bluele/gcache"
)

var (
	GC gcache.Cache
)

func InitCache(size int) {
	GC = gcache.New(size).ARC().Build()
}

func XrayGetRuleHash(req *structs.RuleRequest) string {
	headers := req.Headers
	keys := make([]string, len(headers))
	headerStirng := ""
	i := 0
	for k := range headers {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for _, k := range keys {
		headerStirng += fmt.Sprintf("%s%s", k, headers[k])
	}

	return utils.MD5(fmt.Sprintf("%s%s%s%s%v", req.Method, req.Path, headerStirng, req.Body, req.FollowRedirects))
}

func XraySetRequestResponseCache(ruleReq *structs.RuleRequest, request *http.Request, protoRequest *structs.Request, protoResponse *structs.Response) bool {

	ruleHash := XrayGetRuleHash(ruleReq)

	if cache, err := GC.Get(ruleHash); err != nil {
		if _, ok := cache.(*structs.RequestCache); ok {
			return true
		}
	}

	if err := GC.Set(ruleHash, &structs.RequestCache{
		Request:       request,
		ProtoRequest:  protoRequest,
		ProtoResponse: protoResponse,
	}); err == nil {
		return true
	}

	return false
}

func XrayGetRequestResponseCache(ruleReq *structs.RuleRequest) (*http.Request, *structs.Request, *structs.Response, bool) {
	ruleHash := XrayGetRuleHash(ruleReq)

	if cache, err := GC.Get(ruleHash); err == nil {
		if requestCache, ok := cache.(*structs.RequestCache); ok {
			return requestCache.Request, requestCache.ProtoRequest, requestCache.ProtoResponse, true
		} else {
		}
	}

	return nil, nil, nil, false
}
