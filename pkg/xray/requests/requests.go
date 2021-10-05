package requests

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/WAY29/pocV/pkg/xray/structs"
	"github.com/WAY29/pocV/utils"
)

var (
	client            *http.Client
	clientNoRedirect  *http.Client
	dialTimout        = 5 * time.Second
	keepAlive         = 15 * time.Second
	XrayRequestCache  = make(map[string]*http.Request)
	XrayResponseCache = make(map[string]*structs.Response)
)

func InitHttpClient(ThreadsNum int, DownProxy string, Timeout time.Duration) error {
	dialer := &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}

	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
	}

	if DownProxy != "" {
		u, err := url.Parse(DownProxy)
		if err != nil {
			wrappedErr := errors.Wrap(err, "Parse Proxy error")
			return wrappedErr
		}
		tr.Proxy = http.ProxyURL(u)
	}

	clientCookieJar, _ := cookiejar.New(nil)
	clientNoRedirectCookieJar, _ := cookiejar.New(nil)

	client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
		Jar:       clientCookieJar,
	}
	clientNoRedirect = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
		Jar:       clientNoRedirectCookieJar,
	}
	clientNoRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return nil
}

func ParseUrl(u *url.URL) *structs.UrlType {
	return &structs.UrlType{
		Scheme:   u.Scheme,
		Domain:   u.Hostname(),
		Host:     u.Host,
		Port:     u.Port(),
		Path:     u.EscapedPath(),
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}
}

func XrayCanCluster(r, other *structs.Rule) bool {
	if r.Method != other.Method ||
		r.Path != other.Path ||
		r.Body != other.Body ||
		r.FollowRedirects != other.FollowRedirects ||
		!reflect.DeepEqual(r.Headers, other.Headers) {
		return false
	}
	return true
}

func XrayGetRuleHash(rule *structs.Rule) string {
	headers := rule.Headers
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

	return utils.MD5(fmt.Sprintf("%s%s%s%s%v", rule.Method, rule.Path, headerStirng, rule.Body, rule.FollowRedirects))
}

func XraySetRequestResponseCache(rule *structs.Rule, request *http.Request, response *structs.Response) bool {
	ruleHash := XrayGetRuleHash(rule)

	if _, ok := XrayRequestCache[ruleHash]; !ok {
		XrayRequestCache[ruleHash] = request
	}
	if _, ok := XrayResponseCache[ruleHash]; !ok {
		XrayResponseCache[ruleHash] = response
		return true
	}

	return false
}

func XrayGetRequestResponseCache(rule *structs.Rule) (*http.Request, *structs.Response, bool) {
	var (
		Request  *http.Request
		Response *structs.Response
		ok       bool
	)
	ruleHash := XrayGetRuleHash(rule)

	if Request, ok = XrayRequestCache[ruleHash]; ok {
		if Response, ok = XrayResponseCache[ruleHash]; ok {
			return Request, Response, true
		}
	}

	return nil, nil, false
}

func DoRequest(req *http.Request, redirect bool) (*structs.Response, error) {
	if req.Body == nil || req.Body == http.NoBody {
	} else {
		req.Header.Set("Content-Length", strconv.Itoa(int(req.ContentLength)))
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	var oResp *http.Response
	var err error
	if redirect {
		oResp, err = client.Do(req)
	} else {
		oResp, err = clientNoRedirect.Do(req)
	}
	if oResp != nil {
		defer oResp.Body.Close()
	}
	if err != nil {
		wrappedErr := errors.Wrap(err, "Request error")
		return nil, wrappedErr
	}
	resp, err := ParseResponse(oResp)
	if err != nil {
		wrappedErr := errors.Wrap(err, "Parse response error")
		return nil, wrappedErr
	}
	return resp, err
}

func ParseRequest(oReq *http.Request) (*structs.Request, error) {
	req := &structs.Request{}
	req.Method = oReq.Method
	req.Url = ParseUrl(oReq.URL)
	header := make(map[string]string)
	for k := range oReq.Header {
		header[k] = oReq.Header.Get(k)
	}
	req.Headers = header
	req.ContentType = oReq.Header.Get("Content-Type")
	if oReq.Body == nil || oReq.Body == http.NoBody {
	} else {
		data, err := ioutil.ReadAll(oReq.Body)
		if err != nil {
			wrappedErr := errors.Wrap(err, "Get request body error")
			return nil, wrappedErr
		}
		req.Body = data
		oReq.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	}
	return req, nil
}

func ParseResponse(oResp *http.Response) (*structs.Response, error) {
	var resp structs.Response
	header := make(map[string]string)
	resp.Status = int32(oResp.StatusCode)
	resp.Url = ParseUrl(oResp.Request.URL)
	for k := range oResp.Header {
		header[k] = oResp.Header.Get(k)
	}
	resp.Headers = header
	resp.ContentType = oResp.Header.Get("Content-Type")
	body, err := getRespBody(oResp)
	if err != nil {
		wrappedErr := errors.Wrap(err, "Get response body error")
		return nil, wrappedErr
	}
	resp.Body = body
	return &resp, nil
}

func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, _ := gzip.NewReader(oResp.Body)
		defer gr.Close()
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		raw, err := ioutil.ReadAll(oResp.Body)
		if err != nil {
			wrappedErr := errors.Wrap(err, "Get response body error")
			return nil, wrappedErr
		}
		body = raw
	}
	return body, nil
}
