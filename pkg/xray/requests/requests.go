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
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/WAY29/pocV/internal/common/errors"
	"github.com/WAY29/pocV/pkg/xray/structs"
)

var (
	client           *http.Client
	clientNoRedirect *http.Client
	dialTimout       = 5 * time.Second
	keepAlive        = 15 * time.Second
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
			wrappedErr := errors.Newf(errors.ProxyError, "Parse Proxy error: %v", err)
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

func DoRequest(req *http.Request, redirect bool) (*http.Response, int64, error) {
	var (
		milliseconds int64
		oResp        *http.Response
		err          error
	)
	if req.Body == nil || req.Body == http.NoBody {
	} else {
		req.Header.Set("Content-Length", strconv.Itoa(int(req.ContentLength)))
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	start := time.Now()

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			milliseconds = time.Since(start).Nanoseconds() / 1e6
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	if redirect {
		oResp, err = client.Do(req)
	} else {
		oResp, err = clientNoRedirect.Do(req)
	}

	if err != nil {
		wrappedErr := errors.Newf(errors.RequestError, "Request error: %v", err)
		return nil, 0, wrappedErr
	}

	return oResp, milliseconds, nil
}

func ParseRequest(oReq *http.Request) (*structs.Request, error) {
	var (
		header    string
		rawHeader string = ""
	)
	req := &structs.Request{}

	req.Method = oReq.Method
	req.Url = ParseUrl(oReq.URL)

	headers := make(map[string]string)
	for k := range oReq.Header {
		header = oReq.Header.Get(k)
		headers[k] = header
		rawHeader += fmt.Sprintf("%s=%s\n", k, headers)
	}
	req.Headers = headers
	req.RawHeader = []byte(strings.Trim(rawHeader, "\n"))

	req.ContentType = oReq.Header.Get("Content-Type")
	if oReq.Body == nil || oReq.Body == http.NoBody {
	} else {
		data, err := ioutil.ReadAll(oReq.Body)
		if err != nil {
			wrappedErr := errors.Newf(errors.RequestError, "Get request error: %v", err)
			return nil, wrappedErr
		}
		req.Body = data
		oReq.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	}

	req.Raw, _ = httputil.DumpRequestOut(oReq, true)

	return req, nil
}

func ParseResponse(oResp *http.Response, milliseconds int64) (*structs.Response, error) {
	var resp structs.Response
	header := make(map[string]string)
	resp.Status = int32(oResp.StatusCode)
	resp.Url = ParseUrl(oResp.Request.URL)
	for k := range oResp.Header {
		header[k] = oResp.Header.Get(k)
	}
	resp.Headers = header
	resp.ContentType = oResp.Header.Get("Content-Type")
	body, err := GetRespBody(oResp)
	if err != nil {
		return nil, err
	}

	resp.Raw = body
	resp.Body = body

	resp.Latency = milliseconds

	return &resp, nil
}

func GetRespBody(oResp *http.Response) ([]byte, error) {
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
			wrappedErr := errors.Newf(errors.ResponseError, "Get response body error: %v", err)
			return nil, wrappedErr
		}
		body = raw
	}
	return body, nil
}
