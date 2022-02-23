package check

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/WAY29/pocV/internal/common/errors"
	common_structs "github.com/WAY29/pocV/pkg/common/structs"
	nuclei_structs "github.com/WAY29/pocV/pkg/nuclei/structs"
	"github.com/WAY29/pocV/pkg/xray/requests"
	xray_structs "github.com/WAY29/pocV/pkg/xray/structs"
	"github.com/WAY29/pocV/utils"

	"github.com/panjf2000/ants"
)

var (
	EmptyLinks = []string{}

	Ticker  *time.Ticker
	Pool    *ants.PoolWithFunc
	Verbose bool

	WaitGroup sync.WaitGroup

	OutputChannel chan common_structs.Result

	PocResultPool = sync.Pool{
		New: func() interface{} {
			return new(common_structs.PocResult)
		},
	}

	ReversePool = sync.Pool{
		New: func() interface{} {
			return new(xray_structs.Reverse)
		},
	}
)

// 初始化协程池
func InitCheck(threads, rate int, verbose bool) {
	var err error

	rateLimit := time.Second / time.Duration(rate)
	Ticker = time.NewTicker(rateLimit)
	Pool, err = ants.NewPoolWithFunc(threads, check)
	if err != nil {
		utils.CliError("Initialize goroutine pool error: "+err.Error(), 2)
	}

	Verbose = verbose
}

// 将任务放入协程池
func Start(targets []string, xrayPocMap map[string]xray_structs.Poc, nucleiPocMap map[string]nuclei_structs.Poc, outputChannel chan common_structs.Result) {
	// 设置outputChannel
	OutputChannel = outputChannel

	for _, target := range targets {
		for _, poc := range xrayPocMap {
			WaitGroup.Add(1)
			Pool.Invoke(&xray_structs.Task{
				Target: target,
				Poc:    poc,
			})
		}
		for _, poc := range nucleiPocMap {
			WaitGroup.Add(1)
			Pool.Invoke(&nuclei_structs.Task{
				Target: target,
				Poc:    poc,
			})
		}
	}
}

// 等待协程池
func Wait() {
	WaitGroup.Wait()
}

// 释放协程池
func End() {
	Pool.Release()
}

// 核心代码，poc检测
func check(taskInterface interface{}) {
	var (
		oRequest *http.Request = nil

		isVul   bool
		err     error
		pocName string
	)

	defer WaitGroup.Done()
	<-Ticker.C

	switch taskInterface.(type) {
	case *xray_structs.Task:
		task, ok := taskInterface.(*xray_structs.Task)
		if !ok {
			wrappedErr := errors.Newf(errors.ConvertInterfaceError, "Can't convert task interface: %#v", err)
			utils.ErrorP(wrappedErr)
			return
		}
		target, poc := task.Target, task.Poc

		pocName = poc.Name
		if poc.Transport != "tcp" && poc.Transport != "udp" {
			oRequest, _ = http.NewRequest("GET", target, nil)
		}

		isVul, err = executeXrayPoc(oRequest, target, &poc)
		if err != nil {
			utils.ErrorP(err)
			return
		}

		pocResult := PocResultPool.Get().(*common_structs.PocResult)
		pocResult.Str = fmt.Sprintf("%s (%s)", target, pocName)
		pocResult.Success = isVul
		pocResult.URL = target
		pocResult.PocName = poc.Name
		pocResult.PocLink = poc.Detail.Links
		pocResult.PocAuthor = poc.Detail.Author
		pocResult.PocDescription = poc.Detail.Description

		OutputChannel <- pocResult

	case *nuclei_structs.Task:
		var (
			desc    string
			author  string
			authors []string
		)

		task, ok := taskInterface.(*nuclei_structs.Task)
		if !ok {
			wrappedErr := errors.Newf(errors.ConvertInterfaceError, "Can't convert task interface: %#v", err)
			utils.ErrorP(wrappedErr)
			return
		}
		target, poc := task.Target, task.Poc
		authors, ok = poc.Info.Authors.Value.([]string)
		if !ok {
			author = "Unknown"
		} else {
			author = strings.Join(authors, ", ")
		}

		results, isVul, err := executeNucleiPoc(target, &poc)
		if err != nil {
			utils.ErrorP(err)
			return
		}

		for _, r := range results {
			if r.ExtractorName != "" {
				desc = r.TemplateID + ":" + r.ExtractorName
			} else if r.MatcherName != "" {
				desc = r.TemplateID + ":" + r.MatcherName
			}

			pocResult := PocResultPool.Get().(*common_structs.PocResult)
			pocResult.Str = fmt.Sprintf("%s (%s) ", r.Matched, r.TemplateID)
			pocResult.Success = isVul
			pocResult.URL = r.Matched
			pocResult.PocName = r.TemplateID
			pocResult.PocLink = EmptyLinks
			pocResult.PocAuthor = author
			pocResult.PocDescription = desc

			OutputChannel <- pocResult
		}
	}

}

// xray dns反连平台 目前只支持dnslog.cn和ceye.io
func xrayNewReverse() (reverse *xray_structs.Reverse) {
	var (
		urlStr string
	)
	reverse = ReversePool.Get().(*xray_structs.Reverse)

	switch common_structs.ReversePlatformType {
	case xray_structs.ReverseType_Ceye:
		sub := utils.RandomStr(utils.AsciiLowercaseAndDigits, 8)
		urlStr = fmt.Sprintf("http://%s.%s/", sub, common_structs.CeyeDomain)
	case xray_structs.ReverseType_DnslogCN:
		dnslogCnRequest := common_structs.DnslogCNGetDomainRequest
		resp, _, err := requests.DoRequest(dnslogCnRequest, false)
		if err != nil {
			wrappedErr := errors.Wrap(err, "Get reverse domain error: Can't get domain from dnslog.cn")
			utils.ErrorP(wrappedErr)
			return
		}
		content, _ := requests.GetRespBody(resp)
		urlStr = "http://" + string(content) + "/"
	default:
		return
	}

	u, _ := url.Parse(urlStr)
	utils.DebugF("Get reverse domain: %s", u.Hostname())

	reverse.Url = requests.ParseUrl(u)
	reverse.Domain = u.Hostname()
	reverse.Ip = u.Host
	reverse.IsDomainNameServer = false
	reverse.ReverseType = common_structs.ReversePlatformType

	return
}
