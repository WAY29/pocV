package check

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/WAY29/pocV/internal/common/errors"
	common_structs "github.com/WAY29/pocV/pkg/common/structs"
	nuclei_structs "github.com/WAY29/pocV/pkg/nuclei/structs"
	"github.com/WAY29/pocV/pkg/xray/cel"
	"github.com/WAY29/pocV/pkg/xray/requests"
	"github.com/WAY29/pocV/pkg/xray/structs"
	xray_structs "github.com/WAY29/pocV/pkg/xray/structs"
	"github.com/WAY29/pocV/utils"

	"github.com/panjf2000/ants"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

var (
	Ticker    *time.Ticker
	WaitGroup sync.WaitGroup
	Pool      *ants.PoolWithFunc

	Verbose bool

	OutputChannel chan common_structs.Result
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
		req, _ := http.NewRequest("GET", target, nil)

		isVul, err = executeXrayPoc(req, &poc)
		if err != nil {
			wrappedErr := errors.Wrapf(err, "Run Xray Poc (%v) error", pocName)
			utils.ErrorP(wrappedErr)
			return
		}

		OutputChannel <- &common_structs.PocResult{
			Str:            fmt.Sprintf("%s (%s)", target, pocName),
			Success:        isVul,
			URL:            target,
			PocName:        poc.Name,
			PocLink:        poc.Detail.Links,
			PocAuthor:      poc.Detail.Author,
			PocDescription: poc.Detail.Description,
		}

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
			wrappedErr := errors.Wrapf(err, "Run Nuclei Poc (%v) error", pocName)
			utils.ErrorP(wrappedErr)
			return
		}

		for _, r := range results {
			if r.ExtractorName != "" {
				desc = r.TemplateID + ":" + r.ExtractorName
			} else if r.MatcherName != "" {
				desc = r.TemplateID + ":" + r.MatcherName
			}

			OutputChannel <- &common_structs.PocResult{
				Str:            fmt.Sprintf("%s (%s) ", r.Matched, r.TemplateID),
				Success:        isVul,
				URL:            r.Matched,
				PocName:        r.TemplateID,
				PocLink:        []string{},
				PocAuthor:      author,
				PocDescription: desc,
			}
		}
	}

}

func executeNucleiPoc(target string, poc *nuclei_structs.Poc) (results []*output.ResultEvent, isVul bool, err error) {
	isVul = false

	utils.DebugF("Run Nuclei Poc %s (%s)", target, poc.Info.Name)

	e := poc.Executer
	results = make([]*output.ResultEvent, 0, e.Requests())

	err = e.ExecuteWithResults(target, func(result *output.InternalWrappedEvent) {
		if len(result.Results) > 0 {
			isVul = true
		}
		results = append(results, result.Results...)
	})

	if len(results) == 0 {
		results = append(results, &output.ResultEvent{TemplateID: poc.ID, Matched: target})
	}
	return results, isVul, err
}

func executeXrayPoc(oReq *http.Request, p *xray_structs.Poc) (bool, error) {
	var (
		setPayloadValue string
		oReqUrlString   = oReq.URL.String()
	)

	utils.DebugF("Run Xray Poc %s (%s)", oReqUrlString, p.Name)

	c := cel.NewEnvOption()

	c.UpdateCompileOptions(p.Set)
	env, err := cel.NewEnv(&c)

	if err != nil {
		wrappedErr := errors.Wrap(err, "Environment creation error")
		utils.ErrorP(wrappedErr)
		return false, err
	}

	variableMap := make(map[string]interface{})
	req, err := requests.ParseRequest(oReq)
	if err != nil {
		wrappedErr := errors.Wrapf(err, "Run poc (%v) error", p.Name)
		utils.ErrorP(wrappedErr)
		return false, err
	}
	variableMap["request"] = req

	// 现在假定set中payload作为最后产出，那么先解析其他的自定义变量，更新map[string]interface{}后再来解析payload
	for _, item := range p.Set {
		k, expression := item.Key.(string), item.Value.(string)
		if k != "payload" {
			if expression == "newReverse()" {
				reverse := xrayNewReverse()
				variableMap[k] = reverse
				continue
			}
			out, err := cel.Evaluate(env, expression, variableMap)
			if err != nil {
				wrappedErr := errors.Wrap(err, "Set variable error")
				utils.ErrorP(wrappedErr)
				continue
			}
			switch value := out.Value().(type) {
			case *xray_structs.UrlType:
				variableMap[k] = cel.UrlTypeToString(value)
			case int64:
				variableMap[k] = int(value)
			default:
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		} else {
			setPayloadValue = expression
		}
	}

	// 执行payload
	if setPayloadValue != "" {
		out, err := cel.Evaluate(env, setPayloadValue, variableMap)
		if err != nil {
			return false, err
		}
		variableMap["payload"] = fmt.Sprintf("%v", out)
	}

	success := false

	// 处理单条Rule
	DealWithRule := func(rule xray_structs.Rule) (bool, error) {
		var (
			flag, ok bool
			err      error
			Request  *http.Request
			Response *xray_structs.Response
		)

		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		// 尝试获取缓存
		if Request, Response, ok = requests.XrayGetRequestResponseCache(&rule); !ok {
			// 处理Path
			if oReq.URL.Path != "" && oReq.URL.Path != "/" {
				req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
			} else {
				req.Url.Path = rule.Path
			}
			// 某些poc没有区分path和query，需要处理
			req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
			req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

			// 克隆请求对象
			Request, _ = http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))

			Request.Header = oReq.Header.Clone()
			for k, v := range rule.Headers {
				Request.Header.Set(k, v)
			}

			// 发起请求
			Response, err = requests.DoRequest(Request, rule.FollowRedirects)
			if err != nil {
				return false, err
			}

			// 设置缓存
			requests.XraySetRequestResponseCache(&rule, Request, Response)
		} else {
			utils.DebugF("Use Request Cache [%s%s]", oReqUrlString, rule.Path)
		}

		variableMap["response"] = Response

		// 先判断响应页面是否匹配search规则
		if rule.Search != "" {
			result := xrayDoSearch(strings.TrimSpace(rule.Search), string(Response.Body))
			if result != nil && len(result) > 0 { // 正则匹配成功
				for k, v := range result {
					variableMap[k] = v
				}
			} else {
				return false, nil
			}
		}

		// 执行表达式
		out, err := cel.Evaluate(env, rule.Expression, variableMap)
		if err != nil {
			wrappedErr := errors.Wrap(err, "Evalute expression error")
			return false, wrappedErr
		}

		// 判断最后执行表达式结果
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}
		return flag, nil
	}

	// Rules
	if len(p.Rules) > 0 {
		success = DealWithRules(DealWithRule, p.Rules)
	} else { // Groups
		for _, rules := range p.Groups {
			success = DealWithRules(DealWithRule, rules)
			if success {
				break
			}
		}
	}

	return success, nil
}

// 处理xray rules组，只要其中一个不成功则失败
func DealWithRules(DealWithRuleFunc func(xray_structs.Rule) (bool, error), rules []xray_structs.Rule) bool {
	successFlag := false
	for _, rule := range rules {
		flag, err := DealWithRuleFunc(rule)
		if err != nil {
			wrappedErr := errors.Wrap(err, "Execute Rule error")
			utils.ErrorP(wrappedErr)
		}

		if err != nil || !flag { //如果false不继续执行后续rule
			successFlag = false // 如果其中一步为flag，则直接break
			break
		}
		successFlag = true
	}
	return successFlag
}

// 处理xray search属性，匹配正则
func xrayDoSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	utils.WarningF("Regexp compile error: %v", err.Error())
	if err != nil {
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				paramsMap[name] = result[i]
			}
		}
		return paramsMap
	}
	return nil
}

// xray dns反连平台 目前只支持dnslog.cn和ceye.io
func xrayNewReverse() *xray_structs.Reverse {
	var urlStr string
	switch common_structs.ReversePlatformType {
	case structs.ReverseType_Ceye:
		sub := utils.RandomStr(utils.AsciiLowercaseAndDigits, 8)
		urlStr = fmt.Sprintf("http://%s.%s", sub, common_structs.CeyeDomain)
	case structs.ReverseType_DnslogCN:
		dnslogCnRequest := common_structs.DnslogCNGetDomainRequest
		resp, err := requests.DoRequest(dnslogCnRequest, false)
		if err != nil {
			wrappedErr := errors.Wrap(err, "Get reverse domain error: Can't get domain from dnslog.cn")
			utils.ErrorP(wrappedErr)
			return &xray_structs.Reverse{}
		}
		urlStr = "http://" + string(resp.GetBody())
	default:
		return &xray_structs.Reverse{}
	}

	u, _ := url.Parse(urlStr)
	utils.DebugF("Get reverse domain: %s", u.Hostname())

	return &xray_structs.Reverse{
		Url:                requests.ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
		ReverseType:        common_structs.ReversePlatformType,
	}
}
