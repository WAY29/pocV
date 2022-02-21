package check

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
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
	"gopkg.in/yaml.v2"

	"github.com/panjf2000/ants"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

var (
	Ticker  *time.Ticker
	Pool    *ants.PoolWithFunc
	Verbose bool

	WaitGroup sync.WaitGroup

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
			utils.ErrorP(err)
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
			utils.ErrorP(err)
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

	defer func() {
		if r := recover(); r != nil {
			err = errors.Wrapf(r.(error), "Run Nuclei Poc[%s] error", poc.ID)
			isVul = false
		}
	}()

	utils.DebugF("Run Nuclei Poc %s[%s]", target, poc.Info.Name)

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

func executeXrayPoc(oReq *http.Request, poc *xray_structs.Poc) (isVul bool, err error) {
	isVul = false

	defer func() {
		if r := recover(); r != nil {
			err = errors.Wrapf(r.(error), "Run Xray Poc[%s] error", poc.Name)
			isVul = false
		}
	}()

	var (
		milliseconds  int64
		Request       *http.Request
		Response      *http.Response
		protoRequest  *xray_structs.Request
		protoResponse *xray_structs.Response
		oReqUrlString = oReq.URL.String()
	)

	utils.DebugF("Run Xray Poc %s[%s]", oReqUrlString, poc.Name)

	c := cel.NewEnvOption()
	env, err := cel.NewEnv(&c)
	if err != nil {
		wrappedErr := errors.Wrap(err, "Environment creation error")
		utils.ErrorP(wrappedErr)
		return false, err
	}

	// 请求中的全局变量
	variableMap := make(map[string]interface{})

	// 定义渲染函数
	render := func(v string) string {
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			v1Value := fmt.Sprintf("%v", v1)
			t := "{{" + k1 + "}}"
			if !strings.Contains(v, t) {
				continue
			}
			v = strings.ReplaceAll(v, t, v1Value)
		}
		return v
	}
	// 定义evaluateUpdateVariableMap
	evaluateUpdateVariableMap := func(env *cel.Env, set yaml.MapSlice) {
		for _, item := range set {
			k, expression := item.Key.(string), item.Value.(string)
			if expression == "newReverse()" {
				reverse := xrayNewReverse()
				variableMap[k] = reverse
				continue
			}
			env, err = cel.NewEnv(&c)
			if err != nil {
				wrappedErr := errors.Wrap(err, "Environment re-creation error")
				utils.ErrorP(wrappedErr)
				return
			}

			out, err := cel.Evaluate(env, expression, variableMap)
			if err != nil {
				wrappedErr := errors.Wrapf(err, "Evalaute expression error: %s", expression)
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
		}
	}

	// 处理set
	c.UpdateCompileOptions(poc.Set)
	evaluateUpdateVariableMap(env, poc.Set)

	// 处理payload
	for _, setMapVal := range poc.Payloads.Payloads {
		setMap := setMapVal.Value.(yaml.MapSlice)
		c.UpdateCompileOptions(setMap)
		evaluateUpdateVariableMap(env, setMap)
	}
	// 渲染detail
	detail := &poc.Detail
	detail.Author = render(detail.Author)
	for k, v := range poc.Detail.Links {
		detail.Links[k] = render(v)
	}
	fingerPrint := &detail.FingerPrint
	for _, info := range fingerPrint.Infos {
		info.ID = render(info.ID)
		info.Name = render(info.Name)
		info.Version = render(info.Version)
		info.Type = render(info.Type)
	}
	fingerPrint.HostInfo.Hostname = render(fingerPrint.HostInfo.Hostname)
	vulnerability := &detail.Vulnerability
	vulnerability.ID = render(vulnerability.ID)
	vulnerability.Match = render(vulnerability.Match)

	// 处理Rule中的单条request
	RequestInvoke := func(ruleName string, rule xray_structs.Rule) (bool, error) {
		var (
			flag, ok bool
			err      error
			ruleReq  xray_structs.RuleRequest = rule.Request
		)

		// 渲染请求头，请求路径和请求体
		for k, v := range ruleReq.Headers {
			ruleReq.Headers[k] = render(v)
		}
		ruleReq.Path = render(strings.TrimSpace(ruleReq.Path))
		ruleReq.Body = render(strings.TrimSpace(ruleReq.Body))

		// 尝试获取缓存
		if Request, protoRequest, protoResponse, ok = requests.XrayGetRequestResponseCache(&ruleReq); !ok || !rule.Request.Cache {
			// 获取protoRequest
			protoRequest, err = requests.ParseRequest(oReq)
			if err != nil {
				wrappedErr := errors.Wrapf(err, "Run poc[%v] parse request error", poc.Name)
				utils.ErrorP(wrappedErr)
				return false, err
			}

			// 处理Path
			if strings.HasPrefix(ruleReq.Path, "/") {
				protoRequest.Url.Path = path.Join(oReq.URL.Path, ruleReq.Path)
			} else if strings.HasPrefix(ruleReq.Path, "^") {
				protoRequest.Url.Path = ruleReq.Path[1:]
			}

			// 某些poc没有区分path和query，需要处理
			protoRequest.Url.Path = strings.ReplaceAll(protoRequest.Url.Path, " ", "%20")
			protoRequest.Url.Path = strings.ReplaceAll(protoRequest.Url.Path, "+", "%20")

			// 克隆请求对象
			Request, _ = http.NewRequest(ruleReq.Method, fmt.Sprintf("%s://%s%s", protoRequest.Url.Scheme, protoRequest.Url.Host, protoRequest.Url.Path), strings.NewReader(ruleReq.Body))

			Request.Header = oReq.Header.Clone()
			rawHeader := ""
			for k, v := range ruleReq.Headers {
				Request.Header.Set(k, v)
				rawHeader += fmt.Sprintf("%s=%s\n", k, v)
			}
			protoRequest.RawHeader = []byte(strings.Trim(rawHeader, "\n"))

			// 发起请求
			Response, milliseconds, err = requests.DoRequest(Request, ruleReq.FollowRedirects)
			if err != nil {
				return false, err
			}

			// 获取protoResponse
			protoResponse, err = requests.ParseResponse(Response, milliseconds)
			if err != nil {
				wrappedErr := errors.Wrapf(err, "Run poc[%s] parse response error", poc.Name)
				utils.ErrorP(wrappedErr)
				return false, err
			}

			// 设置缓存
			requests.XraySetRequestResponseCache(&ruleReq, Request, protoRequest, protoResponse)
		} else {
			utils.DebugF("Hit request cache [%s%s]", oReqUrlString, ruleReq.Path)
		}

		variableMap["request"] = protoRequest
		variableMap["response"] = protoResponse

		utils.DebugF("raw requests: \n%#s", string(protoRequest.Raw))
		utils.DebugF("raw response: \n%#s", string(protoResponse.Raw))

		// 执行表达式
		// ? 需要重新生成一遍环境，否则之前增加的变量定义不生效
		env, err = cel.NewEnv(&c)
		if err != nil {
			wrappedErr := errors.Wrap(err, "Environment re-creation error")
			utils.ErrorP(wrappedErr)
			return false, wrappedErr
		}
		out, err := cel.Evaluate(env, rule.Expression, variableMap)

		if err != nil {
			wrappedErr := errors.Wrapf(err, "Evalute rule[%s] expression error: %s", ruleName, rule.Expression)
			utils.ErrorP(wrappedErr)
			return false, wrappedErr
		}

		// 判断表达式结果
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}

		// 处理output
		c.UpdateCompileOptions(rule.Output)
		evaluateUpdateVariableMap(env, rule.Output)
		// 注入名为ruleName的函数
		c.NewResultFunction(ruleName, flag)

		return flag, nil
	}

	// 执行rule
	// TODO: yaml读取时确保顺序(map是无序的，考虑将Rules设置为yaml.MapSlice，但是需要手动处理解析后的数据)
	// TODO: 暂时先用排序根据ruleName确保顺序
	rules := poc.Rules
	ruleKeys := make([]string, len(rules))
	i := 0
	for k := range rules {
		ruleKeys[i] = k
		i++
	}
	sort.Strings(ruleKeys)

	for _, ruleName := range ruleKeys {
		_, err = RequestInvoke(ruleName, rules[ruleName])
	}

	// 判断poc总体表达式结果
	// ? 需要重新生成一遍环境，否则之前增加的结果函数不生效
	env, err = cel.NewEnv(&c)
	if err != nil {
		wrappedErr := errors.Wrap(err, "Environment re-creation error")
		utils.ErrorP(wrappedErr)
		return false, err
	}

	successVal, err := cel.Evaluate(env, poc.Expression, variableMap)
	if err != nil {
		wrappedErr := errors.Wrapf(err, "Evalute poc[%s] expression error: %s", poc.Name, poc.Expression)
		return false, wrappedErr
	}

	isVul, ok := successVal.Value().(bool)
	if !ok {
		isVul = false
	}

	return isVul, nil
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
		resp, _, err := requests.DoRequest(dnslogCnRequest, false)
		if err != nil {
			wrappedErr := errors.Wrap(err, "Get reverse domain error: Can't get domain from dnslog.cn")
			utils.ErrorP(wrappedErr)
			return &xray_structs.Reverse{}
		}
		content, _ := requests.GetRespBody(resp)
		urlStr = "http://" + string(content)
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
