package check

import (
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/WAY29/pocV/internal/common/errors"
	"github.com/WAY29/pocV/pkg/xray/cel"
	"github.com/WAY29/pocV/pkg/xray/requests"
	xray_structs "github.com/WAY29/pocV/pkg/xray/structs"
	"github.com/WAY29/pocV/utils"
	"gopkg.in/yaml.v2"
)

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
