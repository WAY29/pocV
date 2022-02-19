package structs

import "gopkg.in/yaml.v2"

// 参考 pocassist/blob/master/poc/rule/rule.go
// 单个规则
type Rule struct {
	Request    RuleRequest   `yaml:"request"`
	Expression string        `yaml:"expression"`
	Output     yaml.MapSlice `yaml:"output"`
}

type RuleRequest struct {
	Cache           bool              `yaml:"cache"`
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
}

type Infos struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Type       string `yaml:"type"`
	Confidence int    `yaml:"confidence"`
}

type HostInfo struct {
	Hostname string `yaml:"hostname"`
}

type Vulnerability struct {
	ID    string `yaml:"id"`
	Match string `yaml:"match"`
}

type FingerPrint struct {
	Infos    []Infos  `yaml:"infos"`
	HostInfo HostInfo `yaml:"host_info"`
}
type Detail struct {
	Author        string        `yaml:"author"`
	Links         []string      `yaml:"links"`
	FingerPrint   FingerPrint   `yaml:"fingerprint"`
	Vulnerability Vulnerability `yaml:"vulnerability"`
	Description   string        `yaml:"description"`
	Version       string        `yaml:"version"`
	Tags          string        `yaml:"tags"`
}

type SetMapSlice = yaml.MapSlice
type PayloadsMapSlice = yaml.MapSlice

type Payloads struct {
	Continue bool             `yaml:"continue,omitempty"`
	Payloads PayloadsMapSlice `yaml:"payloads"`
}

type Poc struct {
	Name       string          `yaml:"name"`
	Transport  string          `yaml:"transport"`
	Set        SetMapSlice     `yaml:"set"`
	Payloads   Payloads        `yaml:"payloads"`
	Rules      map[string]Rule `yaml:"rules"`
	Expression string          `yaml:"expression"`
	Detail     Detail          `yaml:"detail"`
}
