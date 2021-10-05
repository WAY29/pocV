package structs

import (
	"net/http"
	"strings"
	"time"

	xray_structs "github.com/WAY29/pocV/pkg/xray/structs"
)

var (
	CeyeApi                  string
	CeyeDomain               string
	ReversePlatformType      xray_structs.ReverseType
	DnslogCNGetDomainRequest *http.Request
	DnslogCNGetRecordRequest *http.Request
)

func InitReversePlatform(api, domain string, timeout time.Duration) {
	if api != "" && domain != "" && strings.HasSuffix(domain, ".ceye.io") {
		CeyeApi = api
		CeyeDomain = domain
		ReversePlatformType = xray_structs.ReverseType_Ceye
	} else {
		ReversePlatformType = xray_structs.ReverseType_DnslogCN

		// 设置请求相关参数
		DnslogCNGetDomainRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getdomain.php", nil)
		DnslogCNGetRecordRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getrecords.php", nil)

	}
}
