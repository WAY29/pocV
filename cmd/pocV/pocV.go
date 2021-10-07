package main

import (
	"os"
	"time"

	"github.com/WAY29/errors"
	"github.com/WAY29/pocV/internal/common/check"
	"github.com/WAY29/pocV/internal/common/tag"
	common_structs "github.com/WAY29/pocV/pkg/common/structs"
	xray_requests "github.com/WAY29/pocV/pkg/xray/requests"
	xray_structs "github.com/WAY29/pocV/pkg/xray/structs"
	"github.com/WAY29/pocV/utils"
	cli "github.com/jawher/mow.cli"
)

const (
	__version__ = "1.0.0"
)

var (
	app *cli.Cli
)

func cmdTag(cmd *cli.Cmd) {
	var (
		poc     = cmd.StringsOpt("p poc", make([]string, 0), "Poc file(s)")
		pocPath = cmd.StringsOpt("P pocpath", make([]string, 0), "Load poc from Path")
		tags    = cmd.StringsArg("TAG", make([]string, 0), "poc tag")
		remove  = cmd.BoolOpt("r rm", false, "Remove tag(s) instead of add")
		debug   = cmd.BoolOpt("debug", false, "debug this program")
		verbose = cmd.BoolOpt("v verbose", false, "print verbose messages")
	)

	cmd.Spec = "[--debug] [-v | --verbose] [-r] (-p=<poc> | -P=<pocpath>)...  TAG..."

	cmd.Action = func() {
		// 初始化日志
		utils.InitLog(*debug, *verbose)

		xrayPocMap, nucleiPocMap := utils.LoadPocs(poc, pocPath)

		if *remove {
			tag.RemoveTags(*tags, xrayPocMap, nucleiPocMap)
		} else {
			tag.AddTags(*tags, xrayPocMap, nucleiPocMap)
		}
	}
}

func cmdRun(cmd *cli.Cmd) {

	// 定义选项
	var (
		target      = cmd.StringsOpt("t target", make([]string, 0), "Target url(s)")
		targetFiles = cmd.StringsOpt("T targetfile", make([]string, 0), "Target url file(s)")
		poc         = cmd.StringsOpt("p poc", make([]string, 0), "Poc file(s)")
		pocPath     = cmd.StringsOpt("P pocpath", make([]string, 0), "Load poc from Path, support Glob grammer")
		apiKey      = cmd.StringOpt("k key", "", "ceye.io api key")
		domain      = cmd.StringOpt("d domain", "", "ceye.io subdomain")
		tags        = cmd.StringsOpt("tag", make([]string, 0), "filter poc by tag")
		threads     = cmd.IntOpt("threads", 10, "Thread number")
		timeout     = cmd.IntOpt("timeout", 20, "Request timeout")
		rate        = cmd.IntOpt("rate", 100, "Request rate(per second)")
		proxy       = cmd.StringOpt("proxy", "", "http proxy")
		debug       = cmd.BoolOpt("debug", false, "debug this program")
		verbose     = cmd.BoolOpt("v verbose", false, "print verbose messages")
	)
	// 定义用法
	cmd.Spec = "(-t=<target> | -T=<targetFile>)... (-p=<poc> | -P=<pocpath>)... [--tag=<poc.tag>]... [--threads=<threads>] [--timeout=<timeout>] [--proxy=<proxy>] [-k=<ceye.api.key> | --key=<ceye.api.key>]  [-d=<ceye.subdomain> | --domain=<ceye.subdomain>] [--debug] [-v | --verbose]"

	cmd.Action = func() {
		// 设置变量
		timeoutSecond := time.Duration(*timeout) * time.Second

		if *debug {
			*verbose = true
		}
		// 初始化日志
		utils.InitLog(*debug, *verbose)

		// 初始化dnslog平台
		common_structs.InitReversePlatform(*apiKey, *domain, timeoutSecond)
		if common_structs.ReversePlatformType != xray_structs.ReverseType_Ceye {
			utils.WarningF("No Ceye api, use dnslog.cn")
		}

		// 初始化http客户端
		xray_requests.InitHttpClient(*threads, *proxy, timeoutSecond)

		// 加载目标
		targets := utils.LoadTargets(target, targetFiles)

		// 加载poc
		xrayPocs, nucleiPocs := utils.LoadPocs(poc, pocPath)
		// 过滤poc
		xrayPocs, nucleiPocs = utils.FilterPocs(*tags, xrayPocs, nucleiPocs)
		utils.DebugF("TODO REMOVE THIS: %#v %#v", xrayPocs, nucleiPocs)

		// 检查

		// 初始化check
		check.InitCheck(*threads, *rate, *verbose)
		check.Start(targets, xrayPocs, nucleiPocs)
		check.Wait()
		check.End()
	}
}

func init() {
	errors.SetCurrentAbsPath()
	errors.SetSkipFrameNum(4)
}

func main() {
	app = cli.App("pocV", "Powerful poc framework, adapted to Xray and Nuclei POC")
	app.Command("tag", "Add tag(s) for poc(s)", cmdTag)
	app.Command("run", "Run to test poc", cmdRun)

	app.Version("V version", "pocV 1.0.0")
	app.Spec = "[-V]"

	app.Run(os.Args)
}
