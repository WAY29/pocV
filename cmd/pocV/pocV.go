package main

import (
	"os"
	"time"

	"github.com/WAY29/errors"
	cli "github.com/jawher/mow.cli"

	"github.com/WAY29/pocV/internal/common/check"
	. "github.com/WAY29/pocV/internal/common/load"
	"github.com/WAY29/pocV/internal/common/output"
	"github.com/WAY29/pocV/internal/common/tag"
	"github.com/WAY29/pocV/utils"

	common_structs "github.com/WAY29/pocV/pkg/common/structs"
	nuclei_parse "github.com/WAY29/pocV/pkg/nuclei/parse"
	xray_requests "github.com/WAY29/pocV/pkg/xray/requests"
	xray_structs "github.com/WAY29/pocV/pkg/xray/structs"
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

		// 初始化nuclei options
		nuclei_parse.InitExecuterOptions(100, 10)

		xrayPocMap, nucleiPocMap := LoadPocs(poc, pocPath)

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
		file        = cmd.StringOpt("file", "", "Result file to write")
		json        = cmd.BoolOpt("json", false, "Whether output is in JSON format or not, more information will be output")
		proxy       = cmd.StringOpt("proxy", "", "Http proxy")
		threads     = cmd.IntOpt("threads", 10, "Thread number")
		timeout     = cmd.IntOpt("timeout", 20, "Request timeout")
		rate        = cmd.IntOpt("rate", 100, "Request rate(per second)")
		debug       = cmd.BoolOpt("debug", false, "Debug this program")
		verbose     = cmd.BoolOpt("v verbose", false, "Print verbose messages")
	)
	// 定义用法
	cmd.Spec = "(-t=<target> | -T=<targetFile>)... (-p=<poc> | -P=<pocpath>)... [--tag=<poc.tag>]... [--file=<file> [--json]] [--proxy=<proxy>] [--threads=<threads>] [--timeout=<timeout>] [-k=<ceye.api.key> | --key=<ceye.api.key>]  [-d=<ceye.subdomain> | --domain=<ceye.subdomain>] [--debug] [-v | --verbose]"

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

		// 初始化nuclei options
		nuclei_parse.InitExecuterOptions(*rate, *timeout)

		// 加载目标
		targets := LoadTargets(target, targetFiles)

		// 加载poc
		xrayPocs, nucleiPocs := LoadPocs(poc, pocPath)
		// 过滤poc
		xrayPocs, nucleiPocs = FilterPocs(*tags, xrayPocs, nucleiPocs)
		// utils.DebugF("TODO REMOVE THIS: %#v %#v", xrayPocs, nucleiPocs)

		// 初始化输出
		outputChannel, outputWg := output.InitOutput(*file, *json)

		// 初始化check
		check.InitCheck(*threads, *rate, *verbose)

		// check开始
		check.Start(targets, xrayPocs, nucleiPocs, outputChannel)
		check.Wait()

		// check结束
		close(outputChannel)
		check.End()
		outputWg.Wait()

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
