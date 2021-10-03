package main

import (
	"fmt"
	"os"
	"time"

	xray_check "github.com/WAY29/pocV/internal/xray/check"
	common_structs "github.com/WAY29/pocV/pkg/common/structs"
	xray_requests "github.com/WAY29/pocV/pkg/xray/requests"
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

		tag = cmd.StringsArg("TAG", make([]string, 0), "poc tag")
	)

	cmd.Spec = "(-p=<poc> | -P=<pocpath>)...  TAG..."

	cmd.Action = func() {
		// TODO remove this
		fmt.Printf("TODO REMOVE: %#v %#v %#v\n", *poc, *pocPath, *tag)
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
		threads     = cmd.IntOpt("threads", 10, "Thread number")
		timeout     = cmd.IntOpt("timeout", 20, "Request timeout")
		rate        = cmd.IntOpt("rate", 100, "Request rate(per second)")
		proxy       = cmd.StringOpt("proxy", "", "http proxy")
		debug       = cmd.BoolOpt("debug", false, "debug this program")
		verbose     = cmd.BoolOpt("v verbose", false, "print verbose messages")
	)
	// 定义用法
	cmd.Spec = "(-t=<target> | -T=<targetFile>)... (-p=<poc> | -P=<pocpath>)... [--threads=<threads>] [--timeout=<timeout>] [--proxy=<proxy>] [-k=<ceye.api.key> | --key=<ceye.api.key>]  [-d=<ceye.subdomain> | --domain=<ceye.subdomain>] [--debug] [-v | --verbose]"

	cmd.Action = func() {
		if *debug {
			*verbose = true
		}
		// 初始化日志
		utils.InitLog(*debug, *verbose)

		// 初始化dnslog平台
		if !common_structs.InitCeyeApi(*apiKey, *domain) {
			utils.Warning("No ceye api")
		}

		// 初始化http客户端
		xray_requests.InitHttpClient(*threads, *proxy, time.Duration(*timeout)*time.Second)

		// 加载目标
		targets := utils.LoadTargets(target, targetFiles)

		// 加载poc
		xrayPocs, nucleiPocs := utils.LoadPocs(poc, pocPath)
		utils.DebugF("TODO REMOVE THIS: %#v", nucleiPocs)

		// 检查

		// 初始化check
		xray_check.InitCheck(*threads, *rate, *verbose)
		xray_check.Start(targets, xrayPocs)
		xray_check.Wait()
		xray_check.End()
	}
}

func main() {
	app = cli.App("pocV", "Powerful poc framework, adapted to Xray and Nuclei POC")
	app.Command("tag", "Add tag(s) for poc(s)", cmdTag)
	app.Command("run", "Run to test poc", cmdRun)

	app.Version("V version", "pocV 1.0.0")
	app.Spec = "[-V]"

	app.Run(os.Args)
}
