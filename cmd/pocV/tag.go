package main

import (
	. "github.com/WAY29/pocV/internal/common/load"
	"github.com/WAY29/pocV/internal/common/tag"
	nuclei_parse "github.com/WAY29/pocV/pkg/nuclei/parse"
	"github.com/WAY29/pocV/utils"

	cli "github.com/jawher/mow.cli"
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
