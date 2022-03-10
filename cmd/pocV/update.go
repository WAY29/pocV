package main

import (
	"bufio"
	"os"
	"strings"

	"github.com/WAY29/pocV/internal/common/errors"

	"github.com/WAY29/pocV/utils"
	"github.com/blang/semver"
	cli "github.com/jawher/mow.cli"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

func cmdUpdate(cmd *cli.Cmd) {
	var (
		assumeYes = cmd.BoolOpt("y yes", false, "Automatic yes to prompts, this means automatically updating the latest version")
		debug     = cmd.BoolOpt("debug", false, "Debug this program")
		verbose   = cmd.BoolOpt("v verbose", false, "Print verbose messages")
	)

	cmd.Spec = "[-y | --yes] [--debug] [-v | --verbose]"

	cmd.Action = func() {
		var (
			input string = "y"
		)

		// 初始化日志
		utils.InitLog(*debug, *verbose)
		latest, found, err := selfupdate.DetectLatest("WAY29/pocV")
		if err != nil {
			wrappedErr := errors.Wrap(err, "Error occurred while detecting version")
			utils.ErrorP(wrappedErr)
			return
		}

		v := semver.MustParse(__version__)
		if !found || latest.Version.LTE(v) {
			utils.MessageF("Current pocV[%s] is the latest", __version__)
			return
		}

		if !*assumeYes {
			utils.QuestionF("Do you want to update pocV[%s -> %s] ? (Y/n): ", __version__, latest.Version)
			input, err := bufio.NewReader(os.Stdin).ReadString('\n')
			input = strings.ToLower(strings.TrimSpace(input))
			if err != nil || (input != "y" && input != "n" && input != "") {
				utils.Error("Invalid input")
				return
			}
		}

		if input == "n" {
			return
		}

		exe, err := os.Executable()
		if err != nil {
			wrappedErr := errors.Wrap(err, "Could not locate executable path")
			utils.ErrorP(wrappedErr)
			return
		}
		if err := selfupdate.UpdateTo(latest.AssetURL, exe); err != nil {
			wrappedErr := errors.Wrap(err, "Error occurred while updating binary")
			utils.ErrorP(wrappedErr)
			return
		}
		utils.SuccessF("Successfully updated to pocV[%s]", latest.Version)
	}
}
