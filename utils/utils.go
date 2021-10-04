package utils

import (
	cli "github.com/jawher/mow.cli"
)

// 输出错误并退出
func CliError(message string, exitCode int) {
	Error("[-] " + message)
	cli.Exit(2)
}
