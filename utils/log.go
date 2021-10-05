package utils

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var (
	logger                 *logrus.Logger
	DebugFlag, VerboseFlag bool
)

func InitLog(debug, verbose bool) {
	logger = &logrus.Logger{
		Out:   os.Stdout,
		Level: logrus.ErrorLevel,
		Formatter: &prefixed.TextFormatter{
			ForceColors:     true,
			ForceFormatting: true,
			FullTimestamp:   true,
			TimestampFormat: "15:04",
		},
	}
	if debug == true {
		logger.SetLevel(logrus.DebugLevel)
	} else if verbose == true {
		logger.SetOutput(os.Stdout)
		logger.SetLevel(logrus.InfoLevel)
	}
	DebugFlag = debug
	VerboseFlag = verbose
}

// Info
func InfoF(format string, args ...interface{}) {
	logger.Info(fmt.Sprintf(format, args...))
}

func Info(args ...interface{}) {
	logger.Infoln(args)
}

// Error
func ErrorF(format string, args ...interface{}) {
	logger.Error(fmt.Sprintf(format, args...))
}

func Error(args ...interface{}) {
	logger.Errorln(args)
}

// PrintError
func ErrorP(err error) {
	// print stack trace if debug
	if DebugFlag {
		logger.Error(fmt.Sprintf("%+v", err))
	} else {
		logger.Error(fmt.Sprintf("%v", err))
	}
}

// Warning
func WarningF(format string, args ...interface{}) {
	logger.Warningf(fmt.Sprintf(format, args...))
}

func Warning(args ...interface{}) {
	logger.Warningln(args)
}

// Debug
func DebugF(format string, args ...interface{}) {
	logger.Debug(fmt.Sprintf(format, args...))
}

func Debug(args ...interface{}) {
	logger.Debugln(args)
}
