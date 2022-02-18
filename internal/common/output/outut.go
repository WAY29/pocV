package output

import (
	"os"

	"github.com/WAY29/pocV/internal/common/errors"
	"github.com/WAY29/pocV/pkg/common/structs"
	"github.com/WAY29/pocV/utils"

	"github.com/remeh/sizedwaitgroup"
)

func InitOutput(file string, jsonFlag bool) (chan structs.Result, *sizedwaitgroup.SizedWaitGroup) {
	outputChannel := make(chan structs.Result)
	outputWg := sizedwaitgroup.New(1)
	outputWg.Add()

	go func() {
		defer outputWg.Done()

		var err error
		var f *os.File

		if file != "" {
			f, err = os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				wrappedErr := errors.Newf(errors.ConvertInterfaceError, "Can't create file '%s': %#v", file, err)
				utils.ErrorP(wrappedErr)
			}
			defer f.Close()
		}
		for result := range outputChannel {
			var row string
			if jsonFlag {
				row = result.JSON()
			} else {
				row = result.STR()
			}

			if f != nil {
				_, _ = f.WriteString(row + "\n")
			}

			if result.SUCCESS() {
				utils.Success(result.STR())
			} else {
				utils.Failure(result.STR())
			}
		}
	}()

	return outputChannel, &outputWg
}
