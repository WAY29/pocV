package output

import (
	"os"

	"github.com/WAY29/pocV/internal/common/check"
	"github.com/WAY29/pocV/internal/common/errors"
	"github.com/WAY29/pocV/pkg/common/structs"
	"github.com/WAY29/pocV/utils"

	"github.com/remeh/sizedwaitgroup"
)

func InitOutput(file string, jsonFlag bool) (chan structs.Result, *sizedwaitgroup.SizedWaitGroup) {

	outputChannel := make(chan structs.Result)
	outputs := make([]structs.Output, 0)
	outputWg := sizedwaitgroup.New(1)
	outputWg.Add()

	// inject StrandardOutput
	outputs = append(outputs, &structs.StandardOutput{})

	// inject FileOutput
	if file != "" {
		var err error
		var f *os.File

		if file != "" {
			f, err = os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				wrappedErr := errors.Newf(errors.FileError, "Can't create file '%s': %#v", file, err)
				utils.ErrorP(wrappedErr)
			} else {
				outputs = append(outputs, &structs.FileOutput{F: f, Json: jsonFlag})

			}
		}

	}

	go func() {
		defer outputWg.Done()

		for result := range outputChannel {
			for _, output := range outputs {
				output.Write(result)
			}

			check.PutPocResult(&result)
		}
	}()

	return outputChannel, &outputWg
}
