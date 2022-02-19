package structs

import (
	"os"

	"github.com/WAY29/pocV/internal/common/errors"
	"github.com/WAY29/pocV/utils"
)

type Output interface {
	Write(result Result)
}

// StandardOutput
type StandardOutput struct{}

func (o *StandardOutput) Write(result Result) {
	if result.SUCCESS() {
		utils.Success(result.STR())
	} else {
		utils.Failure(result.STR())
	}
}

// FileOutput
type FileOutput struct {
	F    *os.File
	Json bool
}

func (o *FileOutput) Write(result Result) {
	var row string
	if o.Json {
		row = result.JSON()
	} else {
		row = result.STR()
		if result.SUCCESS() {
			row = "[+] " + row
		} else {
			row = "[-] " + row
		}
	}

	_, err := o.F.WriteString(row + "\n")
	if err != nil {
		wrappedErr := errors.Newf(errors.ConvertInterfaceError, "Can't write file '%s': %#v", o.F.Name(), err)
		utils.ErrorP(wrappedErr)
	}

}
