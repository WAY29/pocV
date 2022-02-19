package parse

import (
	"os"

	"github.com/WAY29/errors"
	"github.com/WAY29/pocV/pkg/xray/structs"
	"gopkg.in/yaml.v2"
)

func ParsePoc(filename string) (*structs.Poc, error) {
	poc := &structs.Poc{}

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err != nil {
		return nil, err
	}

	err = yaml.NewDecoder(f).Decode(poc)

	if err != nil {
		return nil, err
	}
	if poc.Name == "" {
		return nil, errors.Newf("Xray poc[%s] name can't be nil", filename)
	}
	if poc.Transport != "http" && poc.Transport != "" {
		return nil, errors.Newf("Xray poc[%s] only support http poc", filename)
	}
	return poc, nil
}
