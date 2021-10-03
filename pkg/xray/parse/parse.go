package parse

import (
	"io/ioutil"

	"github.com/WAY29/pocV/pkg/xray/structs"
	"gopkg.in/yaml.v2"
)

func ParseYaml(filename string) (*structs.Poc, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	poc := structs.Poc{}

	err = yaml.Unmarshal(data, &poc)

	if err != nil {
		return nil, err
	}
	return &poc, nil
}
