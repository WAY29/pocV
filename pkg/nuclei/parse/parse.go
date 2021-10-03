package parse

import (
	"github.com/WAY29/pocV/pkg/nuclei/structs"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
)

func ParseYaml(filename string) (*structs.Poc, error) {
	return parsers.ParseTemplate(filename)
}
