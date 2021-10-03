package parse

import (
	"reflect"
	"testing"

	"github.com/WAY29/pocV/pkg/xray/structs"
)

func TestParse(t *testing.T) {
	expected_poc := &structs.Poc{
		Name: "poc-yaml-example-com",
		Rules: []structs.Rule{
			{
				Method:     "GET",
				Path:       "/",
				Expression: "response.status==200 && response.body.bcontains(b'Example Domain')\n",
			},
		},
		Detail: structs.Detail{
			Author: "name(link)",
			Links: []string{
				"http://example.com",
			},
			Tags: "test",
		},
	}
	poc, err := ParseYaml("../../../tests/xray_test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected_poc, poc) {
		t.Errorf("\nexpected %#v\ngot %#v", expected_poc, poc)
	}
}
