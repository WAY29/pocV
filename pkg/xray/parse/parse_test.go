package parse

import (
	"reflect"
	"testing"

	"github.com/WAY29/pocV/pkg/xray/structs"
)

func TestRuleParse(t *testing.T) {
	expected_poc := &structs.Poc{
		Name: "poc-yaml-xray-rule-test-example-com",
		Rules: []structs.Rule{
			{
				Method:     "GET",
				Path:       "/",
				Expression: "response.status==200 && response.body.bcontains(b'Example Domain')\n",
			},
		},
		Detail: structs.Detail{
			Author: "test(http://example.com)",
			Links: []string{
				"http://example.com",
			},
			Tags: "test",
		},
	}
	poc, err := ParsePoc("../../../tests/xray/rule_test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected_poc, poc) {
		t.Errorf("\nexpected %#v\ngot %#v", expected_poc, poc)
	}
}

func TestGroupParse(t *testing.T) {
	expected_poc := &structs.Poc{
		Name: "poc-yaml-xray-group-test-example-com",
		Groups: map[string][]structs.Rule{
			"example1": {
				{
					Method:     "GET",
					Path:       "/",
					Expression: "response.status==200 && response.body.bcontains(b'Example Domain')\n",
				},
			},
			"example2": {
				{
					Method:     "GET",
					Path:       "/",
					Expression: "response.status==200 && response.body.bcontains(b'Example1 Domain')\n",
				},
			},
		},
		Detail: structs.Detail{
			Author: "test(http://example.com)",
			Links: []string{
				"http://example.com",
			},
			Tags: "test",
		},
	}
	poc, err := ParsePoc("../../../tests/xray/group_test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected_poc, poc) {
		t.Errorf("\nexpected %#v\ngot %#v", expected_poc, poc)
	}
}
