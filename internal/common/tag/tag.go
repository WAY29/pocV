package tag

import (
	"strings"

	nuclei_structs "github.com/WAY29/pocV/pkg/nuclei/structs"
	xray_structs "github.com/WAY29/pocV/pkg/xray/structs"
	"github.com/WAY29/pocV/utils"
	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
)

func addTag(beforeTag string, tag string) string {
	if beforeTag == "" {
		return tag
	}
	return beforeTag + ", " + tag
}

func removeTag(beforeTag string, tag string) string {
	if beforeTag == tag {
		return ""
	} else {
		beforeTag = strings.TrimSpace(strings.ReplaceAll(beforeTag, ", "+tag, ""))
		beforeTag = strings.TrimSpace(strings.ReplaceAll(beforeTag, ","+tag, ""))
		beforeTag = strings.TrimSpace(strings.ReplaceAll(beforeTag, tag, ""))
		return beforeTag

	}
}

func AddTags(tags []string, xrayPocMap map[string]xray_structs.Poc, nucleiPocMap map[string]nuclei_structs.Poc) {
	for _, tag := range tags {
		for pocPath, poc := range xrayPocMap {
			pocTags := poc.Detail.Tags
			if !strings.Contains(pocTags, tag) {
				poc.Detail.Tags = addTag(pocTags, tag)
				out, err := yaml.Marshal(poc)
				if err != nil {
					utils.CliError("Can't Marshal poc: "+poc.Name, 7)
				}
				err = utils.WriteFile(pocPath, out)
				if err != nil {
					utils.CliError("Can't write file: "+pocPath, 8)
				}
			}
		}
		for pocPath, poc := range nucleiPocMap {
			pocTags := poc.Info.Tags.String()
			if !strings.Contains(pocTags, tag) {
				poc.Info.Tags = stringslice.StringSlice{
					Value: addTag(pocTags, tag),
				}
				out, err := yaml.Marshal(poc)
				if err != nil {
					utils.CliError("Can't Marshal poc: "+poc.ID, 7)
				}
				err = utils.WriteFile(pocPath, out)
				if err != nil {
					utils.CliError("Can't write file: "+pocPath, 8)
				}
			}
		}
	}

}

func RemoveTags(tags []string, xrayPocMap map[string]xray_structs.Poc, nucleiPocMap map[string]nuclei_structs.Poc) {
	for _, tag := range tags {
		for pocPath, poc := range xrayPocMap {
			pocTags := poc.Detail.Tags
			if strings.Contains(pocTags, tag) {
				poc.Detail.Tags = removeTag(pocTags, tag)
				out, err := yaml.Marshal(poc)
				if err != nil {
					utils.CliError("Can't Marshal poc: "+poc.Name, 7)
				}
				err = utils.WriteFile(pocPath, out)
				if err != nil {
					utils.CliError("Can't write file: "+pocPath, 8)
				}
			}
		}
		for pocPath, poc := range nucleiPocMap {
			pocTags := poc.Info.Tags.String()
			if strings.Contains(pocTags, tag) {
				poc.Info.Tags = stringslice.StringSlice{
					Value: removeTag(pocTags, tag),
				}
				out, err := yaml.Marshal(poc)
				if err != nil {
					utils.CliError("Can't Marshal poc: "+poc.ID, 7)
				}
				err = utils.WriteFile(pocPath, out)
				if err != nil {
					utils.CliError("Can't write file: "+pocPath, 8)
				}
			}
		}
	}

}
