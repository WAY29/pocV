package utils

import (
	"path/filepath"
	"strings"

	nuclei_parse "github.com/WAY29/pocV/pkg/nuclei/parse"
	nuclei_structs "github.com/WAY29/pocV/pkg/nuclei/structs"
	xray_parse "github.com/WAY29/pocV/pkg/xray/parse"
	xray_structs "github.com/WAY29/pocV/pkg/xray/structs"

	"github.com/WAY29/pocV/utils"
)

// 读取目标
func LoadTargets(target *[]string, targetFiles *[]string) []string {
	targetsSlice := make([]string, 0)
	if len(*target) != 0 {
		targetsSlice = append(targetsSlice, *target...)
	}

	for _, targetFile := range *targetFiles {
		if utils.Exists(targetFile) && utils.IsFile(targetFile) {
			utils.DebugF("Load target file: %v", targetFile)

			lineSlice, err := utils.ReadFileAsLine(targetFile)
			if err != nil {
				utils.CliError("Read target file error: "+err.Error(), 2)
			}
			targetsSlice = append(targetsSlice, lineSlice...)
		} else {
			utils.WarningF("Target file not found: %v", targetFile)
		}
	}

	utils.InfoF("Load [%d] target(s)", len(targetsSlice))

	return targetsSlice
}

// 读取pocs
func LoadPocs(pocs *[]string, pocPaths *[]string) (map[string]xray_structs.Poc, map[string]nuclei_structs.Poc) {
	xrayPocMap := make(map[string]xray_structs.Poc)
	nucleiPocMap := make(map[string]nuclei_structs.Poc)

	// 加载poc函数
	LoadPoc := func(pocFile string) {
		if utils.Exists(pocFile) && utils.IsFile(pocFile) {
			pocPath, err := filepath.Abs(pocFile)
			if err != nil {
				utils.CliError("Get poc filepath error: "+pocFile, 4)
			}
			utils.DebugF("Load poc file: %v", pocFile)

			xrayPoc, err := xray_parse.ParsePoc(pocPath)
			if err == nil {
				xrayPocMap[pocPath] = *xrayPoc
				return
			}
			nucleiPoc, err := nuclei_parse.ParsePoc(pocPath)

			if err == nil {
				nucleiPocMap[pocPath] = *nucleiPoc
				return
			}

			if err != nil {
				utils.WarningF("Poc[%s] Parse error", pocFile)
			}

		} else {
			utils.WarningF("Poc file not found: '%v'", pocFile)
		}
	}

	for _, pocFile := range *pocs {
		LoadPoc(pocFile)
	}
	for _, pocPath := range *pocPaths {
		utils.DebugF("Load from poc path: %v", pocPath)

		pocFiles, err := filepath.Glob(pocPath)
		if err != nil {
			utils.CliError("Path glob match error: "+err.Error(), 6)
		}
		for _, pocFile := range pocFiles {
			// 只解析yml或yaml文件
			if strings.HasSuffix(pocFile, ".yml") || strings.HasSuffix(pocFile, ".yaml") {
				LoadPoc(pocFile)
			}
		}

	}

	utils.InfoF("Load [%d] xray poc(s), [%d] nuclei poc(s)", len(xrayPocMap), len(nucleiPocMap))

	return xrayPocMap, nucleiPocMap
}

func FilterPocs(tags []string, xrayPocMap map[string]xray_structs.Poc, nucleiPocMap map[string]nuclei_structs.Poc) (map[string]xray_structs.Poc, map[string]nuclei_structs.Poc) {

	for k, poc := range xrayPocMap {
		for _, tag := range tags {
			if !strings.Contains(poc.Detail.Tags, tag) {
				delete(xrayPocMap, k)
				break
			}
		}
	}

	// nuclei tag 不区分大小写
	for k, poc := range nucleiPocMap {
		for _, tag := range tags {
			if !strings.Contains(poc.Info.Tags.String(), strings.ToLower(tag)) {
				delete(nucleiPocMap, k)
				break
			}
		}
	}

	return xrayPocMap, nucleiPocMap
}
