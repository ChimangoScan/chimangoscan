package extractor

import (
	"regexp"
	"strings"
)

var npmInstallRe = regexp.MustCompile(`(npm\s+install\s+.*?)(?:&&|\n|$)`)
var npmInstallArgsRe = regexp.MustCompile(`^npm\s+install\s+(.*)`)

// 参考npm package spec链接：https://docs.npmjs.com/cli/v8/using-npm/package-spec
// var npmPackageSpecRe = regexp.MustCompile(`(?:\s+)(?:@[a-z0-9\-][a-z0-9\-._]*/)?[a-z0-9\-][a-z0-9\-._]*(?:@".*?"|@\S+)?`)

// CheckNpmInstallCmd 检查字符串中是否存在完整的npm install命令
func CheckNpmInstallCmd(instruction string) bool {
	return npmInstallRe.MatchString(instruction)
}

// ExtractNpmInstallCmdsFromString 从image layer instruction中提取出全部npm install完整命令
func ExtractNpmInstallCmdsFromString(instruction string) []string {
	res := make([]string, 0)
	for _, match := range npmInstallRe.FindAllStringSubmatch(instruction, -1) {
		res = append(res, match[1])
	}
	return res
}

// ParseNpmInstallCmdArgs 解析npm install命令中的所有参数。
// 因为npm install没有一个详尽的参数列表，且多少参数不需要有值传入，将所有-开头的参数都视作flag。
// 返回值中"_name" -> []string用于记录每个package的specifier。
func ParseNpmInstallCmdArgs(cmd string) map[string]any {
	cmds := npmInstallArgsRe.FindStringSubmatch(cmd)
	if len(cmds) <= 1 {
		return nil
	}
	cmd = cmds[1]

	args := make(map[string]interface{})
	args["_name"] = make(map[string][]string, 0)

	for _, arg := range strings.Split(cmd, " ") {
		// 以-开头的认为是参数，且都视为flag参数
		if strings.HasPrefix(arg, "-") {
			arg = strings.TrimLeft(arg, "-")
			if arg != "" {
				// 防止-name/--name将内容替换掉
				if arg == "_name" {
					continue
				}
				args[arg] = true
			}
		} else {
			// 其他的都视为package
			args["_name"].(map[string][]string)[arg] = make([]string, 0)
		}
	}

	return args
}
