package extractor

import (
	"regexp"
)

var wgetRe = regexp.MustCompile(`(wget\s+(?:.|[\n\r])*?)(?:&&|$)`)

// CheckWgetCmd 检查命令字符串中是否存在完整的wget命令
func CheckWgetCmd(instruction string) bool {
	return wgetRe.MatchString(instruction)
}

// ExtractWgetCmds 从字符串中提取出全部wget命令
func ExtractWgetCmds(instruction string) []string {
	res := make([]string, 0)

	for _, match := range wgetRe.FindAllStringSubmatch(instruction, -1) {
		res = append(res, match[1])
	}

	return res
}

// ExtractWgetCmdURLs 从wget命令中提取出全部接触过的url路径
func ExtractWgetCmdURLs(cmd string) []string {
	return ExtractURLsFromString(cmd)
}
