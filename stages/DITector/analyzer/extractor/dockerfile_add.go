package extractor

import "regexp"

var addFromURLRe = regexp.MustCompile(`ADD\s+.*(https?://\S+)`)

// CheckAddFromURL 检查Dockerfile ADD命令是否从远程服务器获取内容
func CheckAddFromURL(instruction string) bool {
	return addFromURLRe.MatchString(instruction)
}

// ExtractAddURLs 从ADD命令中提取全部URL
func ExtractAddURLs(cmd string) []string {
	return ExtractURLsFromString(cmd)
}
