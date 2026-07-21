package extractor

import "regexp"

var urlExtractor = regexp.MustCompile(`\s+(https?://\S*)`)

// ExtractURLsFromString 从传入的字符串中解析出全部http/https协议的url
func ExtractURLsFromString(s string) []string {
	res := make([]string, 0)

	for _, match := range urlExtractor.FindAllStringSubmatch(s, -1) {
		res = append(res, match[1])
	}

	return res
}
