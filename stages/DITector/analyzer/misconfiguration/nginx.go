package misconfiguration

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/ChimangoScan/DITector/myutils"
)

const (
	NginxDirTraversalVul = "Nginx Directory traversal vulnerability"
)

var (
	nginxConfFileRe    = regexp.MustCompile(`nginx\.conf$`)
	nginxCurLocRe      = regexp.MustCompile(`location\s+(\S+)`)
	nginxAutoIndexOnRe = regexp.MustCompile(`autoindex\s+on`)
	nginxAliasRe       = regexp.MustCompile(`alias\s+(\S+)`)
)

func isNginxConfFile(filepath string) bool {
	return nginxConfFileRe.MatchString(filepath)
}

func ScanNginxConfFile(filepath string) ([]*myutils.Misconfiguration, error) {
	res := make([]*myutils.Misconfiguration, 0)
	dirClosure := false
	dirTraversal := false
	dirAlias := false

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 未授权访问
	// autoindex on
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过注释行
		if strings.HasPrefix(line, "#") {
			continue
		}
		// 获取当前目录
		location := nginxCurLocRe.FindStringSubmatch(line)
		if len(location) > 1 {
			curLoc := location[1]
			if len(curLoc) > 1 && strings.HasSuffix(curLoc, "/") {
				dirClosure = true
			} else {
				dirClosure = false
			}
		}
		if !dirAlias && nginxAliasRe.MatchString(line) {
			dirAlias = true
			break
		}
		if !dirClosure && nginxAutoIndexOnRe.MatchString(line) {
			dirTraversal = true
			break
		}
	}

	if dirTraversal {
		res = append(res, &myutils.Misconfiguration{
			Type:          myutils.IssueType.Misconfiguration,
			AppName:       AppNginx,
			MisConfType:   NginxDirTraversalVul,
			Match:         fmt.Sprintf("autoindex on"),
			Description:   "improperly configured Nginx authentication, allowing directory traversal",
			Severity:      "LOW",
			SeverityScore: 3,
		})
	}

	return res, nil
}
