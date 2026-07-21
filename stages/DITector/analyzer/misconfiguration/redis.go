package misconfiguration

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/ChimangoScan/DITector/myutils"
)

// redis.conf

var (
	redisConfFileRe    = regexp.MustCompile(`redis\.conf$`)
	redisRequirePassRe = regexp.MustCompile(`requirepass\s+\S+`)
)

func isRedisConfFile(filepath string) bool {
	return redisConfFileRe.MatchString(filepath)
}

func ScanRedisConfFile(filepath string) ([]*myutils.Misconfiguration, error) {
	res := make([]*myutils.Misconfiguration, 0)
	auth := false

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 未授权访问
	// requirepass + <password>
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过注释行
		if strings.HasPrefix(line, "#") {
			continue
		}
		if redisRequirePassRe.MatchString(line) {
			auth = true
			break
		}
	}

	if !auth {
		res = append(res, &myutils.Misconfiguration{
			Type:          myutils.IssueType.Misconfiguration,
			AppName:       AppRedis,
			MisConfType:   MisConfUnauthorization,
			Match:         fmt.Sprintf("no requirepass setted"),
			Description:   "improperly configured Redis authentication, allowing anonymous access",
			Severity:      "MEDIUM",
			SeverityScore: 5,
		})
	}

	return res, nil
}
