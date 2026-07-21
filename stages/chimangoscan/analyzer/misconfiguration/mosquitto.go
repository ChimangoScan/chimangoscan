package misconfiguration

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/ChimangoScan/chimangoscan/myutils"
)

var (
	mqttConfFileRe       = regexp.MustCompile(`mosquitto\.conf$`)
	mqttAllowAnonymousRe = regexp.MustCompile(`allow_anonymous\s+true`)
)

func isMQTTConfFile(filepath string) bool {
	return mqttConfFileRe.MatchString(filepath)
}

func ScanMQTTConfFile(filepath string) ([]*myutils.Misconfiguration, error) {
	res := make([]*myutils.Misconfiguration, 0)
	auth := true

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 未授权访问
	// allow_anonymous true
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过注释行
		if strings.HasPrefix(line, "#") {
			continue
		}
		if mqttAllowAnonymousRe.MatchString(line) {
			auth = false
			break
		}
	}

	if !auth {
		res = append(res, &myutils.Misconfiguration{
			Type:          myutils.IssueType.Misconfiguration,
			AppName:       AppMQTT,
			MisConfType:   MisConfUnauthorization,
			Match:         fmt.Sprintf("allow_anonymous true"),
			Description:   "improperly configured MQTT authentication, allowing anonymous access",
			Severity:      "MEDIUM",
			SeverityScore: 5,
		})
	}

	return res, nil
}
