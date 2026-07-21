package misconfiguration

import (
	"fmt"
	"os"
	"regexp"

	"github.com/ChimangoScan/DITector/myutils"
	"gopkg.in/yaml.v3"
)

var (
	esConfFileRe = regexp.MustCompile(`elasticsearch\.yml$`)
)

type ESConfig struct {
	SecEnabled           bool `yaml:"xpack.security.enabled"`
	SecAutoConfigEnabled bool `yaml:"xpack.security.autoconfiguration.enabled"`
}

func isESConfFile(filepath string) bool {
	return esConfFileRe.MatchString(filepath)
}

func ScanESConfFile(filepath string) ([]*myutils.Misconfiguration, error) {
	res := make([]*myutils.Misconfiguration, 0)

	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// yaml解析器不是完全复写，可以通过这种方式配置默认值
	config := &ESConfig{SecEnabled: true, SecAutoConfigEnabled: true}
	err = yaml.Unmarshal(content, config)

	// 未授权访问
	if !config.SecEnabled {
		res = append(res, &myutils.Misconfiguration{
			Type:          myutils.IssueType.Misconfiguration,
			AppName:       AppElasticsearch,
			MisConfType:   MisConfUnauthorization,
			Match:         fmt.Sprintf("xpack.security.enabled: %t", config.SecEnabled),
			Description:   "improperly configured Elasticsearch authentication, allowing anonymous access",
			Severity:      "MEDIUM",
			SeverityScore: 5,
		})
	}

	return res, nil
}
