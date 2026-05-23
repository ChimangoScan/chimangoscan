package misconfiguration

import (
	"fmt"
	"os"
	"regexp"

	"github.com/anonymous/DITector/myutils"
	"gopkg.in/yaml.v3"
)

var (
	mongoConfFileRe = regexp.MustCompile(`mongo(d|db)?\.conf$`)
)

type MongoConfig struct {
	Net      MongoNetConfig      `yaml:"net"`
	Security MongoSecurityConfig `yaml:"security"`
}

type MongoNetConfig struct {
	Port      int    `yaml:"port"`
	BindIP    string `yaml:"bindIp"`
	BindIPAll bool   `yaml:"bindIpAll"`
}

type MongoSecurityConfig struct {
	Authorization string `yaml:"authorization"`
}

func isMongoConfFile(filepath string) bool {
	return mongoConfFileRe.MatchString(filepath)
}

func ScanMongoConfFile(filepath string) ([]*myutils.Misconfiguration, error) {
	res := make([]*myutils.Misconfiguration, 0)
	unauth := true

	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	config := new(MongoConfig)
	err = yaml.Unmarshal(content, config)
	if err != nil {
		return nil, err
	}

	// 越权访问
	// 只有当security.authorization设置为enabled时，mongodb才关闭匿名访问权限
	if config.Security.Authorization == "enabled" {
		unauth = false
	} else {
		res = append(res, &myutils.Misconfiguration{
			Type:          myutils.IssueType.Misconfiguration,
			AppName:       AppMongo,
			MisConfType:   MisConfUnauthorization,
			Match:         fmt.Sprintf("security.authorization: %s", config.Security.Authorization),
			Description:   "improperly configured MongoDB authentication, allowing anonymous access",
			Severity:      "MEDIUM",
			SeverityScore: 5,
		})
	}

	// 网络配置不当，监听全部IP地址
	// net.BindIP="0.0.0.0"/"::"时监听全部IPv4/IPv6地址
	// 配置net.bindIpAll时同理
	if config.Net.BindIPAll || bindAllIPRe.MatchString(config.Net.BindIP) {
		desc := "improperly configured MongoDB net, listening to all IP addresses"
		severity := "MEDIUM"
		severityScore := 4
		if unauth {
			desc = "improperly configured MongoDB net, listening to all IP addresses with anonymous access allowed"
			severity = "CRITICAL"
			severityScore = 10
		}

		res = append(res, &myutils.Misconfiguration{
			Type:          myutils.IssueType.Misconfiguration,
			AppName:       AppMongo,
			MisConfType:   MisConfGlobalBind,
			Match:         fmt.Sprintf("net.bindIp: %s, net.bindIpAll: %t", config.Net.BindIP, config.Net.BindIPAll),
			Description:   desc,
			Severity:      severity,
			SeverityScore: float64(severityScore),
		})
	}

	return res, nil
}
