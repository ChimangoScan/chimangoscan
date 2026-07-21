package misconfiguration

import (
	"fmt"
	"regexp"

	"github.com/ChimangoScan/chimangoscan/myutils"
	"gopkg.in/ini.v1"
)

// 默认配置文件路径：
// 	etc/default.ini
//  etc/default.d/*.ini
//  etc/local.ini
//	etc/local.d/*.ini

var (
	couchConfFileRe = regexp.MustCompile(`(default|local)(\.d/\S+)?\.ini$`)
)

func isCouchConfFile(filepath string) bool {
	return couchConfFileRe.MatchString(filepath)
}

func ScanCouchConfFile(filepath string) ([]*myutils.Misconfiguration, error) {
	res := make([]*myutils.Misconfiguration, 0)
	auth := false

	config, err := ini.Load(filepath)
	if err != nil {
		return nil, err
	}

	// 未授权访问
	// [chttpd] require_valid_user = false
	requireValidUser, err := config.Section("chttpd").GetKey("require_valid_user")
	if err == nil {
		auth, _ = requireValidUser.Bool()
	} else {
		requireValidUser, err = config.Section("couch_httpd_auth").GetKey("require_valid_user")
		if err == nil {
			auth, _ = requireValidUser.Bool()
		}
	}
	if !auth {
		res = append(res, &myutils.Misconfiguration{
			Type:          myutils.IssueType.Misconfiguration,
			AppName:       AppCouchDB,
			MisConfType:   MisConfUnauthorization,
			Match:         fmt.Sprintf("chttpd.require_valid_user: %t", auth),
			Description:   "improperly configured CouchDB authentication, allowing anonymous access",
			Severity:      "MEDIUM",
			SeverityScore: 5,
		})
	}

	return res, nil
}
