package misconfiguration

import (
	"regexp"

	"github.com/anonymous/DITector/myutils"
)

const (
	AppMongo         = "MongoDB"
	AppCouchDB       = "CouchDB"
	AppRedis         = "Redis"
	AppNginx         = "Nginx"
	AppMySQL         = "MySQL"
	AppPostgreSQL    = "PostgreSQL"
	AppMQTT          = "Mosquitto"
	AppElasticsearch = "Elasticsearch"
)

const (
	MisConfUnauthorization = "Unauthorized access"
	MisConfGlobalBind      = "Global binding vulnerability"
)

var (
	bindAllIPRe = regexp.MustCompile("(0.0.0.0|::)")
)

func ScanFileMisconfiguration(filepath string, app string) ([]*myutils.Misconfiguration, error) {
	res := make([]*myutils.Misconfiguration, 0)

	switch app {
	case AppMongo:
		return ScanMongoConfFile(filepath)
	case AppCouchDB:
		return ScanCouchConfFile(filepath)
	case AppRedis:
		return ScanRedisConfFile(filepath)
	case AppNginx:
		return ScanNginxConfFile(filepath)
	case AppMQTT:
		return ScanMQTTConfFile(filepath)
	case AppElasticsearch:
		return ScanESConfFile(filepath)
	}

	return res, nil
}

// FileNeedScan 判断Linux文件系统下的文件是否需要检测
func FileNeedScan(filepath string) (bool, string) {

	if isMongoConfFile(filepath) {
		return true, AppMongo
	}
	if isCouchConfFile(filepath) {
		return true, AppCouchDB
	}
	if isRedisConfFile(filepath) {
		return true, AppRedis
	}
	if isNginxConfFile(filepath) {
		return true, AppNginx
	}
	if isMQTTConfFile(filepath) {
		return true, AppMQTT
	}
	if isESConfFile(filepath) {
		return true, AppElasticsearch
	}

	return false, ""
}
