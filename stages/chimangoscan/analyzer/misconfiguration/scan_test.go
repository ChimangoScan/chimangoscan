package misconfiguration

import (
	"fmt"
	"testing"
)

func TestFileNeedScan(t *testing.T) {
	fmt.Println(FileNeedScan("/etc/mongo/mongo.confa"))
}

func TestScanCouchConfFile(t *testing.T) {
	file := "tests/local.ini"
	fmt.Println(FileNeedScan(file))
	fmt.Println(ScanCouchConfFile(file))
}

func TestScanRedisConfFile(t *testing.T) {
	file := "tests/redis.conf"
	fmt.Println(FileNeedScan(file))
	fmt.Println(ScanRedisConfFile(file))
}

func TestScanESConfFile(t *testing.T) {
	file := "tests/elasticsearch.yml"
	fmt.Println(FileNeedScan(file))
	fmt.Println(ScanESConfFile(file))
}

func TestScanMQTTConfFile(t *testing.T) {
	file := "tests/mosquitto.conf"
	fmt.Println(FileNeedScan(file))
	fmt.Println(ScanMQTTConfFile(file))
}

func TestScanNginxConfFile(t *testing.T) {
	file := "tests/nginx.conf"
	fmt.Println(FileNeedScan(file))
	fmt.Println(ScanNginxConfFile(file))
}
