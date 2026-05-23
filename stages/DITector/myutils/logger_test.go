package myutils

import (
	"fmt"
	"testing"
)

func TestLogDockerCrawlerString(t *testing.T) {
	LoadConfigFromFile("../config.yaml", 1)
	Logger.Error("this is error")
	Logger.Warn("this is warn")
	Logger.Info("this is info")
	Logger.Debug("this is debug")
	Logger.changeFilepath("testFilepath.log")
	Logger.Info("this is a test")
	Logger.changeFilepath("testFilepath2.log")
	Logger.Error("this is a test")
}

func TestGetLocalNowTime(t *testing.T) {
	fmt.Println(GetLocalNowTimeStr())
}
