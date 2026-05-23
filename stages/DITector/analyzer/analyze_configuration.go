package analyzer

import (
	"fmt"
	"strings"

	"github.com/anonymous/DITector/myutils"
)

func (analyzer *ImageAnalyzer) analyzeConfiguration(ci *CurrentImage) (*myutils.ConfigurationResult, error) {
	res := myutils.NewConfigurationResult()

	secrets, err := scanSecretsInFilepath(ci.manifest.Config)
	if err != nil {
		myutils.Logger.Error("scanSecretsInFilepath for image", ci.name, "manifest file", ci.manifest.Config, "failed with:", err.Error())
		return nil, err
	}
	for _, secret := range secrets {
		secret.Part = myutils.IssuePart.Configuration
		// 定位泄露的隐私位于哪个环境变量中
		for _, env := range ci.configuration.Config.Env {
			if strings.Contains(env, secret.Match) {
				secret.Path = fmt.Sprintf("Env[%s]", strings.Split(env, "=")[0])
				break
			}
		}
	}
	res.SecretLeakages = secrets

	return res, nil
}

// Deprecated
// 转为使用trufflehog扫描manifest文件

//func (analyzer *ImageAnalyzer) analyzeEnvConfig(ci *CurrentImage) []*myutils.SecretLeakage {
//	res := make([]*myutils.SecretLeakage, 0)
//
//	// 分析隐私泄露
//	// 扫描镜像环境变量
//	for _, env := range ci.configuration.Config.Env {
//		is := analyzer.scanSecretsInString(env)
//		for i, _ := range is {
//			is[i].Part = myutils.IssuePart.Configuration
//			is[i].Path = fmt.Sprintf("Env[%s]", strings.Split(env, "=")[0])
//		}
//
//		res = append(res, is...)
//	}
//
//	return res
//}
