package analyzer

import (
	"github.com/anonymous/DITector/myutils"
)

type ImageAnalyzer struct {
	rules *ImageAnalyzerRules
}

// NewImageAnalyzerGlobalConfig creates a new ImageAnalyzer configured based on config.yaml
func NewImageAnalyzerGlobalConfig() (*ImageAnalyzer, error) {
	return NewImageAnalyzer(myutils.GlobalConfig.RulesConfig.SecretRulesFile,
		myutils.GlobalConfig.RulesConfig.SensitiveParamRulesFile)
}

// NewImageAnalyzer returns a configured ImageAnalyzer
//
// Parameters:
//
//	secretFile: file path containing rules for matching secrets
//	sensParamFile: file path containing rules for matching sensitive parameters
func NewImageAnalyzer(secretFile, sensParamFile string) (*ImageAnalyzer, error) {
	analyzer := new(ImageAnalyzer)
	var err error

	// 初始化成员变量
	analyzer.rules = newImageAnalyzerRules()

	// 配置隐私泄露规则
	//if err = analyzer.rules.loadSecretsFromYAMLFile(secretFile); err != nil {
	//	return nil, err
	//}
	//analyzer.rules.compileSecretsRegex()

	// 配置敏感参数规则
	if err = analyzer.rules.loadSensitiveParamsFromYAMLFile(sensParamFile); err != nil {
		return nil, err
	}
	analyzer.rules.compileSensitiveParamRegex()

	return analyzer, nil
}
