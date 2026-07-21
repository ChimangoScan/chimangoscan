package analyzer

import (
	"fmt"
	"log"
	"testing"
)

func TestRules_LoadRulesFromYAMLFile(t *testing.T) {
	rs := ImageAnalyzerRules{}
	err := rs.loadSensitiveParamsFromYAMLFile("../rules/sensitive_param_rules.yaml")
	if err != nil {
		log.Fatalln(err)
	}

	return
}

func TestRules_CompileSecretsRegex(t *testing.T) {
	rs := ImageAnalyzerRules{}
	err := rs.loadSecretsFromYAMLFile("../secret_rules.yaml")
	if err != nil {
		log.Fatalln(err)
	}
	rs.compileSecretsRegex()
	fmt.Println(rs.SecretRules)
}
