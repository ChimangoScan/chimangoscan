package extractor

import (
	"fmt"
	"testing"
)

func TestParseNpmInstallCmdArgs(t *testing.T) {
	ins := `npm install sax@0.1.1
	npm install sax
	npm install githubname/reponame
	npm install @myorg/privatepackage
	npm install sax@">=0.1.0 <0.2.0"
	npm install @myorg/privatepackage@"16 - 17"`

	fmt.Println(CheckNpmInstallCmd(ins))

	for _, cmd := range ExtractNpmInstallCmdsFromString(ins) {
		fmt.Println(cmd)
		fmt.Println(ParseNpmInstallCmdArgs(cmd))
	}
}
