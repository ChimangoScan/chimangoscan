package analyzer

import (
	"fmt"
	"log"
	"testing"
)

func TestExtractInstalledContentsFromInstruction(t *testing.T) {
	instruction := `
	RUN pip install --no-cache-dir pymongo numpy>2.0, <3.1,==3.0 json
	RUN npm install sax@0.1.1 githubname/reponame @myorg/privatepackage
	RUN apt-get install -y wget && wget -O myfile.txt https://example.com/myfile.txt && ln -sf myfile.txt /exe
	ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://mirrors.edge.kernel.org/pub/linux/kernel/Historic/linux-0.01.tar.gz /
	`
	digest := `testdigest111`
	for _, i := range extractInstalledContentsFromInstruction(instruction, digest) {
		fmt.Println(*i)
	}
}

func TestAnalyzeImageMetadata(t *testing.T) {
	fmt.Println(AnalyzeImagePartialByName("benjamineugenewhite/safegraph-sieve-2:early"))
}

func TestAnalyzeImagePartialByName(t *testing.T) {
	// 隐私信息泄露
	//res, err := AnalyzeImagePartialByName("benjamineugenewhite/safegraph-sieve-2:early")
	// 敏感参数
	res, err := AnalyzeImagePartialByName("phenompeople/mongodb:latest")
	if err != nil {
		log.Fatalln("AnalyzeImagePartialByName", res.Name, "failed with:", err)
	}

	return
}

func TestScanSecretsInString(t *testing.T) {
	if DefaultAnalyzerE != nil {
		log.Fatalln(DefaultAnalyzerE)
	}

	secrets := ("-----BEGIN RSA PRIVATE KEYsk_test_000011112222333344445555")
	for _, secret := range secrets {
		fmt.Println(secret)
	}
}

func TestScanSensitiveParamInString(t *testing.T) {
	if DefaultAnalyzerE != nil {
		log.Fatalln(DefaultAnalyzerE)
	}

	secrets := DefaultAnalyzer.scanSensitiveParamInString("")
	for _, secret := range secrets {
		fmt.Println(secret)
	}
}
