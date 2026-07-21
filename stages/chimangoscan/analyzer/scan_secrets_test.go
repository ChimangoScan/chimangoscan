package analyzer

import (
	"fmt"
	"log"
	"testing"
)

func TestScanSecretsInFilepath(t *testing.T) {
	secrets, err := scanSecretsInFilepath("/data/tmp/secret-tests")
	if err != nil {
		log.Fatalln(err)
	}
	for _, secret := range secrets {
		fmt.Println(secret.TrufflehogResult.DetectorName, secret.TrufflehogResult.Raw)
	}
	return
}
