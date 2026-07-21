package extractor

import (
	"fmt"
	"testing"
)

func TestExtractAddURL(t *testing.T) {
	ins := `ADD http://example.com/big.tar.xz /usr/src/things/`

	fmt.Println(CheckAddFromURL(ins))
	fmt.Println(ExtractWgetCmdURLs(ins))
}
