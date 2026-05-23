package myutils

import (
	"fmt"
	"log"
	"testing"
)

func TestReqRepoMetadata(t *testing.T) {
	rMeta, err := ReqRepoMetadata("library", "mongo")
	if err != nil {
		log.Fatalln("request repository metadata failed with:", err)
	}
	fmt.Println(rMeta.Namespace, rMeta.Name, rMeta.PullCount)
	fmt.Println(rMeta.FullDescription)
}

func TestReqTagMetadata(t *testing.T) {
	tMeta, err := ReqTagMetadata("library", "mongo", "latest")
	if err != nil {
		log.Fatalln("request tag metadata failed with:", err)
	}
	fmt.Println(tMeta.RepositoryNamespace, tMeta.RepositoryName, tMeta.Name, tMeta.LastUpdated)
	fmt.Println(len(tMeta.Images))
}

func TestReqImagesMetadata(t *testing.T) {
	isMeta, err := ReqImagesMetadata("library", "mongo", "latest")
	if err != nil {
		log.Fatalln("request images metadata failed with:", err)
	}
	fmt.Println(len(isMeta))
	fmt.Println(isMeta[0].Digest, isMeta[0].Architecture, isMeta[0].OS)
}
