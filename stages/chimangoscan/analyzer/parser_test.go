package analyzer

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/ChimangoScan/chimangoscan/myutils"
)

func TestParseMetadataFromAPI(t *testing.T) {
	ci, err := NewCurrentImage("library/groovy:latest")
	if err != nil {
		log.Fatalln("create new current image got error:", err)
	}

	ci.parseServerPlatform()
	err = ci.parseMetadata(false, false)
	if err != nil {
		log.Fatalln("parse metadata got error:", err)
	}

	ci.metadata.imageMetadata, err = ci.getImageMetadata(false)
	if err != nil {
		log.Fatalln("get image metadata got error:", err)
	}

	ci.parseLayersWithContentFromMetadata()
	fmt.Println(len(ci.layerWithContentList))

	if err := ci.parseMetadata(true, true); err != nil {
		log.Fatalln("333333333333")
	}

	ci.parseLayersWithContentFromMetadata()
	fmt.Println(len(ci.layerWithContentList))

	nonNilLayerCnt := 0
	for _, layer := range ci.metadata.imageMetadata.Layers {
		if layer.Digest != "" {
			nonNilLayerCnt++
		}
	}
	fmt.Println(nonNilLayerCnt)
}

func TestPullSaveExtractImage(t *testing.T) {

	// ci, err := NewCurrentImage("library/groovy:latest")
	ci, err := NewCurrentImage("library/sonarqube:enterprise")
	if err != nil {
		log.Fatalln("create new current image got error:", err)
	}

	finish := make(chan downloadFinish)

	go ci.pullSaveExtractImage(myutils.GlobalConfig.TmpDir, finish)

	f := <-finish
	fmt.Println(f.imgTarPath)
	fmt.Println(f.imgDirPath)
	fmt.Println(f.err)

	fmt.Println(ci.manifest.Config)
	fmt.Println(ci.manifest.RepoTags)
	fmt.Println(ci.manifest.Layers)

	fmt.Println(ci.layerLocalFilepathList)
}

func TestParseFromFile(t *testing.T) {
	myutils.LoadConfigFromFile("../config.yaml", 1)
	//ci, err := NewCurrentImage("curlimages/curl:8.4.0")
	//ci, err := NewCurrentImage("thanhcongnhe/thanhcongnhe:latest")
	ci, err := NewCurrentImage("aiidalab/lab:arm64-aiida-2.4.0")
	if err != nil {
		log.Fatalln("create new current image got error:", err)
	}
	if err = ci.ParseFromFile(); err != nil {
		log.Fatalln(err)
	}

	fmt.Println("get current image:", ci)

	return
}

func TestParsePartial(t *testing.T) {
	myutils.LoadConfigFromFile("../config.yaml", 1)
	ci, err := NewCurrentImage("library/redis:alpine3.18")
	if err != nil {
		log.Fatalln("create new current image got error:", err)
	}
	if err = ci.ParsePartial(); err != nil {
		log.Fatalln("parse partial of image", ci.name, "failed with:", err)
	}

	fmt.Println("get CurrentImage:", ci)

	return
}

func TestExtractRecommendCmd(t *testing.T) {
	for _, s := range extractRecommendCmd("```\n> docker pull curlimages/curl:8.4.0\n```\n\n### run docker image\nCheck everything works properly by running:\n```\n> docker run --rm curlimages/curl:8.4.0 --version\n```\nHere is a more specific example of running curl docker container: \n```\n> docker run --rm curlimages/curl:8.4.0 -L -v https://curl.haxx.se \n```\nTo work with files it is best to mount directory:\n```\n>  docker run --rm -it \\\n-v \"$PWD:/work\" \\\ncurlimages/curl:8.4.0 \\\n-d@/work/test.txt https://httpbin.org/post\n```") {
		fmt.Println(s)
	}
}

func TestTimeZero(t *testing.T) {
	a, b, c := 1, 2, 3
	for i, x := range []*int{&a, &b, &c} {
		if i == 1 {
			tmp := 100
			x = &tmp
		}
		fmt.Println(*x)
	}
}

func TestParseTIme(t *testing.T) {
	repo, _ := time.Parse(time.RFC3339Nano, "2023-12-16T23:13:39.049818Z")
	fmt.Println(repo)
	tag, _ := time.Parse(time.RFC3339Nano, "2023-12-16T23:13:38.741329Z")
	fmt.Println(tag)
	img, _ := time.Parse(time.RFC3339Nano, "2023-12-16T23:12:54.506925Z")
	fmt.Println(img)
	sameTime, _ := time.Parse(time.RFC3339Nano, "2023-12-16T23:13:38.741329Z")
	fmt.Println(sameTime.After(tag))
}
