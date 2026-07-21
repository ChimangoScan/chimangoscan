package scripts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ChimangoScan/DITector/myutils"
)

// CountNodeWithUpstreamImages 计算存在上游镜像的镜像节点数
// output: 写结果文件路径
func CountNodeWithDownstreamImages(input string, output string, form string) error {
	inputF, err := os.Open(input)
	if err != nil {
		log.Fatalln("open file", input, "failed with:", err)
	}

	outputF, err := os.OpenFile(output, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0744)
	if err != nil {
		log.Fatalln("open file", output, "failed with:", err)
	}

	reader := bufio.NewReader(inputF)
	lineNum := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Fatalf("read file get err: %v", err)
		}

		lineNum++
		fmt.Println("line num:", lineNum)

		var imgInfo InputImage

		if form == "json" {
			if err = json.Unmarshal([]byte(line), &imgInfo); err != nil {
				myutils.Logger.Error("json unmarshal got err:", err.Error())
				continue
			}
		} else if form == "raw" {
			_, namespace, repoName, tagName, digest := myutils.DivideImageName(strings.TrimSpace(line))
			imgInfo.Namespace = namespace
			imgInfo.RepoName = repoName
			imgInfo.TagName = tagName
			imgInfo.Digest = digest
		}

		if err = countNodesWithDownstreamImages(&imgInfo, outputF); err != nil {
			myutils.Logger.Error("countNodesWithDownstreamImages for image", imgInfo.Namespace,
				imgInfo.RepoName, imgInfo.TagName, imgInfo.Digest, "fail get err", err.Error())
			continue
		}

		fmt.Println("finish line num:", lineNum)
	}

	fmt.Println(myutils.GetLocalNowTimeStr(), "CountNodeWithDownstreamImages finished")
	return nil
}

func countNodesWithDownstreamImages(imgInfo *InputImage, file *os.File) error {
	img, err := myutils.GlobalDBClient.Mongo.FindImageByDigest(imgInfo.Digest)
	if err != nil {
		myutils.Logger.Error("find image by digest", imgInfo.Digest, "fail get ret:", err.Error())
		return err
	}

	tmp := ImageWithDownstream{
		RepoNamespace:    imgInfo.Namespace,
		RepoName:         imgInfo.RepoName,
		TagName:          imgInfo.TagName,
		ImageDigest:      imgInfo.Digest,
		DownstreamCount:  0,
		DownstreamImages: []string{},
	}

	nodeId := myutils.CalculateImageNodeId(img)
	downImgNames, err := myutils.GlobalDBClient.Neo4j.FindDownstreamImagesByNodeId(nodeId)
	if err != nil {
		myutils.Logger.Error("FindDownstreamImagesByNodeId for image:", imgInfo.Digest,
			", nodeId:", nodeId, ", failed with:", err.Error())
	} else {
		tmp.DownstreamCount = len(downImgNames)
		tmp.DownstreamImages = downImgNames
	}

	b, err := json.Marshal(tmp)
	if err != nil {
		myutils.Logger.Error("json marshal failed with:", err.Error())
		return err
	}

	file.Write(b)
	file.WriteString("\n")

	return nil
}
