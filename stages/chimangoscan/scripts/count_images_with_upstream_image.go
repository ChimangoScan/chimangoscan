package scripts

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/ChimangoScan/chimangoscan/buildgraph"
	"github.com/ChimangoScan/chimangoscan/myutils"
)

type ImageWithUpstream struct {
	RepoNamespace  string   `json:"repository_namespace"`
	RepoName       string   `json:"repository_name"`
	TagName        string   `json:"tag_name"`
	ImageDigest    string   `json:"image_digest"`
	UpstreamCount  int      `json:"upstream_count"`
	UpstreamImages []string `json:"upstream_images"`
}

// CountNodeWithUpstreamImages 计算存在上游镜像的镜像节点数
// output: 写结果文件路径
func CountNodeWithUpstreamImages(output string, page int64, pageSize int, pullCountThreshold int64) error {
	outputF, err := os.OpenFile(output, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0744)
	if err != nil {
		log.Fatalln("open file", output, "failed with:", err)
	}
	defer outputF.Close()

	jobCh := make(chan buildgraph.GraphJob, runtime.NumCPU())
	chDone := make(chan struct{})

	go loadDataFromMongo(page, pageSize, pullCountThreshold, jobCh)
	go countNodesWithUpstreamImages(jobCh, outputF, chDone)
	<-chDone

	fmt.Println(myutils.GetLocalNowTimeStr(), "CalculateNodeRelyWeights finished")
	return nil
}

func countNodesWithUpstreamImages(ch chan buildgraph.GraphJob, file *os.File, chDone chan struct{}) {
	for job := range ch {
		tmp := ImageWithUpstream{
			RepoNamespace: job.RepoNamespace,
			RepoName:      job.RepoName,
			TagName:       job.TagName,
			ImageDigest:   job.ImageMeta.Digest,
		}

		upstreamImgNames, err := myutils.GlobalDBClient.Neo4j.FindUpstreamImagesByNodeId(myutils.CalculateImageNodeId(job.ImageMeta))
		if err != nil {
			myutils.Logger.Error("FindDownstreamImagesByNodeId for image:", job.RepoNamespace, job.RepoNamespace, job.TagName, job.ImageMeta.Digest,
				", nodeId:", myutils.CalculateImageNodeId(job.ImageMeta), ", failed with:", err.Error())
			continue
		}
		tmp.UpstreamCount = len(upstreamImgNames)
		tmp.UpstreamImages = upstreamImgNames

		b, err := json.Marshal(tmp)
		if err != nil {
			myutils.Logger.Error("json marshal failed with:", err.Error())
		}
		file.Write(b)
		file.WriteString("\n")
	}
	chDone <- struct{}{}
}
