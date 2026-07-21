package scripts

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/ChimangoScan/chimangoscan/buildgraph"
	"github.com/ChimangoScan/chimangoscan/myutils"
	"go.mongodb.org/mongo-driver/bson"
)

// 用于统计镜像的依赖权重

type ImageWeight struct {
	RepoNamespace    string   `json:"repository_namespace"`
	RepoName         string   `json:"repository_name"`
	TagName          string   `json:"tag_name"`
	ImageDigest      string   `json:"image_digest"`
	Weights          int      `json:"weights"`
	DownstreamImages []string `json:"downstream_images"`
}

// CalculateNodeRelyWeights 计算每个镜像节点的依赖权重
// output: 写结果文件路径
func CalculateNodeRelyWeights(output string, page int64, pageSize int, pullCountThreshold int64) error {
	outputF, err := os.OpenFile(output, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0744)
	if err != nil {
		log.Fatalln("open file", output, "failed with:", err)
	}
	defer outputF.Close()

	jobCh := make(chan buildgraph.GraphJob, runtime.NumCPU())
	chDone := make(chan struct{})

	go loadDataFromMongo(page, pageSize, pullCountThreshold, jobCh)
	go calculate(jobCh, outputF, chDone)
	<-chDone

	fmt.Println(myutils.GetLocalNowTimeStr(), "CalculateNodeRelyWeights finished")
	return nil
}

// loadDataFromMongo 从mongo加载镜像信息
func loadDataFromMongo(page int64, pageSize int, pullCountThreshold int64, ch chan buildgraph.GraphJob) {
	defer close(ch)

	beginTime := time.Now()
	if !myutils.GlobalDBClient.MongoFlag {
		log.Fatalln("loadDataFromMongo got error: MongoDB not online")
	}

	// 逐页查找repo
	var repoCnt = 0
	var repoPage int64 = page
	var repoPageSize int64 = 5
	for {
		// // 根据build日志卡
		// if repoPage > 318206 {
		// 	fmt.Println(myutils.GetLocalNowTimeStr(), "finish: calculated all dependent weights for page:", repoPage-1, "page_size:", 5)
		// 	return
		// }

		// 先改成只统计library的
		// repoDocs, err := myutils.GlobalDBClient.Mongo.FindRepositoriesByKeywordPaged(map[string]any{"namespace": "library"}, repoPage, repoPageSize)
		// repoDocs, err := myutils.GlobalDBClient.Mongo.FindRepositoriesByKeywordPaged(nil, repoPage, repoPageSize)
		repoDocs, err := myutils.GlobalDBClient.Mongo.FindRepositoriesByKeywordPaged(map[string]any{"pull_count": bson.M{"$gte": 100}}, repoPage, repoPageSize)
		if err != nil {
			myutils.Logger.Error(fmt.Sprintf("find repository in MongoDB page: %d, pagesize: %d, got error: %s", repoPage, repoPageSize, err))
			repoPage++
			continue
		}
		// 进程结束标志，没有更多repo了
		if len(repoDocs) == 0 {
			fmt.Println(myutils.GetLocalNowTimeStr(), "all repo finished")
			break
		}

		// 遍历每个repo
		for _, repoDoc := range repoDocs {
			repoCnt++

			// 对repo逐页查找tag
			// 对library全部tag、下载量>1000000的repo的前100最近更新tag、其他的仓库的前20最近更新tag构建依赖图
			// 过滤掉windows系统的镜像
			var tagPage int64 = 1
			var tagDocs []*myutils.Tag

			if repoDoc.Namespace == "library" {
				// Official library images: fetch all tags for full coverage.
				tagDocs, err = myutils.GlobalDBClient.Mongo.FindAllTagsByRepoName(repoDoc.Namespace, repoDoc.Name)
				if err != nil {
					myutils.Logger.Error(fmt.Sprintf("find all tags for library/%s failed: %s", repoDoc.Name, err))
					continue
				}
			} else {
				// Community images: fetch the most-recently-updated pageSize tags.
				tagDocs, err = myutils.GlobalDBClient.Mongo.FindTagsByRepoNamePaged(repoDoc.Namespace, repoDoc.Name, tagPage, int64(pageSize))
				if err != nil {
					myutils.Logger.Error(fmt.Sprintf("find tags for %s/%s page %d size %d failed: %s", repoDoc.Namespace, repoDoc.Name, tagPage, pageSize, err))
					continue
				}
			}

			// 遍历repo的每个tag
			for _, tagDoc := range tagDocs {
				// 遍历tag的每个image信息
				for _, imgOfTag := range tagDoc.Images {
					imgDigest := imgOfTag.Digest
					// 尝试从数据库拿image元数据
					imgMeta, err := myutils.GlobalDBClient.Mongo.FindImageByDigest(imgDigest)
					// 数据库中没有，下一个
					if err != nil {
						myutils.Logger.Error("find image:", imgDigest, "of tag:", tagDoc.RepositoryNamespace, tagDoc.RepositoryName, tagDoc.Name, "failed with:", err.Error())
						continue
					} else {
						// 数据库中有，生成对应的任务
						ch <- buildgraph.GraphJob{
							Registry:      "docker.io",
							RepoNamespace: repoDoc.Namespace,
							RepoName:      repoDoc.Name,
							TagName:       tagDoc.Name,
							ImageMeta:     imgMeta,
						}
					}
				}
			}
		}

		fmt.Println(myutils.GetLocalNowTimeStr(), "generated all job for repo:", repoCnt, ", page:", repoPage, ", pageSize:", repoPageSize, "time used:", time.Since(beginTime))

		// repo翻页
		repoPage++
	}
}

// 暂时单线程处理任务
func calculate(ch chan buildgraph.GraphJob, file *os.File, chDone chan struct{}) {
	for job := range ch {
		tmp := ImageWeight{
			RepoNamespace: job.RepoNamespace,
			RepoName:      job.RepoName,
			TagName:       job.TagName,
			ImageDigest:   job.ImageMeta.Digest,
		}

		downstreamImgNames, err := myutils.GlobalDBClient.Neo4j.FindDownstreamImagesByNodeId(myutils.CalculateImageNodeId(job.ImageMeta))
		if err != nil {
			myutils.Logger.Error("FindDownstreamImagesByNodeId for image:", job.RepoNamespace, job.RepoNamespace, job.TagName, job.ImageMeta.Digest,
				", nodeId:", myutils.CalculateImageNodeId(job.ImageMeta), ", failed with:", err.Error())
			continue
		}
		tmp.Weights = len(downstreamImgNames)
		tmp.DownstreamImages = downstreamImgNames

		b, err := json.Marshal(tmp)
		if err != nil {
			myutils.Logger.Error("json marshal failed with:", err.Error())
			continue
		}
		if _, err := file.Write(b); err != nil {
			myutils.Logger.Error("write result failed:", err.Error())
			continue
		}
		file.WriteString("\n")
	}
	chDone <- struct{}{}
}
