package scripts

import (
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/ChimangoScan/DITector/analyzer"
	"github.com/ChimangoScan/DITector/myutils"
)

// AnalyzePullCountOverThreshold 分析pull_count > threshold时
func AnalyzePullCountOverThreshold(threshold int64, tagNum int, page int64) error {
	// 配置线程数
	//maxThreads := runtime.NumCPU()
	//if myutils.GlobalConfig.MaxThread > 0 && myutils.GlobalConfig.MaxThread < maxThreads {
	//	maxThreads = myutils.GlobalConfig.MaxThread
	//	runtime.GOMAXPROCS(maxThreads)
	//}
	myutils.Logger.Debug(fmt.Sprintf("analyze-threshold start with threads: %d", myutils.GlobalConfig.MaxThread))

	// 初始化控制并发线程数的管道
	jobCh := make(chan job)
	wg := sync.WaitGroup{}

	for w := 1; w <= myutils.GlobalConfig.MaxThread; w++ {
		wg.Add(1)
		go analyzeThresholdWorker(w, jobCh, &wg)
	}

	wg.Add(1)
	go jobGeneratorThreshold(threshold, tagNum, page, jobCh, &wg)

	wg.Wait()

	return nil
}

// jobGeneratorThreshold 从MongoDB读取repo数据，生成任务传入通道
func jobGeneratorThreshold(threshold int64, tagNum int, page int64, jobCh chan<- job, wg *sync.WaitGroup) {
	defer close(jobCh)
	defer wg.Done()
	if !myutils.GlobalDBClient.MongoFlag {
		log.Fatalln("jobGeneratorAll got error: MongoDB not online")
	}

	var repoCnt = 0
	var repoPage int64 = page
	var pageSize int64 = 5
	for {
		repoDocs, err := myutils.GlobalDBClient.Mongo.FindRepositoriesByPullCountPaged(threshold, repoPage, pageSize)
		if err != nil {
			myutils.Logger.Error(fmt.Sprintf("find repository in MongoDB pull_count > %d, page: %d, pagesize: %d, got error: %s", threshold, repoPage, pageSize, err))
			continue
		}
		// 进程结束标志
		if len(repoDocs) == 0 {
			break
		}

		// 根据tag生成任务
		for _, repoDoc := range repoDocs {
			repoCnt++

			// 从API获取最近更新的tag信息
			tagDocs, err := myutils.ReqTagsMetadata(repoDoc.Namespace, repoDoc.Name, 1, tagNum)
			if err != nil {
				myutils.Logger.Error(fmt.Sprintf("request tags for repository %s/%s from API got error: %s", repoDoc.Namespace, repoDoc.Name, err))
				continue
			}

			// 向数据库中备份一下
			for _, tagDoc := range tagDocs {
				wg.Add(1)
				go func(tagMetadata *myutils.Tag) {
					defer wg.Done()
					if e := myutils.GlobalDBClient.Mongo.UpdateTag(tagMetadata); e != nil {
						myutils.Logger.Error("update metadata of tag", tagMetadata.RepositoryNamespace, tagMetadata.RepositoryName, tagMetadata.Name, "failed with:", e.Error())
					}
				}(tagDoc)
			}

			// 检查时间顺序，顺序不对从API拿新的repo元数据
			if len(tagDocs) > 0 {
				tagLastUpdatedTime, _ := time.Parse(time.RFC3339Nano, tagDocs[0].LastUpdated)
				repoLastUpdatedTime, _ := time.Parse(time.RFC3339Nano, repoDoc.LastUpdated)
				if tagLastUpdatedTime.After(repoLastUpdatedTime) {
					repo, err := myutils.ReqRepoMetadata(repoDoc.Namespace, repoDoc.Name)
					if err != nil {
						myutils.Logger.Error(fmt.Sprintf("request metadata of repository %s/%s from API got error: %s", repoDoc.Namespace, repoDoc.Name, err))
					} else {
						if e := myutils.GlobalDBClient.Mongo.UpdateRepository(repo); e != nil {
							myutils.Logger.Error("update metadata of repo", repo.Namespace, repo.Name, "failed with:", e.Error())
						}
					}
				}
			}

			// 生产任务
			for _, tagDoc := range tagDocs {
				jobCh <- job{
					name:    fmt.Sprintf("%s/%s:%s", repoDoc.Namespace, repoDoc.Name, tagDoc.Name),
					partial: false,
				}
			}

			if repoCnt%10 == 0 {
				fmt.Println("generated threshold", threshold, "job for repo:", repoCnt, ", page:", repoPage)
			}
		}

		repoPage++
	}
}

func analyzeThresholdWorker(workerId int, jobCh <-chan job, wg *sync.WaitGroup) {
	defer wg.Done()
	for j := range jobCh {
		if j.partial {
			_, err := analyzer.AnalyzeImagePartialByName(j.name)
			if err != nil {
				myutils.Logger.Error("analyzeThresholdWorker", strconv.Itoa(workerId), "analyze partial image", j.name, "failed with:", err.Error())
			} else {
				myutils.Logger.Debug("analyzeThresholdWorker", strconv.Itoa(workerId), "analyze partial image", j.name, "succeeded")
			}
		} else {
			_, err := analyzer.AnalyzeImageByName(j.name, true)
			if err != nil {
				myutils.Logger.Error("analyzeThresholdWorker", strconv.Itoa(workerId), "analyze image", j.name, "failed with:", err.Error())
			} else {
				myutils.Logger.Debug("analyzeThresholdWorker", strconv.Itoa(workerId), "analyze image", j.name, "succeeded")
			}
		}
	}
}
