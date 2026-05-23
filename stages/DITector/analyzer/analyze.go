package analyzer

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/anonymous/DITector/myutils"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

var DefaultAnalyzer *ImageAnalyzer
var DefaultAnalyzerE error
var GlobalDockerClient, _ = client.NewClientWithOpts(client.FromEnv)

// AnalyzeImagePartialByName analyzes image partially, currently only metadata.
func AnalyzeImagePartialByName(name string) (*myutils.ImageResult, error) {
	if DefaultAnalyzerE != nil {
		return nil, fmt.Errorf("create ImageAnalyzer failed with: %s", DefaultAnalyzerE)
	}

	return DefaultAnalyzer.AnalyzeImagePartialByName(name)
}

// AnalyzeImageByName analyzes image totally, including metadata, configuration, content of the image.
func AnalyzeImageByName(name string, delFlag bool) (*myutils.ImageResult, error) {
	if DefaultAnalyzerE != nil {
		return nil, fmt.Errorf("create ImageAnalyzer failed with: %s", DefaultAnalyzerE)
	}

	return DefaultAnalyzer.AnalyzeImageByName(name, delFlag)
}

// AnalyzeImageVulByName analyzes image only to detect CVE vulnerabilities.
func AnalyzeImageVulByName(name string, delFlag bool) (*myutils.ImageResult, error) {
	if DefaultAnalyzerE != nil {
		return nil, fmt.Errorf("create ImageAnalyzer failed with: %s", DefaultAnalyzerE)
	}

	return DefaultAnalyzer.AnalyzeImageVulByName(name, delFlag)
}

// AnalyzeImagePartialByName analyzes image partially by name, including only the metadata.
//
// This will never pull the layers of the image to local env.
func (analyzer *ImageAnalyzer) AnalyzeImagePartialByName(name string) (*myutils.ImageResult, error) {
	beginTime := time.Now()
	beginTimeStr := myutils.GetLocalNowTimeStr()

	// 创建新镜像信息
	ci, err := NewCurrentImage(name)
	if err != nil {
		myutils.Logger.Error("create CurrentImage for image", name, "failed with:", err.Error())
		return nil, err
	}

	// 数据库已有检测结果，跳过下载和检测
	if myutils.GlobalDBClient.MongoFlag {
		if res, err := myutils.GlobalDBClient.Mongo.FindImgResultByName(ci.namespace, ci.repoName, ci.tagName, ci.digest); err == nil {
			myutils.Logger.Info("AnalyzeImagePartial", name, "succeeded")
			return res, nil
		}
	}

	// 仅解析镜像元数据
	// ci.ParsePartial中包含WaitGroup Add，后续的return都需要Wait
	if err = ci.ParsePartial(); err != nil {
		myutils.Logger.Error("parse image partially (only metadata) for image", name, "failed with:", err.Error())
		ci.wg.Wait()
		return nil, err
	}

	// 分析镜像
	analyzeBeginTime := time.Now()
	// 查找数据库中是否已有digest对应的镜像结果
	if myutils.GlobalDBClient.MongoFlag {

		// 检查是否有digest相同的镜像结果(完整更好)
		if imgRes, err := myutils.GlobalDBClient.Mongo.FindImgResultByDigest(ci.digest); err == nil {
			imgRes.Name = name
			imgRes.Registry = ci.registry
			imgRes.Namespace = ci.namespace
			imgRes.RepoName = ci.repoName
			imgRes.TagName = ci.tagName

			// 有digest相同的也需要补充分析针对当前repo的描述信息分析
			repoMetaRes, err := analyzer.analyzeRepoMetadata(ci)
			if err != nil {
				imgRes.MetadataResult.SensitiveParams = make([]*myutils.SensitiveParam, 0)
				myutils.Logger.Error("ImageAnalyzer.AnalyzeImageByName analyze repo metadata failed with", err.Error())
			} else {
				imgRes.MetadataResult.SensitiveParams = repoMetaRes.SensitiveParams
			}

			imgRes.TotalTime = time.Since(beginTime).String()
			imgRes.AnalyzeTime = time.Since(analyzeBeginTime).String()

			ci.wg.Add(1)
			go func(imgRes *myutils.ImageResult) {
				defer ci.wg.Done()
				if e := myutils.GlobalDBClient.Mongo.UpdateImgResult(imgRes); e != nil {
					myutils.Logger.Error("update ImageResult", imgRes.Name, imgRes.Digest, "failed with:", e.Error())
				}
			}(imgRes)

			ci.wg.Wait()
			myutils.Logger.Info("AnalyzeImagePartial", name, "succeeded: image with same digest previously analyzed")
			return imgRes, nil
		}
	}

	// 创建结果对象
	res := CurrentImageToImageResult(ci)
	res.LastAnalyzed = beginTimeStr

	// 分析镜像元数据
	metaIs, err := analyzer.analyzeMetadata(ci)
	if err != nil {
		ci.wg.Wait()
		return nil, err
	}
	res.MetadataAnalyzed = true
	res.MetadataResult = metaIs

	// 收尾赋值工作
	res.TotalTime = time.Since(beginTime).String()
	res.AnalyzeTime = time.Since(analyzeBeginTime).String()

	if myutils.GlobalDBClient.MongoFlag {
		ci.wg.Add(1)
		go func(imgRes *myutils.ImageResult) {
			defer ci.wg.Done()
			if e := myutils.GlobalDBClient.Mongo.UpdateImgResult(imgRes); e != nil {
				myutils.Logger.Error("update ImageResult", imgRes.Name, imgRes.Digest, "failed with:", e.Error())
			}
		}(res)
	}

	ci.wg.Wait()
	myutils.Logger.Info("AnalyzeImagePartial", name, "succeeded")
	return res, nil
}

// AnalyzeImageByName analyzes image totally by name, including analyzing metadata,
// configuration, content of the image.
//
// Image needs to be stored in the local Docker environment.
func (analyzer *ImageAnalyzer) AnalyzeImageByName(name string, delFlag bool) (*myutils.ImageResult, error) {
	beginTime := time.Now()
	beginTimeStr := myutils.GetLocalNowTimeStr()

	// 创建新镜像信息
	ci, err := NewCurrentImage(name)
	if err != nil {
		myutils.Logger.Error("create CurrentImage for image", name, "failed with:", err.Error())
		return nil, err
	}

	// 数据库已有检测结果，跳过下载和检测
	if myutils.GlobalDBClient.MongoFlag {
		// TODO: 添加检查命令行工具覆盖位标识 --cover
		// 区分是否指定了镜像digest
		if ci.digest != "" {
			if res, err := myutils.GlobalDBClient.Mongo.FindImgResultByExactName(ci.namespace, ci.repoName, ci.tagName, ci.digest); err == nil && res.ConfigurationAnalyzed && res.ContentAnalyzed {
				myutils.Logger.Info("AnalyzeImage", name, "succeeded: previously analyzed")
				return res, nil
			} else {
				tmpBeginTime := time.Now()
				if res, err := myutils.GlobalDBClient.Mongo.FindImgResultByDigest(ci.digest); err == nil && res.ConfigurationAnalyzed && res.ContentAnalyzed {
					// 只有digest对应的镜像有结果
					// 只需要补充获取和分析repo和tag的metadata
					res.Name = name
					res.Registry = ci.registry
					res.Namespace = ci.namespace
					res.RepoName = ci.repoName
					res.TagName = ci.tagName

					// 获取和分析repo和tag的metadata
					if err := ci.parseMetadata(false, false); err != nil {
						myutils.Logger.Error("ImageAnalyzer.AnalyzeImageByName parse metadata of repo and tag failed with", err.Error())
					} else {
						repoMetaRes, err := analyzer.analyzeRepoMetadata(ci)
						if err != nil {
							res.MetadataResult.SensitiveParams = make([]*myutils.SensitiveParam, 0)
							myutils.Logger.Error("ImageAnalyzer.AnalyzeImageByName analyze repo metadata failed with", err.Error())
						} else {
							res.MetadataResult.SensitiveParams = repoMetaRes.SensitiveParams
						}
					}

					res.TotalTime = time.Since(beginTime).String()
					res.AnalyzeTime = time.Since(tmpBeginTime).String()

					ci.wg.Add(1)
					go func(imgRes *myutils.ImageResult) {
						defer ci.wg.Done()
						if e := myutils.GlobalDBClient.Mongo.UpdateImgResult(imgRes); e != nil {
							myutils.Logger.Error("update ImageResult", imgRes.Name, imgRes.Digest, "failed with:", e.Error())
						}
					}(res)
					ci.wg.Wait()

					myutils.Logger.Info("AnalyzeImage", name, "succeeded: image with same digest previously analyzed")
					return res, nil
				}
			}
		} else {
			if res, err := myutils.GlobalDBClient.Mongo.FindImgResultByName(ci.namespace, ci.repoName, ci.tagName, ci.digest); err == nil && res.ConfigurationAnalyzed && res.ContentAnalyzed {
				myutils.Logger.Info("AnalyzeImage", name, "succeeded: repo:tag previously analyzed")
				return res, nil
			}
		}
	}

	// 下载并解析镜像信息
	// ci.ParseFromFile中涉及WaitGroup Add，后续返回前需要Wait
	if err = ci.ParseFromFile(); err != nil {
		myutils.Logger.Error("parse image", name, "failed with:", err.Error())
		ci.wg.Wait()
		return nil, err
	}

	// 查找数据库中是否已有digest对应的镜像结果
	analyzeBeginTime := time.Now()
	if myutils.GlobalDBClient.MongoFlag {

		// 检查是否有digest相同的完整镜像结果
		imgRes, err := myutils.GlobalDBClient.Mongo.FindImgResultByDigest(ci.digest)
		if err == nil {
			if imgRes.ConfigurationAnalyzed && imgRes.ContentAnalyzed {
				imgRes.Name = name
				imgRes.Registry = ci.registry
				imgRes.Namespace = ci.namespace
				imgRes.RepoName = ci.repoName
				imgRes.TagName = ci.tagName
				imgRes.Architecture = ci.architecture
				imgRes.Variant = ci.variant
				imgRes.OS = ci.os
				imgRes.OSVersion = ci.osVersion

				// 需要补充对repo描述信息的分析
				repoMetaRes, err := analyzer.analyzeRepoMetadata(ci)
				if err != nil {
					imgRes.MetadataResult.SensitiveParams = make([]*myutils.SensitiveParam, 0)
					myutils.Logger.Error("ImageAnalyzer.AnalyzeImageByName analyze repo metadata failed with", err.Error())
				} else {
					imgRes.MetadataResult.SensitiveParams = repoMetaRes.SensitiveParams
				}

				imgRes.TotalTime = time.Since(beginTime).String()
				imgRes.AnalyzeTime = time.Since(analyzeBeginTime).String()

				ci.wg.Add(1)
				go func(imgRes *myutils.ImageResult) {
					defer ci.wg.Done()
					if e := myutils.GlobalDBClient.Mongo.UpdateImgResult(imgRes); e != nil {
						myutils.Logger.Error("update ImageResult", imgRes.Name, imgRes.Digest, "failed with:", e.Error())
					}
				}(imgRes)
				ci.wg.Wait()
				myutils.Logger.Info("AnalyzeImage", name, "succeeded: image with same digest previously analyzed")
				return imgRes, nil
			}
		}
	}

	// 数据库中没有结果，创建结果对象
	res := CurrentImageToImageResult(ci)
	res.LastAnalyzed = beginTimeStr

	// 分析镜像
	// 分析镜像元数据
	metaIs, err := analyzer.analyzeMetadata(ci)
	if err != nil {
		ci.wg.Wait()
		return nil, err
	}
	res.MetadataAnalyzed = true
	res.MetadataResult = metaIs

	// 分析镜像配置信息
	configIs, err := analyzer.analyzeConfiguration(ci)
	if err != nil {
		ci.wg.Wait()
		return nil, err
	}
	res.ConfigurationAnalyzed = true
	res.ConfigurationResult = configIs

	// 分析镜像内容信息
	contentIs, err := analyzer.analyzeContent(ci, res)
	if err != nil {
		ci.wg.Wait()
		return nil, err
	}
	res.ContentAnalyzed = true
	res.ContentResult = contentIs

	// 收尾赋值工作
	res.TotalTime = time.Since(beginTime).String()
	res.AnalyzeTime = time.Since(analyzeBeginTime).String()

	if myutils.GlobalDBClient.MongoFlag {
		go func(imgRes *myutils.ImageResult) {
			if e := myutils.GlobalDBClient.Mongo.UpdateImgResult(imgRes); e != nil {
				myutils.Logger.Error("update ImageResult", imgRes.Name, imgRes.Digest, "failed with:", e.Error())
			}
		}(res)
	}

	// 结束时删除一切解压内容
	//ci.wg.Add(1)
	go func(dir string) {
		//defer ci.wg.Done()
		e := os.RemoveAll(dir)
		if e != nil {
			myutils.Logger.Error("remove all from dir", dir, "failed with:", e.Error())
		}
	}(ci.imgFilepath)

	//ci.wg.Add(1)
	go func(tarFilepath string) {
		//defer ci.wg.Done()
		e := os.RemoveAll(tarFilepath)
		if e != nil {
			myutils.Logger.Error("remove all from file", tarFilepath, "failed with:", e.Error())
		}
	}(ci.imgTarFile)

	if delFlag {
		//ci.wg.Add(1)
		go func(name string) {
			//defer ci.wg.Done()
			_, e := GlobalDockerClient.ImageRemove(context.TODO(), name, types.ImageRemoveOptions{})
			if e != nil {
				myutils.Logger.Error("remove image", name, "from Docker failed with:", e.Error())
			}
		}(name)
	}

	ci.wg.Wait()
	myutils.Logger.Info("AnalyzeImage", name, "succeeded")
	return res, nil
}

// AnalyzeImageVulByName 用于分析结果中不包含漏洞的镜像，并补充扫描到的漏洞信息
func (analyzer *ImageAnalyzer) AnalyzeImageVulByName(name string, delFlag bool) (*myutils.ImageResult, error) {
	beginTime := time.Now()
	beginTimeStr := myutils.GetLocalNowTimeStr()

	// 创建新镜像信息
	ci, err := NewCurrentImage(name)
	if err != nil {
		myutils.Logger.Error("create CurrentImage for image", name, "failed with:", err.Error())
		return nil, err
	}

	// 下载并解析镜像信息
	// ci.ParseFromFile中涉及WaitGroup Add，后续返回前需要Wait
	if err = ci.ParseFromFile(); err != nil {
		myutils.Logger.Error("parse image", name, "failed with:", err.Error())
		ci.wg.Wait()
		return nil, err
	}

	// 创建结果对象
	analyzeBeginTime := time.Now()
	res := CurrentImageToImageResult(ci)
	res.LastAnalyzed = beginTimeStr

	// 分析镜像内容信息
	contentIs, err := analyzer.analyzeContentVul(ci, res)
	if err != nil {
		ci.wg.Wait()
		return nil, err
	}
	res.ContentAnalyzed = true
	res.ContentResult = contentIs

	// 收尾赋值工作
	res.TotalTime = time.Since(beginTime).String()
	res.AnalyzeTime = time.Since(analyzeBeginTime).String()

	if myutils.GlobalDBClient.MongoFlag {
		go func(imgRes *myutils.ImageResult) {
			if e := myutils.GlobalDBClient.Mongo.UpdateImgResultVul(imgRes); e != nil {
				myutils.Logger.Error("update content_result.vulnerabilities of ImageResult", imgRes.Name, imgRes.Digest, "failed with:", e.Error())
			}
		}(res)
	}

	// 结束时删除一切解压内容
	//ci.wg.Add(1)
	go func(dir string) {
		//defer ci.wg.Done()
		e := os.RemoveAll(dir)
		if e != nil {
			myutils.Logger.Error("remove all from dir", dir, "failed with:", e.Error())
		}
	}(ci.imgFilepath)

	//ci.wg.Add(1)
	go func(tarFilepath string) {
		//defer ci.wg.Done()
		e := os.RemoveAll(tarFilepath)
		if e != nil {
			myutils.Logger.Error("remove all from file", tarFilepath, "failed with:", e.Error())
		}
	}(ci.imgTarFile)

	if delFlag {
		//ci.wg.Add(1)
		go func(name string) {
			//defer ci.wg.Done()
			_, e := GlobalDockerClient.ImageRemove(context.TODO(), name, types.ImageRemoveOptions{})
			if e != nil {
				myutils.Logger.Error("remove image", name, "from Docker failed with:", e.Error())
			}
		}(name)
	}

	ci.wg.Wait()
	myutils.Logger.Info("AnalyzeImageVulByName", name, "succeeded")
	return res, nil
}

func CurrentImageToImageResult(ci *CurrentImage) *myutils.ImageResult {
	ir := myutils.NewImageResult()

	ir.Name = ci.name
	ir.Registry = ci.registry
	ir.Namespace = ci.namespace
	ir.RepoName = ci.repoName
	ir.TagName = ci.tagName
	ir.Digest = ci.digest
	ir.Architecture = ci.architecture
	ir.Variant = ci.variant
	ir.OS = ci.os
	ir.OSVersion = ci.osVersion

	ir.Layers = make([]string, len(ci.layerWithContentList))
	copy(ir.Layers, ci.layerWithContentList)
	for _, digest := range ci.layerWithContentList {
		ir.LayerResults[digest] = &myutils.LayerResult{
			Instruction: ci.layerInfoMap[digest].instruction,
			Size:        ci.layerInfoMap[digest].size,
			Digest:      digest,
		}
	}

	return ir
}
