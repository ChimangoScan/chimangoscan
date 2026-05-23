package analyzer

import (
	"fmt"
	"regexp"

	"github.com/anonymous/DITector/myutils"
)

var (
	extRecommendCmdRE = regexp.MustCompile(`docker\s+run.*(?:\\[\n\r].+)*.`)
)

type ImageUpdatedAfterTagError struct {
	tagName string
}

func (e *ImageUpdatedAfterTagError) Error() string {
	return fmt.Sprintf("images of tag: %s may have updated after tag", e.tagName)
}

func isImageUpdatedAfterTagError(e error) bool {
	if _, ok := e.(*ImageUpdatedAfterTagError); ok {
		return true
	}
	return false
}

// parseMetadata loads metadata of repository
func (currI *CurrentImage) parseMetadata(partial, fromAPI bool) error {

	if err := currI.parseRepoMetadata(fromAPI); err != nil {
		return err
	}

	if err := currI.parseTagMetadata(fromAPI); err != nil {
		return err
	}

	if partial {
		if err := currI.parseImageMetadata(fromAPI); err != nil {
			if isImageUpdatedAfterTagError(err) {
				if e := currI.parseMetadata(partial, true); e != nil {
					return e
				}
			} else {
				return err
			}
		}
	}

	return nil
}

func (currI *CurrentImage) parseRepoMetadata(fromAPI bool) (err error) {
	if !currI.repoMetaFromAPI {
		if currI.metadata.repositoryMetadata, err = currI.getRepositoryMetadata(fromAPI); err != nil {
			myutils.Logger.Error("parse repository metadata of image", currI.name, "failed with:", err.Error())
			return err
		}
	}

	// 提取推荐容器启动命令
	currI.recommendedCmd = extractRecommendCmd(currI.metadata.repositoryMetadata.FullDescription)

	return nil
}

// getRepositoryMetadata gets repository metadata from local MongoDB,
// if repository not maintained in MongoDB or disconnected from MongoDB,
// try to get metadata from Docker Hub API and store metadata to MongoDB.
func (currI *CurrentImage) getRepositoryMetadata(fromAPI bool) (*myutils.Repository, error) {
	var rMeta *myutils.Repository
	var err error

	// 要求从API获取
	if fromAPI {
		rMeta, err = myutils.ReqRepoMetadata(currI.namespace, currI.repoName)
	} else {
		// 不要求从网络获取时先尝试从MongoDB获取
		if myutils.GlobalDBClient.MongoFlag {
			if rMeta, err = myutils.GlobalDBClient.Mongo.FindRepositoryByName(currI.namespace, currI.repoName); err == nil {
				return rMeta, nil
			}
		}
		// MongoDB返回err，从API获取
		rMeta, err = myutils.ReqRepoMetadata(currI.namespace, currI.repoName)
	}
	// 从API获取时err非空
	if err != nil {
		return nil, err
	}

	// API结果正常，存入数据库，存数据库过程的error不需要返回
	if myutils.GlobalDBClient.MongoFlag {
		currI.wg.Add(1)
		go func(repoMetadata *myutils.Repository) {
			defer currI.wg.Done()
			if e := myutils.GlobalDBClient.Mongo.UpdateRepository(repoMetadata); e != nil {
				myutils.Logger.Error("update metadata of repository", repoMetadata.Namespace, repoMetadata.Name, "failed with:", e.Error())
			}
		}(rMeta)
	}

	// 标记元数据来自API
	currI.repoMetaFromAPI = true

	return rMeta, nil
}

func (currI *CurrentImage) parseTagMetadata(fromAPI bool) (err error) {
	if !currI.tagMetaFromAPI {
		if currI.metadata.tagMetadata, err = currI.getTagMetadata(fromAPI); err != nil {
			myutils.Logger.Error("parse tag metadata of image", currI.name, "failed with:", err.Error())
			return err
		}
	}

	return nil
}

// getTagMetadata gets tag metadata from local MongoDB, if tag not maintained
// in MongoDB or disconnected from MongoDB, try to get metadata from Docker
// Hub API and store metadata to MongoDB.
func (currI *CurrentImage) getTagMetadata(fromAPI bool) (*myutils.Tag, error) {
	var tMeta *myutils.Tag
	var err error

	if fromAPI {
		tMeta, err = myutils.ReqTagMetadata(currI.namespace, currI.repoName, currI.tagName)
	} else {
		if myutils.GlobalDBClient.MongoFlag {
			if tMeta, err = myutils.GlobalDBClient.Mongo.FindTagByName(currI.namespace, currI.repoName, currI.tagName); err == nil {
				return tMeta, err
			}
		}
		tMeta, err = myutils.ReqTagMetadata(currI.namespace, currI.repoName, currI.tagName)
	}

	if err != nil {
		return nil, err
	}

	if myutils.GlobalDBClient.MongoFlag {
		currI.wg.Add(1)
		go func(tagMetadata *myutils.Tag) {
			defer currI.wg.Done()
			if e := myutils.GlobalDBClient.Mongo.UpdateTag(tagMetadata); e != nil {
				myutils.Logger.Error("update metadata of tag", tagMetadata.RepositoryNamespace, tagMetadata.RepositoryName, tagMetadata.Name, "failed with:", e.Error())
			}
		}(tMeta)
	}

	// 标记元数据来自API
	currI.tagMetaFromAPI = true

	return tMeta, nil
}

func (currI *CurrentImage) parseImageMetadata(fromAPI bool) (err error) {
	if !currI.imgMetaFromAPI {
		if currI.metadata.imageMetadata, err = currI.getImageMetadata(fromAPI); err != nil {
			myutils.Logger.Error("parse image metadata of image", currI.name, "failed with:", err.Error())
			return err
		}
	}

	return nil
}

// getImageMetadata gets image metadata from local MongoDB, if image not
// maintained in MongoDB or disconnected from MongoDB, try to get
// metadata from Docker Hub API and store metadata to MongoDB.
func (currI *CurrentImage) getImageMetadata(fromAPI bool) (*myutils.Image, error) {
	var iMeta *myutils.Image
	var err error
	var isMeta []*myutils.Image

	// 检查是否有architecture和os记录
	if currI.digest == "" && currI.architecture == "" && currI.os == "" {
		return nil, fmt.Errorf("no architecture or os parsed in current image")
	}

	archList := make([]string, 0)

	// 根据arch, os匹配tag元数据中的镜像digest
	osMatched := false

	// 如果digest为空，根据arch和os匹配获得信息
	// image name中可能已经指定了digest
	if currI.digest == "" || !currI.digestFromName {
		for _, iit := range currI.metadata.tagMetadata.Images {
			arch := fmt.Sprintf("%s:%s/%s:%s", iit.OS, iit.OSVersion, iit.Architecture, iit.Variant)
			archList = append(archList, arch)

			// 命中arch时覆盖digest
			if currI.architecture == iit.Architecture {
				// 有os命中更好，更覆盖
				if currI.os == iit.OS {
					if iit.Digest != "" {
						currI.digest = iit.Digest
					}
					osMatched = true
				} else if !osMatched && (iit.OS == "" || iit.OS == "unknown") {
					// os尚未命中时，如果tag的arch命中且os为空或unknown，可以暂存一个digest
					if iit.Digest != "" {
						currI.digest = iit.Digest
					}
				}
				// 信息全部命中时直接退出
				if osMatched && currI.variant == iit.Variant && currI.osVersion == iit.OSVersion {
					break
				}
			} else if iit.Architecture == "" || iit.Architecture == "unknown" {
				if currI.digest == "" {
					currI.digest = iit.Digest
				}
			}
		}
	}

	// 如果到这里digest还是为空，说明根据名称和arch解析的digest都失败了
	if currI.digest == "" {
		return nil, fmt.Errorf("no image with the same platform %s:%s/%s:%s was found in tag %s/%s/%s:%s metadata %s",
			currI.os, currI.osVersion, currI.architecture, currI.variant, currI.registry, currI.namespace, currI.repoName, currI.tagName, archList)
	}

	// 要求从API获取
	if fromAPI {
		isMeta, err = myutils.ReqImagesMetadata(currI.namespace, currI.repoName, currI.tagName)
	} else {
		if myutils.GlobalDBClient.MongoFlag {
			if iMeta, err = myutils.GlobalDBClient.Mongo.FindImageByDigest(currI.digest); err == nil {
				return iMeta, nil
			}
		}
		isMeta, err = myutils.ReqImagesMetadata(currI.namespace, currI.repoName, currI.tagName)
	}

	if err != nil {
		return nil, err
	}

	// 根据digest匹配对应的image metadata
	for _, iit := range isMeta {
		if currI.digest == iit.Digest {
			iMeta = iit
			break
		}
	}

	// 在检测时指定的digest匹配不上就要返回错误
	if iMeta == nil {
		if currI.digestFromName {
			return nil, fmt.Errorf("no image digest: %s was found in tag %s metadata", currI.digest,
				currI.registry+"/"+currI.namespace+"/"+currI.repoName+":"+currI.tagName)
		} else if !currI.tagMetaFromAPI {
			return nil, &ImageUpdatedAfterTagError{currI.registry + "/" + currI.namespace + "/" + currI.repoName + ":" + currI.tagName}
		} else {
			return nil, fmt.Errorf("no image digest: %s with the same platform %s was found in tag %s metadata",
				currI.digest, currI.os+"/"+currI.architecture, currI.registry+"/"+currI.namespace+"/"+currI.repoName+":"+currI.tagName)
		}
	}

	// API结果正常，存入数据库，存数据库过程的error不需要返回
	// TODO: 自由切换是全部保存还是只保存当前这一个镜像的信息
	if myutils.GlobalDBClient.MongoFlag {
		// 拿到的tag的全部image元数据都保存
		// for _, imgMeta := range isMeta {
		// 	currI.wg.Add(1)
		// 	go func(imgMetadata *myutils.Image) {
		// 		defer currI.wg.Done()
		// 		if e := myutils.GlobalDBClient.Mongo.UpdateImage(imgMetadata); e != nil {
		// 			myutils.Logger.Error("update metadata of image", imgMetadata.Digest, "failed with:", e.Error())
		// 		}
		// 	}(imgMeta)
		// }

		// 只保存当前这个镜像的信息
		currI.wg.Add(1)
		go func(imgMetadata *myutils.Image) {
			defer currI.wg.Done()
			if e := myutils.GlobalDBClient.Mongo.UpdateImage(imgMetadata); e != nil {
				myutils.Logger.Error("update metadata of image", imgMetadata.Digest, "failed with:", e.Error())
			}
		}(iMeta)
	}

	// 标记元数据来自API
	currI.imgMetaFromAPI = true

	return iMeta, nil
}

// extractRecommendCmd extracts container start command recommended
// by the author like `docker run` from full_description in repo metadata.
func extractRecommendCmd(desc string) []string {
	return extRecommendCmdRE.FindAllString(desc, -1)
}
