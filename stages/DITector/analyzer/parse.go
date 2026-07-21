package analyzer

import (
	"context"
	"fmt"
	"time"

	"github.com/ChimangoScan/DITector/myutils"
)

// ParsePartial 仅解析指定镜像的元数据
func (currI *CurrentImage) ParsePartial() (err error) {
	// 获取当前Docker server环境所在的平台信息
	// 只有digest为空的时候需要解析平台信息
	if currI.digest == "" {
		if err = currI.parseServerPlatform(); err != nil {
			myutils.Logger.Error("get Docker server platform failed with:", err.Error())
			return
		}
	}

	if err = currI.parseMetadata(true, false); err != nil {
		return
	}

	return
}

// ParseFromFile pulls and saves image to tar archive, and parses
// information based on the tar file.
func (currI *CurrentImage) ParseFromFile() (err error) {
	// 新启动线程下载镜像
	downloadCh := make(chan downloadFinish)
	go currI.pullSaveExtractImage(myutils.GlobalConfig.TmpDir, downloadCh)

	// 解析镜像repo、tag元数据
	if err = currI.parseMetadata(false, false); err != nil {
		return
	}

	// 等待镜像下载完成
	finish := <-downloadCh
	if finish.err != nil {
		return fmt.Errorf("pull, save and extract image %s error: %s", currI.name, finish.err)
	}
	currI.imgTarFile = finish.imgTarPath
	currI.imgFilepath = finish.imgDirPath

	// 解析镜像配置
	if err = currI.parseConfigurationFromFile(); err != nil {
		myutils.Logger.Error("parse configuration of image", currI.name, "failed with:", err.Error())
		return
	}

	// 解析镜像image元数据
	if err = currI.parseImageMetadata(false); err != nil {
		if isImageUpdatedAfterTagError(err) {
			if e := currI.parseMetadata(true, true); e != nil {
				return e
			}
		} else {
			return err
		}
	}

	// 根据时间检查镜像是否发生过更新，如果发生更新则从API获取
	if err = currI.checkUpdateOrder(); err != nil {
		myutils.Logger.Error("checkUpdateOrder for image:", currI.name, ", failed with:", err.Error())
		return err
	}

	// 解析镜像内容
	if err = currI.parseContentFromFile(); err != nil {
		myutils.Logger.Error("parse content of image", currI.name, "failed with:", err.Error())
		return
	}

	return
}

// ParseFromDockerEnv TODO: 解析指定镜像的元数据、配置信息，下载镜像，定位镜像的各个层
func (currI *CurrentImage) ParseFromDockerEnv() (err error) {
	// `docker pull`下载镜像
	if err = currI.pullImage(); err != nil {
		return err
	}

	// 获取当前Docker server环境所在的平台信息
	if err = currI.parseServerPlatform(); err != nil {
		myutils.Logger.Error("get Docker server platform failed with:", err.Error())
	}

	// 获取元数据
	if err = currI.parseMetadata(false, false); err != nil {
		return err
	}

	// 解析配置信息
	// 检查image是否位于本地Docker环境中，如果不存在则下载镜像
	if err = currI.parseConfigurationFromDockerEnv(); err != nil {
		myutils.Logger.Error("inspect image", currI.name, "failed with:", err.Error())
		return err
	}

	// 根据镜像配置提取出的平台信息获取image metadata
	if currI.metadata.imageMetadata, err = currI.getImageMetadata(false); err != nil {
		myutils.Logger.Error("parse image metadata of image", currI.name, "failed with:", err.Error())
		return err
	}

	// 解析内容信息
	if err = currI.parseContentFromDockerEnv(); err != nil {
		return err
	}

	return nil
}

// parseName parses registry, namespace, repository, tag of the image according to name.
func (currI *CurrentImage) parseName() {
	currI.registry, currI.namespace, currI.repoName, currI.tagName, currI.digest = myutils.DivideImageName(currI.name)
}

// parseServerPlatform gets platform of the host with Docker client.
func (currI *CurrentImage) parseServerPlatform() error {
	if plf, err := currI.dockerClient.ServerVersion(context.TODO()); err != nil {
		return err
	} else {
		currI.architecture, currI.os = plf.Arch, plf.Os
	}

	return nil
}

// checkUpdateOrder 检查镜像创建时间与image, tag, repository元数据间的更新时间关系，
// 根据时间顺序逻辑判断是否存在数据过时问题，如果有数据过时，则从API获取过时数据补充到
func (currI *CurrentImage) checkUpdateOrder() error {
	imgLastPushedTime, _ := time.Parse(time.RFC3339Nano, currI.metadata.imageMetadata.LastPushed)
	tagLastPushedTime, _ := time.Parse(time.RFC3339Nano, currI.metadata.tagMetadata.TagLastPushed)
	repoLastUpdatedTime, _ := time.Parse(time.RFC3339Nano, currI.metadata.repositoryMetadata.LastUpdated)

	if currI.configuration.Created.After(imgLastPushedTime) ||
		currI.configuration.Created.After(tagLastPushedTime) || imgLastPushedTime.After(tagLastPushedTime) ||
		currI.configuration.Created.After(repoLastUpdatedTime) || imgLastPushedTime.After(repoLastUpdatedTime) ||
		tagLastPushedTime.After(repoLastUpdatedTime) {
		if err := currI.parseMetadata(true, true); err != nil {
			return err
		}
	}

	//if currI.configuration.Created.After(currI.metadata.imageMetadata.LastPushed) {
	//	if err := currI.parseImageMetadata(true); err != nil {
	//		return err
	//	}
	//}
	//if currI.configuration.Created.After(currI.metadata.tagMetadata.TagLastPushed) ||
	//	currI.metadata.imageMetadata.LastPushed.After(currI.metadata.tagMetadata.TagLastPushed) {
	//	if err := currI.parseTagMetadata(true); err != nil {
	//		return err
	//	}
	//}
	//if currI.configuration.Created.After(currI.metadata.repositoryMetadata.LastUpdated) ||
	//	currI.metadata.imageMetadata.LastPushed.After(currI.metadata.repositoryMetadata.LastUpdated) ||
	//	currI.metadata.tagMetadata.TagLastPushed.After(currI.metadata.repositoryMetadata.LastUpdated) {
	//	if err := currI.parseRepoMetadata(true); err != nil {
	//		return err
	//	}
	//}

	return nil
}
