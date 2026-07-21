package analyzer

import "fmt"

// parseContentFromFile parses content information from local file,
// including locating local filepath of layers.
func (currI *CurrentImage) parseContentFromFile() error {
	// 从image metadata中提取有文件内容的layer信息
	currI.parseLayersWithContentFromMetadata()

	// 根据文件解压情况对应镜像文件本地位置（不需要root权限）
	if len(currI.layerWithContentList) != len(currI.layerLocalFilepathList) {
		if err := currI.parseMetadata(true, true); err != nil {
			return fmt.Errorf("layers number of image %s from metadata %d != from tar manifest %d, reload metadata from API got error: %s",
				currI.name, len(currI.layerWithContentList), len(currI.layerLocalFilepathList), err)
		} else {
			currI.parseLayersWithContentFromMetadata()
			if len(currI.layerWithContentList) != len(currI.layerLocalFilepathList) {
				return fmt.Errorf("layers number of image %s from metadata %d != from tar manifest %d",
					currI.name, len(currI.layerWithContentList), len(currI.layerLocalFilepathList))
			}
		}
	}
	for i, digest := range currI.layerWithContentList {
		currI.layerInfoMap[digest].localFilePath = currI.layerLocalFilepathList[i]
		currI.layerInfoMap[digest].localRootFilePath = currI.layerLocalRootFilepathList[i]
	}

	return nil
}

// parseContentFromDockerEnv parses content information from local Docker env,
// including locating local filepath of layers.
func (currI *CurrentImage) parseContentFromDockerEnv() error {
	currI.parseLayersWithContentFromMetadata()

	// TODO: 根据LowerDir和UpperDir获取Docker维护的本地层文件位置（需要root权限）
	//for _, graphPath := range currI.configuration.GraphDriver.Data[] {
	//
	//}

	return nil
}

// parseLayersWithContentFromMetadata extracts layer digests from layer metadata.
func (currI *CurrentImage) parseLayersWithContentFromMetadata() {
	currI.layerWithContentList = []string{}
	for _, layer := range currI.metadata.imageMetadata.Layers {
		if layer.Digest != "" {
			currI.layerWithContentList = append(currI.layerWithContentList, layer.Digest)
			currI.layerInfoMap[layer.Digest] = &layerInfo{
				size:        layer.Size,
				instruction: layer.Instruction,
				digest:      layer.Digest,
			}
		}
	}
}
