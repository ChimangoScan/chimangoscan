package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/ChimangoScan/DITector/analyzer/extractor"
	"github.com/ChimangoScan/DITector/myutils"
)

func (analyzer *ImageAnalyzer) analyzeMetadata(ci *CurrentImage) (*myutils.MetadataResult, error) {
	res := myutils.NewMetadataResult()

	repoMetaRes, err := analyzer.analyzeRepoMetadata(ci)
	if err != nil {
		return nil, err
	}
	res.SensitiveParams = repoMetaRes.SensitiveParams

	imgMetaRes, err := analyzer.analyzeImageMetadata(ci)
	if err != nil {
		return nil, err
	}
	res.SecretLeakages = imgMetaRes.SecretLeakages
	res.InstalledContents = imgMetaRes.InstalledContents

	return res, nil
}

func (analyzer *ImageAnalyzer) analyzeRepoMetadata(ci *CurrentImage) (*myutils.MetadataResult, error) {
	res := myutils.NewMetadataResult()

	// 分析敏感参数
	// full_description中推荐的`docker run`
	for _, recCmd := range ci.recommendedCmd {
		is := analyzer.scanSensitiveParamInString(recCmd)
		for i, _ := range is {
			is[i].Part = myutils.IssuePart.RepoMetadata
			is[i].Path = "full_description"
		}
		res.SensitiveParams = append(res.SensitiveParams, is...)
	}

	return res, nil
}

func (analyzer *ImageAnalyzer) analyzeImageMetadata(ci *CurrentImage) (*myutils.MetadataResult, error) {
	res := myutils.NewMetadataResult()

	// 扫描隐私泄露
	// 将image元数据中的layer信息写入临时文件
	if ci.metadata.imageMetadata == nil || ci.metadata.imageMetadata.Layers == nil {
		return nil, fmt.Errorf("nil pointer detected when analyzed image metadata of image %s, digest: %s", ci.name, ci.digest)
	}
	metaFilepath := path.Join(myutils.GlobalConfig.TmpDir, fmt.Sprintf("%s-%s-%s-meta.json", ci.namespace, ci.repoName, ci.tagName))
	layerData, err := json.MarshalIndent(ci.metadata.imageMetadata.Layers, "", "    ")
	if err != nil {
		myutils.Logger.Error("json marshal layer metadata of image", ci.name, "failed with:", err.Error())
		return nil, err
	}
	err = os.WriteFile(metaFilepath, layerData, 0644)
	if err != nil {
		myutils.Logger.Error("write layer metadata of image", ci.name, "to file", metaFilepath, "failed with:", err.Error())
		return nil, err
	}
	defer os.Remove(metaFilepath)

	// 调用trufflehog扫描layer信息临时文件中包含的敏感数据
	secrets, err := scanSecretsInFilepath(metaFilepath)
	if err != nil {
		myutils.Logger.Error("scanSecretsInFilepath", metaFilepath, "failed with:", err.Error())
		return nil, err
	}
	for _, secret := range secrets {
		secret.Part = myutils.IssuePart.ImageMetadata
		// 定位泄露的隐私位于哪个层命令中
		for index, layer := range ci.metadata.imageMetadata.Layers {
			if strings.Contains(layer.Instruction, secret.Match) {
				secret.Path = fmt.Sprintf("layers[%d].instruction", index)
				break
			}
		}
	}

	res.SecretLeakages = secrets

	// 扫描内容下载
	installedContents := make([]*myutils.InstalledContent, 0)
	for _, layer := range ci.metadata.imageMetadata.Layers {
		installs := extractInstalledContentsFromInstruction(layer.Instruction, layer.Digest)
		installedContents = append(installedContents, installs...)
	}
	res.InstalledContents = installedContents

	return res, nil
}

// extractInstalledContentsFromInstruction 从命令字符串中提取出安装内容，包括pip install, npm install, wget, ADD
func extractInstalledContentsFromInstruction(instruction string, digest string) []*myutils.InstalledContent {
	res := make([]*myutils.InstalledContent, 0)

	// pip install
	if extractor.CheckPipInstallCmd(instruction) {
		for _, cmd := range extractor.ExtractPipInstallCmdsFromString(instruction) {
			pipArgs := extractor.ParsePipInstallCmdArgs(cmd)
			pkgsMap := pipArgs["_name"].(map[string][]string)
			for name, vers := range pkgsMap {
				res = append(res, &myutils.InstalledContent{
					Source:        "pip install",
					Command:       cmd,
					Name:          name,
					VersionLimits: vers,
					Instruction:   instruction,
					LayerDigest:   digest,
				})
			}
		}
	}

	// npm install
	if extractor.CheckNpmInstallCmd(instruction) {
		for _, cmd := range extractor.ExtractNpmInstallCmdsFromString(instruction) {
			npmArgs := extractor.ParseNpmInstallCmdArgs(cmd)
			pkgsMap := npmArgs["_name"].(map[string][]string)
			for name, vers := range pkgsMap {
				res = append(res, &myutils.InstalledContent{
					Source:        "npm install",
					Command:       cmd,
					Name:          name,
					VersionLimits: vers,
					Instruction:   instruction,
					LayerDigest:   digest,
				})
			}
		}
	}

	// wget
	if extractor.CheckWgetCmd(instruction) {
		for _, cmd := range extractor.ExtractWgetCmds(instruction) {
			for _, u := range extractor.ExtractWgetCmdURLs(cmd) {
				res = append(res, &myutils.InstalledContent{
					Source:        "wget",
					Command:       cmd,
					Name:          u,
					VersionLimits: []string{},
					Instruction:   instruction,
					LayerDigest:   digest,
				})
			}
		}
	}

	// Dockerfile ADD
	if extractor.CheckAddFromURL(instruction) {
		for _, u := range extractor.ExtractAddURLs(instruction) {
			res = append(res, &myutils.InstalledContent{
				Source:        "ADD",
				Command:       instruction,
				Name:          u,
				VersionLimits: []string{},
				Instruction:   instruction,
				LayerDigest:   digest,
			})
		}
	}

	return res
}

//func (analyzer *ImageAnalyzer) analyzeImageMetadata(ci *CurrentImage) (*myutils.MetadataResult, error) {
//	res := myutils.NewMetadataResult()
//
//	// 分析隐私泄露
//	// 扫描layers.instruction
//	for index, layer := range ci.metadata.imageMetadata.Layers {
//		is := analyzer.scanSecretsInString(layer.Instruction)
//		for i, _ := range is {
//			is[i].Part = myutils.IssuePart.ImageMetadata
//			is[i].Path = fmt.Sprintf("layers[%d].instruction", index)
//			is[i].LayerDigest = layer.Digest
//		}
//		res.SecretLeakages = append(res.SecretLeakages, is...)
//	}
//
//	return res, nil
//}
