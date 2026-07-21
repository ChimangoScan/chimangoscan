package scripts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ChimangoScan/DITector/myutils"
)

// CheckSameNodeAsHighDependentImages 统计高依赖权重镜像的节点
// 从input文件路径读取
// 结果输出到output文件
func CheckSameNodeAsHighDependentImages(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	nameList := []string{}
	reader := bufio.NewReader(inputFile)
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		nameList = append(nameList, string(line))
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	writer := bufio.NewWriter(outputFile)

	for i := range nameList {
		if i%1000 == 0 {
			fmt.Println("begin to check image", i)
		}

		_, _, _, _, digest := myutils.DivideImageName(nameList[i])
		img, err := myutils.GlobalDBClient.Mongo.FindImageByDigest(digest)
		if err != nil {
			fmt.Println("mongo FindImageByDigest failed for image", i, ", digest", digest)
			continue
		}

		nodeId := myutils.CalculateImageNodeId(img)
		rec, err := myutils.GlobalDBClient.Neo4j.FindLayerByNodeId(nodeId)
		if err != nil {
			fmt.Println("neo4j FindLayerByNodeId failed for image", i, ", digest", digest, ", nodeId", nodeId)
			continue
		}

		nodeStruct := struct {
			NodeId        string   `json:"node_id"`
			ImageNameList []string `json:"image_name_list"`
		}{
			NodeId:        nodeId,
			ImageNameList: []string{},
		}

		imageSet := make(map[string]struct{})
		prop := myutils.GetNodeProps(rec)
		if imageList, ok := prop["images"]; ok && len(imageList.([]interface{})) > 0 {
			for _, imageName := range imageList.([]interface{}) {
				imgNameStr := imageName.(string)
				imageSet[imgNameStr] = struct{}{}
			}
		} else {
			fmt.Println("parse neo4j node got empty image list for nodeId", nodeId)
			continue
		}

		for k, _ := range imageSet {
			nodeStruct.ImageNameList = append(nodeStruct.ImageNameList, k)
		}

		b, err := json.Marshal(nodeStruct)
		if err != nil {
			fmt.Printf("json Marshal for nodeStruct %s failed with: %s\n", nodeStruct, err)
			continue
		}

		_, err = writer.Write(b)
		if err != nil {
			fmt.Printf("write to output file %s got error: %s\n", outputPath, err)
			continue
		}

		_ = writer.WriteByte('\n')
		writer.Flush()
	}

	return nil
}
