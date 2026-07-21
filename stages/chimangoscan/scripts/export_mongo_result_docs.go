package scripts

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/ChimangoScan/chimangoscan/myutils"
	"go.mongodb.org/mongo-driver/bson"
)

// inFile为镜像数据集文件，每一行为一个镜像名
// outDir为导出文件结果的根目录
func ExportImgResultsJSON(inFile, outDir string) error {
	file, err := os.Open(inFile)
	if err != nil {
		log.Fatalf("open %s failed with: %s\n", inFile, err)
	}
	defer file.Close()

	// 逐行读取文件内容
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		_, repoNamespace, repoName, tagName, digest := myutils.DivideImageName(line)
		if digest == "" {
			outFilename := path.Join(outDir, fmt.Sprintf("%s_%s_%s.json", repoNamespace, repoName, tagName))

			filter := bson.M{
				"namespace":       repoNamespace,
				"repository_name": repoName,
				"tag_name":        tagName,
			}

			qb, err := json.Marshal(filter)
			if err != nil {
				myutils.Logger.Error("marshal query filter to json for image", line, "failed with:", err.Error())
				continue
			}
			qs := string(qb)

			if err = ExportMongoDocJSON(
				myutils.GlobalConfig.MongoConfig.URI,
				myutils.GlobalConfig.MongoConfig.Database,
				myutils.GlobalConfig.MongoConfig.Collections.ImageResults,
				qs,
				outFilename); err != nil {
				myutils.Logger.Error("export image results of image", line, "failed with:", err.Error())
			} else {
				myutils.Logger.Info("export image results of image", line, "success")
			}
		} else {
			outFilename := path.Join(outDir, fmt.Sprintf("%s_%s_%s_%s.json", repoNamespace, repoName, tagName, digest))

			filter := bson.M{
				"namespace":       repoNamespace,
				"repository_name": repoName,
				"tag_name":        tagName,
				"digest":          digest,
			}

			qb, err := json.Marshal(filter)
			if err != nil {
				myutils.Logger.Error("marshal query filter to json for image", line, "failed with:", err.Error())
				continue
			}
			qs := string(qb)

			if err = ExportMongoDocJSON(
				myutils.GlobalConfig.MongoConfig.URI,
				myutils.GlobalConfig.MongoConfig.Database,
				myutils.GlobalConfig.MongoConfig.Collections.ImageResults,
				qs,
				outFilename); err != nil {
				myutils.Logger.Error("export image results of image", line, "failed with:", err.Error())
			} else {
				myutils.Logger.Info("export image results of image", line, "success")
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// filter为查询文档的关键字
// outFile为输出结果文件
func ExportMongoDocJSON(host, db, coll, filter, outFile string) error {
	cmd := exec.CommandContext(context.TODO(), "mongoexport", "--uri", host, "-d", db, "-c", coll, "-q", filter, "-o", outFile)
	err := cmd.Run()
	return err
}
