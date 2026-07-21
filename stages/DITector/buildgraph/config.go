package buildgraph

import (
	"fmt"
	"os"
)

var ConfigBuilder struct {
	MaxThread      int    `json:"max_thread"`
	DataDir        string `json:"data_dir"`
	RepositoryFile string `json:"repository_file"`
	TagsFile       string `json:"tags_file"`
	ImagesFile     string `json:"images_file"`
	Builder        URIS   `json:"builder"`
}

type URIS struct {
	Neo4jURI      string `json:"neo4j_uri"`
	Neo4jUsername string `json:"neo4j_username"`
	Neo4jPassword string `json:"neo4j_password"`
}

func config(format string) {
	// 根据format连接数据源
	switch format {
	case "mongo":
		// 目前没什么要做的
	default:
		fmt.Println("[ERROR] Invalid data source configured: ", format)
		os.Exit(-2)
	}
}
