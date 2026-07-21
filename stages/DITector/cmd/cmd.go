package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ChimangoScan/DITector/analyzer"
	"github.com/ChimangoScan/DITector/buildgraph"
	"github.com/ChimangoScan/DITector/crawler"
	"github.com/ChimangoScan/DITector/myutils"
	"github.com/ChimangoScan/DITector/scripts"
	"github.com/spf13/cobra"
)

var logLevelStr string
var validLogLevel = map[string]int{"debug": 1, "info": 2, "warn": 3, "error": 4, "critical": 5}

const longDesc = `
 _____             _             _____                 
|  __ \           | |           / ____|                
| |  | | ___   ___| | _____ _ _| (___   ___ __ _ _ __  
| |  | |/ _ \ / __| |/ / _ \ '__\___ \ / __/ _ | '_ \ 
| |__| | (_) | (__|   <  __/ |  ____) | (_| (_| | | | |
|_____/ \___/ \___|_|\_\___|_| |_____/ \___\__,_|_| |_|

A Docker security tool built with Go, implementing:
	- crawl Docker container image from Docker Hub
	- build dependency graph
	- pull, save image with Docker CLI and scan weakness of image`

var RootCmd = &cobra.Command{
	Use:   "docker-scan",
	Short: "docker-scan is a security tool for scraping and scanning Docker container images",
	Long:  longDesc,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		if logLevel, ok := validLogLevel[logLevelStr]; ok {
			myutils.LoadConfigFromFile(configFile, logLevel)
			// 初始化analyzer
			analyzer.DefaultAnalyzer, analyzer.DefaultAnalyzerE = analyzer.NewImageAnalyzerGlobalConfig()
		} else {
			log.Fatalln("invalid log_level:", logLevelStr)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		// 仅用作测试
		myutils.Logger.Info("start test")
		beginTime := time.Now()

		// Test code here

		myutils.Logger.Info("finish test")
		fmt.Println("time used:", time.Since(beginTime))
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		// 所有命令退出前的清理工作
		myutils.CloseAllConnections()
	},
}

var crawlCmd = &cobra.Command{
	Use:   "crawl",
	Short: "crawl metadata of repositories and images from specific Docker registry, now supports Docker Hub only",
	Run: func(cmd *cobra.Command, args []string) {
		workers, _ := cmd.Flags().GetInt("workers")
		proxyFile, _ := cmd.Flags().GetString("proxies")
		accountFile, _ := cmd.Flags().GetString("accounts")
		seed, _ := cmd.Flags().GetString("seed")
		shard, _ := cmd.Flags().GetInt("shard")
		shards, _ := cmd.Flags().GetInt("shards")

		im, err := crawler.LoadIdentities(proxyFile, accountFile)
		if err != nil {
			log.Fatalf("Failed to load identities: %v", err)
		}

		// Determine seeds using the following priority:
		//   1. --shard N --shards M  → meet-in-the-middle: explore 1/M of the alphabet
		//   2. --seed a,b,c          → explicit comma-separated keywords
		//   3. (nothing)             → full alphabet (backward-compatible default)
		var seeds []string
		if shards > 1 && shard >= 0 {
			if shard >= shards {
				log.Fatalf("--shard %d must be < --shards %d", shard, shards)
			}
			seeds = crawler.ShardSeeds(shard, shards)
			myutils.Logger.Info(fmt.Sprintf("Meet-in-the-middle: shard %d/%d → %d root keywords", shard, shards, len(seeds)))
		} else if seed != "" {
			seeds = strings.Split(seed, ",")
			for i, s := range seeds {
				seeds[i] = strings.TrimSpace(s)
			}
		}
		// len(seeds)==0 → Start() seeds the full alphabet

		pc := crawler.NewParallelCrawler(workers, im)
		pc.Start(seeds)
	},
}

var calculateCmd = &cobra.Command{
	Use:   "calculate",
	Short: "calculate node id of specific image",
	Run: func(cmd *cobra.Command, args []string) {
		digest, _ := cmd.Flags().GetString("digest")
		img, err := myutils.GlobalDBClient.Mongo.FindImageByDigest(digest)
		if err != nil {
			log.Fatalln("mongo find image", digest, "failed with:", err)
		}
		fmt.Println(myutils.CalculateImageNodeId(img))
	},
}

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "fetch tag/image metadata and build Neo4j dependency graph from crawled repos",
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		threshold, _ := cmd.Flags().GetInt64("threshold")
		proxyFile, _ := cmd.Flags().GetString("proxies")
		accountFile, _ := cmd.Flags().GetString("accounts")
		dataDir, _ := cmd.Flags().GetString("data_dir")

		im, err := crawler.LoadIdentities(proxyFile, accountFile)
		if err != nil {
			log.Fatalf("Failed to load identities: %v", err)
		}
		workers := len(im.Accounts)
		if workers == 0 {
			workers = 1
		}
		buildgraph.Build(format, threshold, workers, im, dataDir)
	},
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "analyze Docker image by name/file",
	Run: func(cmd *cobra.Command, args []string) {
		partial, _ := cmd.Flags().GetBool("partial")
		name, _ := cmd.Flags().GetString("name")
		file, _ := cmd.Flags().GetString("file")
		jsonFlag, _ := cmd.Flags().GetBool("json")
		output, _ := cmd.Flags().GetString("output")

		var res *myutils.ImageResult
		var err error

		if name != "" {
			if partial {
				res, err = analyzer.AnalyzeImagePartialByName(name)
			} else {
				res, err = analyzer.AnalyzeImageByName(name, false)
			}
		} else if file != "" {
			// AnalyzeImageByFile暂时未实现
		} else {
			log.Fatalf("invalid use of command: %s analyze, `%s analyze` to see help\n", RootCmd.Use, RootCmd.Use)
		}

		if err != nil {
			log.Fatalln("analyze image got error:", err)
		}

		if res != nil {
			if jsonFlag {
				jsonData, err := json.Marshal(res)
				if err != nil {
					log.Fatalln("json marshal analysis result got error:", err)
				}
				if output != "" {
					err = os.WriteFile(output, jsonData, 0664)
					if err != nil {
						log.Fatalln("json marshal analysis result got error:", err)
					}
				}
			}

			fmt.Println("analysis succeeded, result stored in file:", output)
		} else {
			log.Fatalln("something wrong during analyzing image got result: nil")
		}

		fmt.Println("analyze finish")
	},
}

var executeCmd = &cobra.Command{
	Use:   "execute",
	Short: "execute custom scripts",
	Run: func(cmd *cobra.Command, args []string) {
		script, _ := cmd.Flags().GetString("script")
		switch script {
		case "analyze-threshold":
			threshold, _ := cmd.Flags().GetInt64("threshold")
			tagNum, _ := cmd.Flags().GetInt("tags")
			page, _ := cmd.Flags().GetInt64("page")
			err := scripts.AnalyzePullCountOverThreshold(threshold, tagNum, page)
			if err != nil {
				log.Fatalln("analyze-threshold got error:", err)
			}
		case "analyze-all":
			page, _ := cmd.Flags().GetInt64("page")
			pageSize, _ := cmd.Flags().GetInt64("page_size")
			tagCnt, _ := cmd.Flags().GetInt("tags")
			partial, _ := cmd.Flags().GetBool("partial")
			fmt.Println(myutils.GetLocalNowTimeStr(), "start to execute, script:", script, ", page:", page, ", page_size:", pageSize, ", tags:", tagCnt, ", partial:", partial)
			err := scripts.AnalyzeAll(page, pageSize, tagCnt, partial)
			if err != nil {
				log.Fatalln("analyze-all got error:", err)
			}
		case "calculate-node-weights":
			file, _ := cmd.Flags().GetString("file")
			page, _ := cmd.Flags().GetInt64("page")
			pageSize, _ := cmd.Flags().GetInt64("page_size")
			threshold, _ := cmd.Flags().GetInt64("threshold")
			err := scripts.CalculateNodeRelyWeights(file, page, int(pageSize), threshold)
			if err != nil {
				log.Fatalln("calculate-node-weights got error:", err)
			}
		case "count-images-with-upstream":
			file, _ := cmd.Flags().GetString("file")
			page, _ := cmd.Flags().GetInt64("page")
			pageSize, _ := cmd.Flags().GetInt64("page_size")
			threshold, _ := cmd.Flags().GetInt64("threshold")
			err := scripts.CountNodeWithUpstreamImages(file, page, int(pageSize), threshold)
			if err != nil {
				log.Fatalln("calculate-node-weights got error:", err)
			}
		case "count-images-with-downstream":
			file, _ := cmd.Flags().GetString("file")
			output, _ := cmd.Flags().GetString("output")
			form, _ := cmd.Flags().GetString("format")
			fmt.Println("count-images-with-downstream with file:", file, "output:", output, "format:", form)
			err := scripts.CountNodeWithDownstreamImages(file, output, form)
			if err != nil {
				log.Fatalln("count-images-with-downstream got error:", err)
			}
		case "export-mongo-result-docs":
			file, _ := cmd.Flags().GetString("file")
			output, _ := cmd.Flags().GetString("output")
			err := scripts.ExportImgResultsJSON(file, output)
			if err != nil {
				log.Fatalln("export-mongo-result-docs got error:", err)
			}
		case "check-same-node-as-high-dependent-images":
			file, _ := cmd.Flags().GetString("file")
			output, _ := cmd.Flags().GetString("output")
			fmt.Printf("begin to check-same-node-as-high-dependent-images with arguements, file: %s, output: %s\n", file, output)
			err := scripts.CheckSameNodeAsHighDependentImages(file, output)
			if err != nil {
				log.Fatalln("check-same-node-as-high-dependent-images got error:", err)
			}
		}
	},
}

func init() {
	// RootCmd
	RootCmd.PersistentFlags().StringP("config", "c", "config.yaml", "path to config file")
	RootCmd.PersistentFlags().StringVarP(&logLevelStr, "log_level", "l", "debug", "log level: debug, info, warn, error, critical")

	// crawlCmd
	crawlCmd.Flags().IntP("workers", "w", 10, "number of parallel crawler workers")
	crawlCmd.Flags().String("proxies", "", "path to proxies file (one per line)")
	crawlCmd.Flags().String("accounts", "", "path to accounts JSON file")
	crawlCmd.Flags().String("seed", "", "comma-separated root keywords for DFS (e.g., 'nginx' or 'a,b,c')")
	crawlCmd.Flags().Int("shard", -1, "shard index (0-based) for meet-in-the-middle crawl; requires --shards")
	crawlCmd.Flags().Int("shards", 1, "total number of shards for meet-in-the-middle crawl (e.g., 2)")

	// calculateCmd
	calculateCmd.Flags().String("digest", "", "digest of the image to calculate the node id in Neo4j")

	// buildCmd
	buildCmd.Flags().String("format", "mongo", "source format: mongo")
	buildCmd.Flags().Int64("threshold", 0, "minimum pull_count to include a repo (0 = all repos, ordered by pull_count DESC)")
	buildCmd.Flags().String("proxies", "", "path to proxies file (one per line)")
	buildCmd.Flags().String("accounts", "", "path to accounts JSON file")
	buildCmd.Flags().String("data_dir", ".", "directory for build_checkpoint.jsonl (use a host-mounted path)")

	// analyzeCmd
	analyzeCmd.Flags().Bool("partial", false, "only analyze metadata of the Docker image")
	analyzeCmd.Flags().StringP("name", "n", "", "analyze Docker image by name")
	analyzeCmd.Flags().StringP("file", "f", "", "analyze Docker image by file")
	analyzeCmd.Flags().Bool("json", true, "output in JSON")
	analyzeCmd.Flags().StringP("output", "o", fmt.Sprintf("%s_result.json", myutils.GetLocalNowTimeNoSpace()), "analysis result output filepath")

	// executeCmd
	executeCmd.Flags().String("script", "", "execute custom script, including: batch-analyze, analyze-threshold, analyze-all")
	executeCmd.Flags().Bool("partial", false, "only analyze metadata of the Docker images")
	executeCmd.Flags().StringP("file", "f", "", "input file for scripts, like batch-analyze")
	executeCmd.Flags().StringP("output", "o", "", "output file for scripts")
	executeCmd.Flags().String("format", "", "json")
	executeCmd.Flags().Int64("threshold", 1000000, "pull_count threshold to analyze an image")
	executeCmd.Flags().Int("tags", 3, "the top tag-num recently updated tags to analyze")
	executeCmd.Flags().Int64("page", 1, "start page for analyzing multiple repos from MongoDB")
	executeCmd.Flags().Int64("page_size", 5, "page size of finding multiple repos from MongoDB")

	// 向root命令中注册命令
	RootCmd.AddCommand(
		crawlCmd,
		calculateCmd,
		buildCmd,
		analyzeCmd,
		executeCmd,
	)
}
