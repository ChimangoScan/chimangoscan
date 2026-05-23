package myutils

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

var GlobalConfig struct {
	MaxThread            int    `yaml:"max_thread"`
	LogFile              string `yaml:"log_file"`
	RepoWithManyTagsFile string `yaml:"repo_with_many_tags_file"`
	TmpDir               string `yaml:"tmp_dir"`
	Proxy                struct {
		HTTPProxy  string `yaml:"http_proxy"`
		HTTPSProxy string `yaml:"https_proxy"`
	} `yaml:"proxy"`
	DockerConfig struct {
		Username      string `yaml:"username"`
		Password      string `yaml:"password"`
		Auth          string `yaml:"auth"`
		ServerAddress string `yaml:"serveraddress"`
		IdentityToken string `yaml:"identitytoken"`
		RegistryToken string `yaml:"registrytoken"`
	} `yaml:"docker_config"`
	MongoConfig struct {
		URI         string `yaml:"uri"`
		Database    string `yaml:"database"`
		Collections struct {
			Repositories string `yaml:"repositories"`
			Tags         string `yaml:"tags"`
			Images       string `yaml:"images"`
			ImageResults string `yaml:"image_results"`
			LayerResults string `yaml:"layer_results"`
			User         string `yaml:"user"`
		} `yaml:"collections"`
	} `yaml:"mongo_config"`
	Neo4jConfig struct {
		Neo4jURI      string `yaml:"neo4j_uri"`
		Neo4jUsername string `yaml:"neo4j_username"`
		Neo4jPassword string `yaml:"neo4j_password"`
	} `yaml:"neo4j_config"`
	RulesConfig struct {
		SecretRulesFile         string `yaml:"secret_rules_file"`
		SensitiveParamRulesFile string `yaml:"sensitive_param_rules_file"`
	} `yaml:"rules_config"`
	TrufflehogConfig struct {
		Filepath string `yaml:"filepath"`
		Verify   bool   `yaml:"verify"`
	} `yaml:"trufflehog_config"`
	AnchoreConfig struct {
		Filepath string `yaml:"filepath"`
	} `yaml:"anchore_config"`
}

// GlobalDBClient 用于维护全局所有模块的数据库client连接
var GlobalDBClient struct {
	Mongo     *MyMongo
	MongoFlag bool // 标识Mongo是否成功连接
	Neo4j     *MyNeo4j
	Neo4jFlag bool // 标识Neo4j是否成功连接
}

func LoadConfigFromFile(configFilepath string, logLevel int) {
	// 获取程序根目录，这个好像不太对，换了一个实现
	// _, filename, _, _ := runtime.Caller(0)
	// root := path.Dir(path.Dir(filename))

	root, err := os.Getwd()
	if err != nil {
		log.Fatalln("[ERROR] get working dir path failed, got err:", err)
	}
	// fmt.Println(root)

	// 加载config.yaml
	fb, err := os.ReadFile(configFilepath)
	if err != nil {
		log.Fatalln("[ERROR] Failed to load ", configFilepath)
	}
	if err = yaml.Unmarshal(fb, &GlobalConfig); err != nil {
		log.Fatalf("[ERROR] Json failed to unmarshal %s with err: %v\n", configFilepath, err)
	}

	// Environment variable overrides — allow remote machines to point at a
	// shared MongoDB/Neo4j without needing a separate config file.
	//   MONGO_URI=mongodb://<node1-ip>:27017
	//   NEO4J_URI=neo4j://<node1-ip>:7687
	if v := os.Getenv("MONGO_URI"); v != "" {
		GlobalConfig.MongoConfig.URI = v
	}
	if v := os.Getenv("NEO4J_URI"); v != "" {
		GlobalConfig.Neo4jConfig.Neo4jURI = v
	}

	fmt.Println(GlobalConfig.MongoConfig.URI, GlobalConfig.MongoConfig.Database, GlobalConfig.MongoConfig.Collections)

	// 配置最大线程数
	if GlobalConfig.MaxThread > 0 && GlobalConfig.MaxThread < runtime.NumCPU() {
		runtime.GOMAXPROCS(GlobalConfig.MaxThread)
	} else {
		GlobalConfig.MaxThread = runtime.NumCPU()
	}

	// 调整相对路径到绝对路径
	relativeToAbsoluteConfig(root)

	// 初始化日志模块
	logFilepath := genLogFilepath()
	if err = configLogger(logFilepath, logLevel); err != nil {
		log.Fatalf("[ERROR] Open %s failed with: %s\n", logFilepath, err)
	} else {
		fmt.Println("[+] Open log file: ", logFilepath)
	}
	// 引入日志文件按日期轮换
	go checkAndRotateLogFile()

	// 初始化包含过多tag的repo名称列表
	repoNameWithManyTagsFile, _ = NewRepoNameRecordFile(GlobalConfig.RepoWithManyTagsFile)

	// 配置http代理
	configEnvHTTPProxy(GlobalConfig.Proxy.HTTPProxy, GlobalConfig.Proxy.HTTPSProxy)

	// 配置tls，跳过https证书验证
	configTLSConfig()

	// 初始化数据库连接
	connectDBs()
}

// relativeToAbsoluteConfig 将GlobalConfig中相对路径的部分调整为绝对路径
func relativeToAbsoluteConfig(root string) {
	if !strings.HasPrefix(GlobalConfig.LogFile, "/") {
		GlobalConfig.LogFile = path.Join(root, GlobalConfig.LogFile)
	}
	if !strings.HasPrefix(GlobalConfig.RulesConfig.SecretRulesFile, "/") {
		GlobalConfig.RulesConfig.SecretRulesFile = path.Join(root, GlobalConfig.RulesConfig.SecretRulesFile)
	}
	if !strings.HasPrefix(GlobalConfig.RulesConfig.SensitiveParamRulesFile, "/") {
		GlobalConfig.RulesConfig.SensitiveParamRulesFile = path.Join(root, GlobalConfig.RulesConfig.SensitiveParamRulesFile)
	}
}

// connectDBs connects MongoDB and Neo4j based on config.yaml
func connectDBs() {
	var err error

	// 连接MongoDB
	// TODO: Mongo Timeout设置不正确，目前不生效
	if GlobalDBClient.Mongo, err = NewMongoGlobalConfig(); err != nil {
		GlobalDBClient.MongoFlag = false
		Logger.Error("connect to MongoDB failed with:", err.Error())
		fmt.Println("[-] Connect to MongoDB failed")
	} else {
		GlobalDBClient.MongoFlag = true
		fmt.Println("[+] Connect to MongoDB")
	}

	// 连接Neo4j
	// Neo4j connection is optional for Stage I (crawl).
	GlobalDBClient.Neo4j, err = NewNeo4jDriverGlobalConfig()
	if err != nil {
		GlobalDBClient.Neo4jFlag = false
		Logger.Warn(fmt.Sprintf("Neo4j connection failed (optional): %v", err))
		fmt.Println("[-] Connect to Neo4j failed (optional)")
	} else {
		// Verify connection with a timeout to avoid hanging
		ctx, cancel := context.WithTimeout(context.Background(), 5000000000) // 5 seconds in nanoseconds
		defer cancel()
		if err := GlobalDBClient.Neo4j.Driver.VerifyConnectivity(ctx); err != nil {
			GlobalDBClient.Neo4jFlag = false
			Logger.Warn(fmt.Sprintf("Neo4j connectivity check failed: %v", err))
			fmt.Println("[-] Connect to Neo4j failed (connectivity check)")
		} else {
			GlobalDBClient.Neo4jFlag = true
			fmt.Println("[+] Connect to Neo4j")
		}
	}
}

// CloseAllConnections 用于在主函数退出前关闭所有占用的资源
func CloseAllConnections() {
	// disconnect MongoDB
	if GlobalDBClient.MongoFlag {
		if err := GlobalDBClient.Mongo.Client.Disconnect(context.TODO()); err != nil {
			Logger.Error("disconnect MongoDB client failed with:", err.Error())
		}
	}

	// close Neo4j
	if GlobalDBClient.Neo4jFlag {
		if err := GlobalDBClient.Neo4j.Driver.Close(context.TODO()); err != nil {
			Logger.Error("close Neo4j driver failed with:", err.Error())
		}
	}

	// close logger file
	if err := Logger.Close(); err != nil {
		log.Fatalln(LogLevelStr.Error, "close log file", GlobalConfig.LogFile, "failed with:", err.Error())
	}
}
