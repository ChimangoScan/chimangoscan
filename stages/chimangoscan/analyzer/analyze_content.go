package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/ChimangoScan/chimangoscan/analyzer/misconfiguration"
	"github.com/ChimangoScan/chimangoscan/myutils"
)

type FileReputation struct {
	Sha256          string  `json:"sha256"`
	Level           int     `json:"level"`
	MalwareName     string  `json:"malware_name"`
	MalwareTypeName string  `json:"malware_type_name"`
	FileDesc        string  `json:"file_desc"`
	Describe        string  `json:"describe"`
	MaliciousFamily string  `json:"malicious_family"`
	SandboxScore    float64 `json:"sandbox_score"`
}

type AnchoreReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string   `json:"id"`
			DataSource  string   `json:"dataSource"`
			Namespace   string   `json:"namespace"`
			Severity    string   `json:"severity"`
			Urls        []string `json:"urls"`
			Description string   `json:"description"`
			Cvss        []struct {
				Source  string `json:"source"`
				Type    string `json:"type"`
				Version string `json:"version"`
				Vector  string `json:"vector"`
				Metrics struct {
					BaseScore           float64 `json:"baseScore"`
					ExploitabilityScore float64 `json:"exploitabilityScore"`
					ImpactScore         float64 `json:"impactScore"`
				} `json:"metrics"`
				VendorMetadata struct {
				} `json:"vendorMetadata"`
			} `json:"cvss"`
			Fix struct {
				Versions []any  `json:"versions"`
				State    string `json:"state"`
			} `json:"fix"`
			Advisories []any `json:"advisories"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []any `json:"relatedVulnerabilities"`
		MatchDetails           []struct {
			Type       string `json:"type"`
			Matcher    string `json:"matcher"`
			SearchedBy struct {
				Namespace string   `json:"namespace"`
				Cpes      []string `json:"cpes"`
				Package   struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"Package"`
			} `json:"searchedBy"`
			Found struct {
				VulnerabilityID   string   `json:"vulnerabilityID"`
				VersionConstraint string   `json:"versionConstraint"`
				Cpes              []string `json:"cpes"`
			} `json:"found"`
		} `json:"matchDetails"`
		Artifact struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
			Language  string   `json:"language"`
			Licenses  []string `json:"licenses"`
			Cpes      []string `json:"cpes"`
			Purl      string   `json:"purl"`
			Upstreams []struct {
				Name string `json:"name"`
			} `json:"upstreams"`
		} `json:"artifact"`
	} `json:"matches"`
	Source struct {
		Type   string `json:"type"`
		Target string `json:"target"`
	} `json:"source"`
	Distro struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		IDLike  any    `json:"idLike"`
	} `json:"distro"`
	Descriptor struct {
		Name          string `json:"name"`
		Version       string `json:"version"`
		Configuration struct {
			ConfigPath         string   `json:"configPath"`
			Verbosity          int      `json:"verbosity"`
			Output             []string `json:"output"`
			File               string   `json:"file"`
			Distro             string   `json:"distro"`
			AddCpesIfNone      bool     `json:"add-cpes-if-none"`
			OutputTemplateFile string   `json:"output-template-file"`
			Quiet              bool     `json:"quiet"`
			CheckForAppUpdate  bool     `json:"check-for-app-update"`
			OnlyFixed          bool     `json:"only-fixed"`
			OnlyNotfixed       bool     `json:"only-notfixed"`
			Platform           string   `json:"platform"`
			Search             struct {
				Scope             string `json:"scope"`
				UnindexedArchives bool   `json:"unindexed-archives"`
				IndexedArchives   bool   `json:"indexed-archives"`
			} `json:"search"`
			Ignore  any   `json:"ignore"`
			Exclude []any `json:"exclude"`
			Db      struct {
				CacheDir              string `json:"cache-dir"`
				UpdateURL             string `json:"update-url"`
				CaCert                string `json:"ca-cert"`
				AutoUpdate            bool   `json:"auto-update"`
				ValidateByHashOnStart bool   `json:"validate-by-hash-on-start"`
				ValidateAge           bool   `json:"validate-age"`
				MaxAllowedBuiltAge    int64  `json:"max-allowed-built-age"`
			} `json:"db"`
			ExternalSources struct {
				Enable bool `json:"enable"`
				Maven  struct {
					SearchUpstreamBySha1 bool   `json:"searchUpstreamBySha1"`
					BaseURL              string `json:"baseUrl"`
				} `json:"maven"`
			} `json:"externalSources"`
			Match struct {
				Java struct {
					UsingCpes bool `json:"using-cpes"`
				} `json:"java"`
				Dotnet struct {
					UsingCpes bool `json:"using-cpes"`
				} `json:"dotnet"`
				Golang struct {
					UsingCpes bool `json:"using-cpes"`
				} `json:"golang"`
				Javascript struct {
					UsingCpes bool `json:"using-cpes"`
				} `json:"javascript"`
				Python struct {
					UsingCpes bool `json:"using-cpes"`
				} `json:"python"`
				Ruby struct {
					UsingCpes bool `json:"using-cpes"`
				} `json:"ruby"`
				Stock struct {
					UsingCpes bool `json:"using-cpes"`
				} `json:"stock"`
			} `json:"match"`
			Dev struct {
				ProfileCPU bool `json:"profile-cpu"`
				ProfileMem bool `json:"profile-mem"`
			} `json:"dev"`
			FailOnSeverity string `json:"fail-on-severity"`
			Registry       struct {
				InsecureSkipTLSVerify bool   `json:"insecure-skip-tls-verify"`
				InsecureUseHTTP       bool   `json:"insecure-use-http"`
				Auth                  []any  `json:"auth"`
				CaCert                string `json:"ca-cert"`
			} `json:"registry"`
			Log struct {
				Structured bool   `json:"structured"`
				Level      string `json:"level"`
				File       string `json:"file"`
			} `json:"log"`
			ShowSuppressed         bool   `json:"show-suppressed"`
			ByCve                  bool   `json:"by-cve"`
			Name                   string `json:"name"`
			DefaultImagePullSource string `json:"default-image-pull-source"`
		} `json:"configuration"`
		Db struct {
			Built         time.Time `json:"built"`
			SchemaVersion int       `json:"schemaVersion"`
			Location      string    `json:"location"`
			Checksum      string    `json:"checksum"`
			Error         any       `json:"error"`
		} `json:"db"`
		Timestamp time.Time `json:"timestamp"`
	} `json:"descriptor"`
}

type ComponentMapKey struct {
	Name    string
	Version string
	Path    string
}

func (analyzer *ImageAnalyzer) analyzeContent(ci *CurrentImage, ir *myutils.ImageResult) (*myutils.ContentResult, error) {
	res := myutils.NewContentResult()
	fileWithIssues := make(map[string]bool)
	defaultExecFiles := make(map[string]struct{})
	for _, f := range ci.defaultExecFile {
		defaultExecFiles[f] = struct{}{}
	}

	// 逐层分析layer内容，写入对应LayerResult
	for _, ld := range ci.layerWithContentList {
		layerRes, fromMongo, err, layerGotErr := analyzer.analyzeLayer(ci.layerInfoMap[ld], fileWithIssues, defaultExecFiles)
		if err != nil {
			myutils.Logger.Error("analyze layer", ci.layerInfoMap[ld].digest, "layer dir path", ci.layerInfoMap[ld].localFilePath, "failed with:", err.Error())
			continue
		}
		ir.LayerResults[ld] = layerRes

		// 新分析的结果存入数据库
		if !fromMongo && !layerGotErr {
			if myutils.GlobalDBClient.MongoFlag {
				ci.wg.Add(1)
				go func(layerRes *myutils.LayerResult) {
					ci.wg.Done()
					if e := myutils.GlobalDBClient.Mongo.UpdateLayerResult(layerRes); e != nil {
						myutils.Logger.Error("update LayerResult", layerRes.Digest, "failed with:", e.Error())
					}
				}(layerRes)
			}
		}

		// 记录检测过程中出错的layer digest列表
		if layerGotErr {
			res.LayersGotErr = append(res.LayersGotErr, ld)
		}

		// 把有问题的结果文件放入当前状态表
		for _, secretInfo := range layerRes.SecretLeakages {
			fileWithIssues[secretInfo.Path] = true
		}
		for _, vulnInfo := range layerRes.Vulnerabilities {
			fileWithIssues[vulnInfo.Path] = false
		}
		for _, misconfInfo := range layerRes.Misconfigurations {
			fileWithIssues[misconfInfo.Path] = false
		}
		for _, malInfo := range layerRes.MaliciousFiles {
			fileWithIssues[malInfo.Path] = false
		}
	}

	// 汇总各层结果，存入全局表中（当前状态）
	fileAdded := make(map[string]int)
	for i := len(ir.Layers) - 1; i >= 0; i-- {
		layerDigest := ir.Layers[i]
		// 敏感信息泄露直接加到最终结果
		res.SecretLeakages = append(res.SecretLeakages, ir.LayerResults[layerDigest].SecretLeakages...)
		// 其他问题从顶层到底层添加，存在覆盖问题
		// 软件漏洞
		for _, vulnInfo := range ir.LayerResults[layerDigest].Vulnerabilities {
			// 不存在问题（已被修复）的文件不计入
			if _, issued := fileWithIssues[vulnInfo.Path]; !issued {
				continue
			}
			// 同层同一文件问题不覆盖（一个应用文件路径对应多个漏洞）
			// 不同层同一文件问题覆盖
			if pre, ok := fileAdded[vulnInfo.Path]; ok && pre != i {
				continue
			}
			res.Vulnerabilities = append(res.Vulnerabilities, vulnInfo)
			fileAdded[vulnInfo.Path] = i
		}
		// 错误配置
		for _, misconfInfo := range ir.LayerResults[layerDigest].Misconfigurations {
			if _, issued := fileWithIssues[misconfInfo.Path]; !issued {
				continue
			}

			if pre, ok := fileAdded[misconfInfo.Path]; ok && pre != i {
				continue
			}
			res.Misconfigurations = append(res.Misconfigurations, misconfInfo)
			fileAdded[misconfInfo.Path] = i
		}
		// 恶意软件
		for _, malInfo := range ir.LayerResults[layerDigest].MaliciousFiles {
			if _, issued := fileWithIssues[malInfo.Path]; !issued {
				continue
			}

			if pre, ok := fileAdded[malInfo.Path]; ok && pre != i {
				continue
			}
			res.MaliciousFiles = append(res.MaliciousFiles, malInfo)
			fileAdded[malInfo.Path] = i
		}

		// SCA结果
		for _, appInfo := range ir.LayerResults[layerDigest].Components {
			if pre, ok := fileAdded[appInfo.Filepath]; ok && pre != i {
				continue
			}
			res.Components = append(res.Components, appInfo)
			fileAdded[appInfo.Filepath] = i
		}
	}

	return res, nil
}

// analyzeContentVul 仅用于逐层分析镜像中包含的软件漏洞
func (analyzer *ImageAnalyzer) analyzeContentVul(ci *CurrentImage, ir *myutils.ImageResult) (*myutils.ContentResult, error) {
	res := myutils.NewContentResult()
	fileWithIssues := make(map[string]bool)

	// 逐层分析layer内容，写入对应LayerResult
	for _, ld := range ci.layerWithContentList {
		layerRes, fromMongo, err, layerGotErr := analyzer.analyzeLayer(ci.layerInfoMap[ld], fileWithIssues, map[string]struct{}{})
		if err != nil {
			myutils.Logger.Error("analyze layer", ci.layerInfoMap[ld].digest, "layer dir path", ci.layerInfoMap[ld].localFilePath, "for vulnerabilities failed with:", err.Error())
			continue
		}
		ir.LayerResults[ld] = layerRes

		// 新分析的结果存入数据库，只更新vulnerabilities字段
		if !fromMongo && !layerGotErr {
			if myutils.GlobalDBClient.MongoFlag {
				ci.wg.Add(1)
				go func(layerRes *myutils.LayerResult) {
					ci.wg.Done()
					if e := myutils.GlobalDBClient.Mongo.UpdateLayerResult(layerRes); e != nil {
						myutils.Logger.Error("update LayerResult", layerRes.Digest, "failed with:", e.Error())
					}
				}(layerRes)
			}
		}

		// 记录检测过程中出错的layer digest列表
		if layerGotErr {
			res.LayersGotErr = append(res.LayersGotErr, ld)
		}

		// 把有问题的结果文件放入当前状态表
		for _, vulnInfo := range layerRes.Vulnerabilities {
			fileWithIssues[vulnInfo.Path] = false
		}
	}

	// 汇总各层结果，存入全局表中（当前状态）
	fileAdded := make(map[string]int)
	for i := len(ir.Layers) - 1; i >= 0; i-- {
		layerDigest := ir.Layers[i]
		// 其他问题从顶层到底层添加，存在覆盖问题
		// 软件漏洞
		for _, vulnInfo := range ir.LayerResults[layerDigest].Vulnerabilities {
			// 不存在问题（已被修复）的文件不计入
			if _, issued := fileWithIssues[vulnInfo.Path]; !issued {
				continue
			}
			// 同层同一文件问题不覆盖（一个应用文件路径对应多个漏洞）
			// 不同层同一文件问题覆盖
			if pre, ok := fileAdded[vulnInfo.Path]; ok && pre != i {
				continue
			}
			res.Vulnerabilities = append(res.Vulnerabilities, vulnInfo)
			fileAdded[vulnInfo.Path] = i
		}

		// SCA结果
		for _, appInfo := range ir.LayerResults[layerDigest].Components {
			if pre, ok := fileAdded[appInfo.Filepath]; ok && pre != i {
				continue
			}
			res.Components = append(res.Components, appInfo)
			fileAdded[appInfo.Filepath] = i
		}
	}

	return res, nil
}

// analyzeLayer traverses and analyzes files under inputted layerDir,
// and writes results directly to layerResult.
func (analyzer *ImageAnalyzer) analyzeLayer(layer *layerInfo, fileWithIssues map[string]bool, defaultExecFiles map[string]struct{}) (*myutils.LayerResult, bool, error, bool) {
	// 数据库在线，检查是否已被分析
	if myutils.GlobalDBClient.MongoFlag {
		if lr, err := myutils.GlobalDBClient.Mongo.FindLayerResultByDigest(layer.digest); err == nil {
			return lr, true, nil, false
		}
	}

	layerBeginTime := time.Now()
	lastAnalyzed := myutils.GetLocalNowTimeStr()
	var err error
	var layerGotErr bool

	resLock := sync.Mutex{}
	res := myutils.NewLayerResult()
	res.Instruction = layer.instruction
	res.Size = layer.size
	res.Digest = layer.digest

	wg := sync.WaitGroup{}

	// SCA: 调用Anchore对本地层文件做SCA和漏洞匹配
	wg.Add(1)
	go func(layerRootDir, layerDir string, layerRes *myutils.LayerResult, gotErrFlag *bool) {
		defer wg.Done()

		report, err := scaVul(layerDir, path.Join(layerRootDir, "anchore_result.json"))
		if err != nil {
			myutils.Logger.Error("sca and matches vuln for filepath", layerDir, "failed with:", err.Error())
			*gotErrFlag = true
			return
		}

		// component加入LayerResult
		componentMap := make(map[ComponentMapKey]struct{})
		componentList := make([]*myutils.Component, 0)
		vulnList := make([]*myutils.Vulnerability, 0)
		affectFileList := make([]string, 0)
		for _, match := range report.Matches {
			for _, loc := range match.Artifact.Locations {
				affectFileList = append(affectFileList, loc.Path)
				tmpKey := ComponentMapKey{
					Name:    match.Artifact.Name,
					Version: match.Artifact.Version,
					Path:    loc.Path,
				}

				if _, ok := componentMap[tmpKey]; ok {
					continue
				}

				componentList = append(componentList, &myutils.Component{
					Filename: match.Artifact.Name,
					Codetype: match.Artifact.Language,
					Filepath: loc.Path,
					// FileSha1:    match.Artifact.ID,
					// FileMd5:     match.Artifact.ID,
					FileVersion: match.Artifact.Version,
					OpenSource:  match.Artifact.Type,
				})

				componentMap[tmpKey] = struct{}{}
			}

			cvss := match.Vulnerability.Cvss[0].Metrics.BaseScore
			vulnList = append(vulnList, &myutils.Vulnerability{
				Type:        myutils.IssueType.Vulnerability,
				Name:        match.Vulnerability.ID,
				Part:        myutils.IssuePart.Content,
				Path:        match.Artifact.Locations[0].Path,
				LayerDigest: layer.digest,

				CVEID: match.Vulnerability.ID,
				// Filename:    match.Vulnerability.FileName,
				ProductName: match.Artifact.Name,
				// VendorName:  match.Artifact.VendorName,
				Version: match.Artifact.Version,
				// VulnType: match.Vulnerability.VulnType,
				// ThrType:  match.Vulnerability.ThrType,
				// PublishedTime:   match.Vulnerability.PublishedTime,
				Description:     match.Vulnerability.Description,
				Severity:        match.Vulnerability.Severity,
				CVSSScore:       cvss,
				AffectComponent: []string{match.Artifact.Name},
				AffectFile:      affectFileList,
			})
		}

		// 上锁写入layer
		resLock.Lock()
		defer resLock.Unlock()
		layerRes.Total = len(vulnList)
		layerRes.ComponentNum = len(componentList)
		layerRes.Components = componentList
		layerRes.Vulnerabilities = vulnList
	}(layer.localRootFilePath, layer.localFilePath, res, &layerGotErr)

	// 隐私泄露扫描：调用trufflehog对层的解压文件目录扫描
	wg.Add(1)
	go func(layerRootDir, layerDir string, layerRes *myutils.LayerResult, gotErrFlag *bool) {
		defer wg.Done()

		secrets, err := scanSecretsInFilepath(layerDir)
		if err != nil {
			myutils.Logger.Error("scanSecretsInFilepath", layerDir, "failed with:", err.Error())
			*gotErrFlag = true
			return
		}

		for _, secret := range secrets {
			secret.Part = myutils.IssuePart.Content
			secret.Path = getRelAbsPath(layerDir, secret.TrufflehogResult.SourceMetadata.Data.Filesystem.File)
			secret.LayerDigest = layer.digest
		}

		resLock.Lock()
		defer resLock.Unlock()
		layerRes.SecretLeakages = secrets
	}(layer.localRootFilePath, layer.localFilePath, res, &layerGotErr)

	// 遍历layer目录，发现需要扫描错误配置/恶意软件的文件，并进行相应扫描
	if err = filepath.Walk(layer.localFilePath, analyzer.scanLayerFunc(layer, fileWithIssues, defaultExecFiles, res, &resLock)); err != nil {
		myutils.Logger.Error("walk and scan layer dir", layer.localFilePath, "failed with:", err.Error())
		layerGotErr = true
	}

	wg.Wait()

	// 添加层检测s
	layerAnalyzeTime := time.Since(layerBeginTime).String()
	res.AnalyzeTime = layerAnalyzeTime
	res.LastAnalyzed = lastAnalyzed

	return res, false, err, layerGotErr
}

// analyzeLayerVul 仅用于分析一个layer中的漏洞问题，暂时用不上，因为以前出错的layer注定不存在于layer_results表中
func (analyzer *ImageAnalyzer) analyzeLayerVul(layer *layerInfo, fileWithIssues map[string]bool) (*myutils.LayerResult, bool, error, bool) {
	// 数据库在线，检查是否已被分析
	if myutils.GlobalDBClient.MongoFlag {
		if lr, err := myutils.GlobalDBClient.Mongo.FindLayerResultByDigest(layer.digest); err == nil {
			return lr, true, nil, false
		}
	}

	layerBeginTime := time.Now()
	lastAnalyzed := myutils.GetLocalNowTimeStr()
	var err error
	var layerGotErr bool

	res := myutils.NewLayerResult()
	res.Instruction = layer.instruction
	res.Size = layer.size
	res.Digest = layer.digest

	// SCA: 调用Anchore对本地层文件做SCA和漏洞匹配
	func(layerRootDir, layerDir string, layerRes *myutils.LayerResult, gotErrFlag *bool) {
		report, err := scaVul(layerDir, path.Join(layerRootDir, "anchore_result.json"))
		if err != nil {
			myutils.Logger.Error("sca and matches vuln for filepath", layerDir, "failed with:", err.Error())
			*gotErrFlag = true
			return
		}

		// component加入LayerResult
		componentMap := make(map[ComponentMapKey]struct{})
		componentList := make([]*myutils.Component, 0)
		vulnList := make([]*myutils.Vulnerability, 0)
		affectFileList := make([]string, 0)
		for _, match := range report.Matches {
			for _, loc := range match.Artifact.Locations {
				affectFileList = append(affectFileList, loc.Path)
				tmpKey := ComponentMapKey{
					Name:    match.Artifact.Name,
					Version: match.Artifact.Version,
					Path:    loc.Path,
				}

				if _, ok := componentMap[tmpKey]; ok {
					continue
				}

				componentList = append(componentList, &myutils.Component{
					Filename: match.Artifact.Name,
					Codetype: match.Artifact.Language,
					Filepath: loc.Path,
					// FileSha1:    match.Artifact.ID,
					// FileMd5:     match.Artifact.ID,
					FileVersion: match.Artifact.Version,
					OpenSource:  match.Artifact.Type,
				})

				componentMap[tmpKey] = struct{}{}
			}

			cvss := match.Vulnerability.Cvss[0].Metrics.BaseScore
			vulnList = append(vulnList, &myutils.Vulnerability{
				Type:        myutils.IssueType.Vulnerability,
				Name:        match.Vulnerability.ID,
				Part:        myutils.IssuePart.Content,
				Path:        match.Artifact.Locations[0].Path,
				LayerDigest: layer.digest,

				CVEID: match.Vulnerability.ID,
				// Filename:    match.Vulnerability.FileName,
				ProductName: match.Artifact.Name,
				// VendorName:  match.Artifact.VendorName,
				Version: match.Artifact.Version,
				// VulnType: match.Vulnerability.VulnType,
				// ThrType:  match.Vulnerability.ThrType,
				// PublishedTime:   match.Vulnerability.PublishedTime,
				Description:     match.Vulnerability.Description,
				Severity:        match.Vulnerability.Severity,
				CVSSScore:       cvss,
				AffectComponent: []string{match.Artifact.Name},
				AffectFile:      affectFileList,
			})
		}

		// 没有竞争，无需上锁直接写
		layerRes.Total = len(vulnList)
		layerRes.ComponentNum = len(componentList)
		layerRes.Components = componentList
		layerRes.Vulnerabilities = vulnList
	}(layer.localRootFilePath, layer.localFilePath, res, &layerGotErr)

	// 添加层检测s
	layerAnalyzeTime := time.Since(layerBeginTime).String()
	res.AnalyzeTime = layerAnalyzeTime
	res.LastAnalyzed = lastAnalyzed

	return res, false, err, layerGotErr
}

// scaVul 对层文件进行SCA并进行漏洞匹配
func scaVul(layerDir, dest string) (*AnchoreReport, error) {
	timeout := 1 * time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		myutils.GlobalConfig.AnchoreConfig.Filepath,
		layerDir,
		"--file", dest,
		"--output", "json")
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("scavul with anchore for filepath %s timeout with %s", layerDir, timeout)
	} else if err != nil {
		return nil, err
	}

	report := new(AnchoreReport)
	reportFile, err := os.ReadFile(dest)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(reportFile, report); err != nil {
		return nil, err
	}

	return report, nil
}

// scanLayerFunc 返回一个用于遍历layer目录时扫描文件内容的函数
func (analyzer *ImageAnalyzer) scanLayerFunc(layer *layerInfo, fileWithIssues map[string]bool, defaultExecFiles map[string]struct{}, layerRes *myutils.LayerResult, layerResMu *sync.Mutex) filepath.WalkFunc {
	return func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			myutils.Logger.Error("scan layer file", layer.localFilePath, "failed with:", err.Error())
			return err
		}

		// 跳过文件夹
		if info.IsDir() {
			return nil
		}

		relPath := getRelAbsPath(layer.localFilePath, path)

		// 基于当前状态删除过往扫描记录
		if secretFlag, ok := fileWithIssues[relPath]; ok && !secretFlag {
			delete(fileWithIssues, relPath)
		}

		// 根据文件路径确定扫描内容

		// 配置文件，检测错误配置
		if need, app := misconfiguration.FileNeedScan(relPath); need {
			misConfs, err := misconfiguration.ScanFileMisconfiguration(path, app)
			if err != nil {
				myutils.Logger.Error("scan misconfiguration of app", app, "for file", path, "failed with:", err.Error())
				return err
			}
			for _, misConf := range misConfs {
				misConf.Part = myutils.IssuePart.Content
				misConf.Path = relPath
				misConf.LayerDigest = layer.digest

				layerResMu.Lock()
				layerRes.Misconfigurations = append(layerRes.Misconfigurations, misConf)
				layerResMu.Unlock()
			}
		}

		// 默认执行路径文件，检测恶意性
		// Entry File，检测恶意性
		if _, ok := defaultExecFiles[relPath]; ok {
			malFile, malFlag, err := scanFileMalicious(path)
			if err != nil {
				return err
			}
			if malFlag {
				malFile.Part = myutils.IssuePart.Content
				malFile.Path = relPath
				malFile.LayerDigest = layer.digest

				layerResMu.Lock()
				layerRes.MaliciousFiles = append(layerRes.MaliciousFiles, malFile)
				layerResMu.Unlock()
			}
		}

		return nil
	}
}

func scanFileMalicious(filepath string) (*myutils.MaliciousFile, bool, error) {
	// TODO: generate FileReputation with your own tool
	reputation := FileReputation{}

	if reputation.MalwareName == "" {
		return nil, false, nil
	}

	i := &myutils.MaliciousFile{
		Type:        myutils.IssueType.MaliciousFile,
		Name:        reputation.MalwareName,
		Description: reputation.Describe,
		Severity:    "HIGH",

		Sha256:          reputation.Sha256,
		Level:           reputation.Level,
		MalwareTypeName: reputation.MalwareTypeName,
		FileDesc:        reputation.FileDesc,
		Describe:        reputation.Describe,
		MaliciousFamily: reputation.MaliciousFamily,
		SandboxScore:    reputation.SandboxScore,
	}

	return i, true, nil
}

func getRelAbsPath(layerDir, path string) string {
	relPath, err := filepath.Rel(layerDir, path)
	if err != nil {
		return path
	}
	return "/" + relPath
}
