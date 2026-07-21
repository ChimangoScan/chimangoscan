package myutils

// ImageResult is used to store analysis result
type ImageResult struct {
	Name         string `json:"name" bson:"name"`
	Registry     string `json:"registry" bson:"registry"`
	Namespace    string `json:"namespace" bson:"namespace"`
	RepoName     string `json:"repository_name" bson:"repository_name"`
	TagName      string `json:"tag_name" bson:"tag_name"`
	Digest       string `json:"digest" bson:"digest"`
	Architecture string `json:"architecture" bson:"architecture"`
	Variant      string `json:"variant" bson:"variant"`
	OS           string `json:"os" bson:"os"`
	OSVersion    string `json:"os_version" bson:"os_version"`

	LastAnalyzed string `json:"last_analyzed" bson:"last_analyzed"`
	TotalTime    string `json:"total_time" bson:"total_time"`
	AnalyzeTime  string `json:"analyze_time" bson:"analyze_time"`

	MetadataAnalyzed bool            `json:"metadata_analyzed" bson:"metadata_analyzed"`
	MetadataResult   *MetadataResult `json:"metadata_result" bson:"metadata_result"`

	ConfigurationAnalyzed bool                 `json:"configuration_analyzed" bson:"configuration_analyzed"`
	ConfigurationResult   *ConfigurationResult `json:"configuration_result" bson:"configuration_result"`

	ContentAnalyzed bool `json:"content_analyzed" bson:"content_analyzed"`
	// Layers: [ layer-id1, layer-id2, ... ], from bottom to top
	Layers []string `json:"layers" bson:"layers"`
	// LayerResults: layer-id -> LayerResult
	LayerResults map[string]*LayerResult `json:"-" bson:"-"`
	// FileWithIssues: filepath -> bool, true: 文件包含问题为隐私泄露，false:文件包含问题不是隐私泄露
	//FileWithIssues map[string]bool `json:"-"`
	ContentResult *ContentResult `json:"content_result" bson:"content_result"`
}

type MetadataResult struct {
	SecretLeakages    []*SecretLeakage    `json:"secret_leakages" bson:"secret_leakages"`
	SensitiveParams   []*SensitiveParam   `json:"sensitive_params" bson:"sensitive_params"`
	InstalledContents []*InstalledContent `json:"installed_contents" bson:"installed_contents"`
}

type ConfigurationResult struct {
	SecretLeakages []*SecretLeakage `json:"secret_leakages" bson:"secret_leakages"`
}

type ContentResult struct {
	Components []*Component `json:"components" bson:"components"`

	SecretLeakages    []*SecretLeakage    `json:"secret_leakages" bson:"secret_leakages"`
	Vulnerabilities   []*Vulnerability    `json:"vulnerabilities" bson:"vulnerabilities"`
	Misconfigurations []*Misconfiguration `json:"misconfigurations" bson:"misconfigurations"`
	MaliciousFiles    []*MaliciousFile    `json:"malicious_files" bson:"malicious_files"`

	LayersGotErr []string `json:"layers_got_err" bson:"layers_got_err"`
}

type LayerResult struct {
	Instruction string `bson:"instruction"`
	Size        int64  `bson:"size"`
	Digest      string `bson:"digest"`

	LastAnalyzed string `bson:"last_analyzed"`
	AnalyzeTime  string `bson:"analyze_time"`

	Total        int
	ComponentNum int
	Components   []*Component

	SecretLeakages    []*SecretLeakage
	Vulnerabilities   []*Vulnerability
	Misconfigurations []*Misconfiguration
	MaliciousFiles    []*MaliciousFile
}

// InstalledContent 记录layer instruction中通过pip install, npm install, wget下载的内容
type InstalledContent struct {
	Source        string   `json:"source" bson:"source"`   // 内容来源，pip, npm, wget, add
	Command       string   `json:"command" bson:"command"` // 安装命令，pip install, npm install, wget, add
	Name          string   `json:"name" bson:"name"`
	VersionLimits []string `json:"version_limits" bson:"version_limits"`
	Instruction   string   `json:"instruction" bson:"instruction"` // layer instruction
	LayerDigest   string   `json:"layer_digest" bson:"layer_digest"`
	Description   string   `json:"description" bson:"description"`
	Severity      string   `json:"severity" bson:"severity"`
	SeverityScore float64  `json:"severity_score" bson:"severity_score"`
}

type Component struct {
	Filename    string `json:"filename" bson:"filename"`
	Codetype    string `json:"codetype" bson:"codetype"`
	Filepath    string `json:"filepath" bson:"filepath"`
	FileSha1    string `json:"file_sha1" bson:"file_sha1"`
	FileMd5     string `json:"file_md5" bson:"file_md5"`
	FileVersion string `json:"file_version" bson:"file_version"`
	OpenSource  string `json:"open_source" bson:"open_source"`
}

func NewImageResult() *ImageResult {
	ir := new(ImageResult)

	ir.MetadataResult = NewMetadataResult()
	ir.ConfigurationResult = NewConfigurationResult()
	ir.Layers = make([]string, 0)
	ir.LayerResults = make(map[string]*LayerResult)
	//ir.FileWithIssues = make(map[string]bool)
	ir.ContentResult = NewContentResult()

	return ir
}

func NewMetadataResult() *MetadataResult {
	res := new(MetadataResult)

	res.SecretLeakages = make([]*SecretLeakage, 0)
	res.SensitiveParams = make([]*SensitiveParam, 0)
	res.InstalledContents = make([]*InstalledContent, 0)

	return res
}

func NewConfigurationResult() *ConfigurationResult {
	res := new(ConfigurationResult)

	res.SecretLeakages = make([]*SecretLeakage, 0)

	return res
}

func NewContentResult() *ContentResult {
	res := new(ContentResult)

	res.Components = make([]*Component, 0)

	res.SecretLeakages = make([]*SecretLeakage, 0)
	res.Vulnerabilities = make([]*Vulnerability, 0)
	res.Misconfigurations = make([]*Misconfiguration, 0)
	res.MaliciousFiles = make([]*MaliciousFile, 0)

	res.LayersGotErr = make([]string, 0)

	return res
}

func NewLayerResult() *LayerResult {
	res := new(LayerResult)

	res.Components = make([]*Component, 0)

	res.SecretLeakages = make([]*SecretLeakage, 0)
	res.Vulnerabilities = make([]*Vulnerability, 0)
	res.Misconfigurations = make([]*Misconfiguration, 0)
	res.MaliciousFiles = make([]*MaliciousFile, 0)

	return res
}

type SecretLeakage struct {
	Type             string           `json:"type" bson:"type"`
	Name             string           `json:"name" bson:"name"`
	Part             string           `json:"part" bson:"part"` // part of image: metadata, configuration, content
	Path             string           `json:"path" bson:"path"`
	Match            string           `json:"match" bson:"match"`
	Description      string           `json:"description" bson:"description"`
	Severity         string           `json:"severity" bson:"severity"`
	SeverityScore    float64          `json:"severity_score" bson:"severity_score"`
	LayerDigest      string           `json:"layer_digest,omitempty" bson:"layer_digest,omitempty"`
	TrufflehogResult TrufflehogResult `json:"trufflehog_result" bson:"trufflehog_result"`
}

type TrufflehogResult struct {
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file" bson:"file"`
				Line int    `json:"line" bson:"line"`
			} `json:"Filesystem" bson:"Filesystem"`
		} `json:"Data" bson:"Data"`
	} `json:"SourceMetadata" bson:"SourceMetadata"`
	SourceID     int    `json:"SourceID" bson:"SourceID"`
	SourceType   int    `json:"SourceType" bson:"SourceType"`
	SourceName   string `json:"SourceName" bson:"SourceName"`
	DetectorType int    `json:"DetectorType" bson:"DetectorType"`
	DetectorName string `json:"DetectorName" bson:"DetectorName"`
	DecoderName  string `json:"DecoderName" bson:"DecoderName"`
	Verified     bool   `json:"Verified" bson:"Verified"`
	Raw          string `json:"Raw" bson:"Raw"`
	RawV2        string `json:"RawV2" bson:"RawV2"`
	Redacted     string `json:"Redacted" bson:"Redacted"`
	ExtraData    struct {
		RotationGuide string `json:"rotation_guide" bson:"rotation_guide"`
	} `json:"ExtraData" bson:"ExtraData"`
	StructuredData interface{} `json:"StructuredData" bson:"StructuredData"`
}

type SensitiveParam struct {
	Type          string  `json:"type" bson:"type"`
	Name          string  `json:"name" bson:"name"`
	Part          string  `json:"part" bson:"part"` // part of image: metadata, configuration, content
	Path          string  `json:"path" bson:"path"`
	Match         string  `json:"match" bson:"match"`
	RawCmd        string  `json:"raw_cmd" bson:"raw_cmd"`
	SensitiveType string  `json:"sensitive_type" bson:"sensitive_type"`
	Description   string  `json:"description" bson:"description"`
	Severity      string  `json:"severity" bson:"severity"`
	SeverityScore float64 `json:"severity_score" bson:"severity_score"`
}

type Vulnerability struct {
	Type        string `json:"type" bson:"type"`
	Name        string `json:"name" bson:"name"`
	Part        string `json:"part" bson:"part"` // part of image: metadata, configuration, content
	Path        string `json:"path" bson:"path"`
	LayerDigest string `json:"layer_digest" bson:"layer_digest"`

	CVEID           string   `json:"cve_id" bson:"cve_id"`
	Filename        string   `json:"filename" bson:"filename"`
	ProductName     string   `json:"product_name" bson:"product_name"`
	VendorName      string   `json:"vendor_name" bson:"vendor_name"`
	Version         string   `json:"version" bson:"version"`
	VulnType        string   `json:"vuln_type" bson:"vuln_type"`
	ThrType         string   `json:"thr_type" bson:"thr_type"`
	PublishedTime   string   `json:"published_time" bson:"published_time"`
	Description     string   `json:"description" bson:"description"`
	Severity        string   `json:"severity" bson:"severity"`
	CVSSScore       float64  `json:"cvss_score" bson:"cvss_score"`
	AffectComponent []string `json:"affect_component" bson:"affect_component"`
	AffectFile      []string `json:"affect_file" bson:"affect_file"`
}

type Misconfiguration struct {
	Type          string  `json:"type" bson:"type"`
	AppName       string  `json:"app_name" bson:"app_name"`
	MisConfType   string  `json:"mis_conf_type" bson:"mis_conf_type"`
	Part          string  `json:"part" bson:"part"` // part of image: metadata, configuration, content
	Path          string  `json:"path" bson:"path"`
	Match         string  `json:"match" bson:"match"`
	Description   string  `json:"description" bson:"description"`
	Severity      string  `json:"severity" bson:"severity"`
	SeverityScore float64 `json:"severity_score" bson:"severity_score"`
	LayerDigest   string  `json:"layer_digest" bson:"layer_digest"`
}

type MaliciousFile struct {
	Type          string  `json:"type" bson:"type"`
	Name          string  `json:"name" bson:"name"`
	Part          string  `json:"part" bson:"part"` // part of image: metadata, configuration, content
	Path          string  `json:"path" bson:"path"`
	Description   string  `json:"description" bson:"description"`
	Severity      string  `json:"severity" bson:"severity"`
	SeverityScore float64 `json:"severity_score" bson:"severity_score"`
	LayerDigest   string  `json:"layer_digest" bson:"layer_digest"`

	Sha256          string  `json:"sha256" bson:"sha256"` // sha256 of file, only for malicious file
	Level           int     `json:"level" bson:"level"`
	MalwareTypeName string  `json:"malware_type_name" bson:"malware_type_name"`
	FileDesc        string  `json:"file_desc" bson:"file_desc"`
	Describe        string  `json:"describe" bson:"describe"`
	MaliciousFamily string  `json:"malicious_family" bson:"malicious_family"`
	SandboxScore    float64 `json:"sandbox_score" bson:"sandbox_score"`
}

type ImgResultUniqueField struct {
	Registry  string `json:"registry" bson:"registry"`
	Namespace string `json:"namespace" bson:"namespace"`
	RepoName  string `json:"repository_name" bson:"repository_name"`
	TagName   string `json:"tag_name" bson:"tag_name"`
	Digest    string `json:"digest" bson:"digest"`
}

var IssueType = struct {
	SecretLeakage    string
	SensitiveParam   string
	Vulnerability    string
	Misconfiguration string
	MaliciousFile    string
}{
	"secret-leakage",
	"sensitive-parameter",
	"vulnerability",
	"misconfiguration",
	"malicious-file",
}

var IssuePart = struct {
	RepoMetadata  string
	TagMetadata   string
	ImageMetadata string
	Configuration string
	Content       string
}{
	"repository-metadata",
	"tag-metadata",
	"image-metadata",
	"configuration",
	"content",
}
