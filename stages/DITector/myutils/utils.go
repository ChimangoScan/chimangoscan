package myutils

import (
	"archive/tar"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

var shanghai, _ = time.LoadLocation("Asia/Shanghai")

func GetLocalNowTime() time.Time {
	return time.Now().In(shanghai)
}

func GetLocalNowTimeStr() string {
	return time.Now().In(shanghai).Format(time.DateTime)
}

func GetLocalNowTimeNoSpace() string {
	return time.Now().In(shanghai).Format("20060102T150405")
}

// 生成n位随机字符串
func GetRandStr(n int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, n)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < n; i++ {
		result[i] = str[r.Intn(len(str))]
	}
	return string(result)
}

func Md5Str(s string) string {
	hash := md5.Sum([]byte(s))
	return hex.EncodeToString(hash[:])
}

// Sha256Str 对字符串计算sha256，并返回string
func Sha256Str(s string) string {
	tmpHash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(tmpHash[:])
}

// Sha256File 计算文件sha256哈希值
func Sha256File(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// StrLegalForRepository check whether string s is legal for repository search
func StrLegalForRepository(s string) bool {
	match, _ := regexp.MatchString(`^[a-zA-Z0-9:\-]*$`, s)
	return match
}

// StrLegalForImage check whether string s is legal for image search
func StrLegalForImage(s string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z0-9:]*$", s)
	return match
}

// DivideImageName 拆解镜像名称，[registry/][namespace/]repository[:tag][@digest]
func DivideImageName(name string) (registry, namespace, repository, tag, digest string) {
	// obtain digest by splitting by "@"
	digestParts := strings.Split(name, "@")
	// 这个digest未必是系统中约束的image digest，也可能是tag digest
	// 系统的image digest应是从元数据中匹配得到的
	if len(digestParts) == 2 {
		digest = digestParts[1]
	}

	// obtain tag by splitting by ":"
	nameParts := strings.Split(digestParts[0], ":")
	switch len(nameParts) {
	case 1:
		tag = "latest"
	case 2:
		tag = nameParts[1]
	}

	// obtain registry, namespace, repository by splitting by "/"
	repoParts := strings.Split(nameParts[0], "/")
	switch len(repoParts) {
	case 1:
		registry = "docker.io"
		namespace = "library"
		repository = repoParts[0]
	case 2:
		registry = "docker.io"
		namespace = repoParts[0]
		repository = repoParts[1]
	case 3:
		registry = repoParts[0]
		namespace = repoParts[1]
		repository = repoParts[2]
	}

	return
}

// ExtractTar extracts tar file to specific dst dir,
// creating recursively when dir not exists.
func ExtractTar(src, dst string) error {
	// 打开tar文件
	tarFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer tarFile.Close()

	// 创建目标文件夹
	if err = os.MkdirAll(dst, 0750); err != nil {
		return err
	}

	// 创建Tar读取器
	tr := tar.NewReader(tarFile)

	// 逐个解压文件
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // 所有文件已解压
		}
		if err != nil {
			return err
		}

		// 创建目标文件
		targetFile := path.Join(dst, header.Name)
		info := header.FileInfo()

		// 如果是文件夹，创建目录
		if info.IsDir() {
			if err = os.MkdirAll(targetFile, 0750); err != nil {
				return err
			}
			continue
		}

		// 如果是文件，创建文件并写入数据
		// 不再根据原有文件权限创建文件，容易报错
		file, err := os.Create(targetFile)
		//file, err := os.OpenFile(targetFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(file, tr)
		if err != nil {
			// 跳过权限不足的文件
			if os.IsPermission(err) {
				continue
			}
			return err
		}
	}

	return nil
}

// RepoNameRecordFile 每行用来记录一个镜像名
type RepoNameRecordFile struct {
	file *os.File
	lock sync.Mutex
}

func NewRepoNameRecordFile(filepath string) (*RepoNameRecordFile, error) {
	var err error
	rnf := new(RepoNameRecordFile)
	rnf.file, err = os.OpenFile(filepath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0744)
	if err != nil {
		Logger.Error("open repo name record file", filepath, "failed with:", err.Error())
		return nil, err
	}
	rnf.lock = sync.Mutex{}
	return rnf, nil
}

func (rnf *RepoNameRecordFile) Write(ss ...string) {
	rnf.lock.Lock()
	defer rnf.lock.Unlock()
	rnf.file.WriteString(strings.Join(ss, " ") + "\n")
}
