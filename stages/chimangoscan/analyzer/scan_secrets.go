package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/ChimangoScan/chimangoscan/myutils"
)

// scanSecretsInFilepath 调用trufflehog扫描指定文件路径下的隐私信息
func scanSecretsInFilepath(filepath string) ([]*myutils.SecretLeakage, error) {
	res := make([]*myutils.SecretLeakage, 0)

	timeout := 1 * time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	if myutils.GlobalConfig.TrufflehogConfig.Verify {
		cmd = exec.CommandContext(
			ctx,
			myutils.GlobalConfig.TrufflehogConfig.Filepath,
			"--json",
			"--no-update",
			"filesystem",
			filepath,
		)
	} else {
		cmd = exec.CommandContext(
			ctx,
			myutils.GlobalConfig.TrufflehogConfig.Filepath,
			"--json",
			"--no-update",
			"--no-verification",
			"filesystem",
			filepath,
		)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		myutils.Logger.Error("connect to stdout pipe of cmd", cmd.Path, "failed with:", err.Error())
		return nil, err
	}
	defer stdout.Close()
	if err = cmd.Start(); err != nil {
		myutils.Logger.Error("start cmd", cmd.Path, "failed with:", err.Error())
		return nil, err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		var result myutils.TrufflehogResult
		if err = json.Unmarshal(scanner.Bytes(), &result); err != nil {
			myutils.Logger.Error("json unmarshal trufflehog result failed with:", err.Error())
			continue
		}

		if result.DetectorName == "" {
			continue
		}

		secret := &myutils.SecretLeakage{
			Type:          myutils.IssueType.SecretLeakage,
			Name:          result.DetectorName,
			Match:         result.Raw,
			Severity:      "LOW",
			SeverityScore: 3,

			TrufflehogResult: result,
		}
		res = append(res, secret)
	}

	if err = cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			myutils.Logger.Error(fmt.Sprintf("wait for cmd exec %s failed with: timeout %s", cmd.Path, timeout))
		}
		myutils.Logger.Error("wait for cmd exec", cmd.Path, "failed with:", err.Error())
		return nil, err
	}

	return res, nil
}

// Deprecated
// 改为直接依赖trufflehog工具实现

//func FileNeedScanSecrets(filepath string) bool {
//	// 判断文件类型是否为text
//	file, err := os.Open(filepath)
//	if err != nil {
//		return false
//	}
//	defer file.Close()
//
//	buffer := make([]byte, 512)
//	_, err = file.Read(buffer)
//	if err != nil && err != io.EOF {
//		return false
//	}
//
//	mimeType := http.DetectContentType(buffer)
//	fmt.Println(mimeType)
//	isText := false
//	if len(mimeType) >= 5 && mimeType[:5] == "text/" {
//		isText = true
//	}
//
//	if !isText {
//		return false
//	}
//
//	// 根据文件路径判断是否需要检测
//
//	return false
//}

//func (analyzer *ImageAnalyzer) scanSecretsInFile(filepath string) ([]*myutils.SecretLeakage, error) {
//	content, err := os.ReadFile(filepath)
//	if err != nil {
//		return nil, err
//	}
//
//	return analyzer.scanSecretsInBytes(content), nil
//}
//
//func (analyzer *ImageAnalyzer) scanSecretsInString(s string) []*myutils.SecretLeakage {
//	res := make([]*myutils.SecretLeakage, 0)
//
//	for _, secret := range analyzer.rules.SecretRules {
//		if secret.CompiledRegex == nil {
//			continue
//		}
//		matches := secret.CompiledRegex.FindAllString(s, -1)
//		for _, match := range matches {
//			tmp := &myutils.SecretLeakage{
//				Type:          myutils.IssueType.SecretLeakage,
//				Name:          secret.Name,
//				Match:         match,
//				Description:   secret.Description,
//				Severity:      secret.Severity,
//				SeverityScore: secret.SeverityScore,
//			}
//			res = append(res, tmp)
//		}
//	}
//
//	return res
//}
//
//func (analyzer *ImageAnalyzer) scanSecretsInBytes(b []byte) []*myutils.SecretLeakage {
//	res := make([]*myutils.SecretLeakage, 0)
//
//	for _, secret := range analyzer.rules.SecretRules {
//		if secret.CompiledRegex == nil {
//			continue
//		}
//		matches := secret.CompiledRegex.FindAll(b, -1)
//		for _, match := range matches {
//			tmp := &myutils.SecretLeakage{
//				Type:          myutils.IssueType.SecretLeakage,
//				Name:          secret.Name,
//				Match:         string(match),
//				Description:   secret.Description,
//				Severity:      secret.Severity,
//				SeverityScore: secret.SeverityScore,
//			}
//			res = append(res, tmp)
//		}
//	}
//
//	return res
//}
