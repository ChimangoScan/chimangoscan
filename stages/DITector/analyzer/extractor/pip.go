package extractor

import (
	"regexp"
	"strings"
)

var pipOptionsWithArgs = map[string]string{
	"-r":                 "requirement",
	"--requirement":      "requirement",
	"-c":                 "constraint",
	"--constraint":       "constraint",
	"-e":                 "editable",
	"--editable":         "editable",
	"-t":                 "target",
	"--target":           "target",
	"-b":                 "build",
	"--build":            "build",
	"--platform":         "platform",
	"--python-version":   "python-version",
	"--implementation":   "implementation",
	"--abi":              "abi",
	"--root":             "root",
	"--prefix":           "prefix",
	"--src":              "src",
	"--upgrade-strategy": "upgrade-strategy",
	"--install-option":   "install-option",
	"-C":                 "config-settings",
	"--config-settings":  "config-settings",
	"--global-option":    "global-option",
	"--no-binary":        "no-binary",
	"--only-binary":      "only-binary",
	"--progress-bar":     "progress-bar",
	"--root-user-action": "root-user-action",
	"--report":           "report",
	"-i":                 "index-url",
	"--index-url":        "index-url",
	"--extra-index-url":  "extra-index-url",
	"-f":                 "find-links",
	"--find-links":       "find-links",
}

// pipInstallVersionSpecifiers PEP440中指定的版本比较符号
var pipInstallVersionSpecifiers = []string{
	"~=", "==", "!=", "<=", ">=", "<", ">", "===",
}

// pipInstallRe 用于从layer instruction中提取出pip install完整命令。
// golang regexp不支持lookahead/lookbehind assertion。
// var pipInstallRe = regexp.MustCompile(`pip\s+install\s+.*?(?=&&|\n|$)`)
var pipInstallRe = regexp.MustCompile(`(pip\s+install\s+.*?)(?:&&|\n|$)`)

// pipInstallArgsRe 用于检查是否是pip install命令
var pipInstallArgsRe = regexp.MustCompile(`^pip\s+install\s+(.*)`)

// CheckPipInstallCmd 检查命令字符串中是否存在完整的pip install命令
func CheckPipInstallCmd(instruction string) bool {
	return pipInstallRe.MatchString(instruction)
}

// ExtractPipInstallCmdsFromString 从image layer instruction中提取出全部pip install完整命令
func ExtractPipInstallCmdsFromString(instruction string) []string {
	res := make([]string, 0)
	matches := pipInstallRe.FindAllStringSubmatch(instruction, -1)
	for _, match := range matches {
		res = append(res, match[1])
	}
	return res
}

// ParsePipInstallCmdArgs 解析pip install命令中的所有参数。
// 其中"_name" -> map[string][]string 用于记录每个python包的package name以及对应的版本要求。
func ParsePipInstallCmdArgs(cmd string) map[string]any {
	cmds := pipInstallArgsRe.FindStringSubmatch(cmd)
	if len(cmds) <= 1 {
		return nil
	}
	cmd = cmds[1]

	args := make(map[string]interface{})
	args["_name"] = make(map[string][]string)

	words := strings.Split(cmd, " ")
	consumption := false
	lastArgName := ""
	lastPackageName := ""
	for _, word := range words {
		// 跳过多个空格之间的内容
		if word == "" {
			continue
		}
		word = strings.Trim(word, `"`)
		word = strings.Trim(word, `'`)
		if strings.HasPrefix(word, "--") {
			// 由等于号赋值的部分直接把值写到表中
			tmp := strings.Split(word, "=")
			if len(tmp) > 1 {
				key := strings.TrimLeft(tmp[0], "-")
				if key == "_name" {
					continue
				}
				val := tmp[1]
				args[key] = val
			} else {
				// 非等于号赋值的部分，检查是否是有值参数
				if t, ok := pipOptionsWithArgs[word]; ok {
					// 有值参数要消费掉下一个输入内容
					consumption = true
					lastArgName = t
				} else {
					// 不是有值参数，直接作为bool存入
					key := strings.TrimLeft(word, "-")
					if key == "_name" {
						continue
					}
					args[key] = true
				}
			}
		} else if strings.HasPrefix(word, "-") {
			// 检查是否是有值参数
			if t, ok := pipOptionsWithArgs[word]; ok {
				consumption = true
				lastArgName = t
			} else {
				key := strings.TrimLeft(word, "-")
				if key == "_name" {
					continue
				}
				args[key] = true
			}
		} else {
			// 需要被消费的内容，直接将当前值存入上一个参数中
			if consumption {
				if lastArgName != "" {
					// 上一个需要传值的参数
					args[lastArgName] = word
					// 取消消费状态
					consumption = false
					lastArgName = ""
					continue
				} else if lastPackageName != "" {
					// 上一个package的版本限制
					commas := strings.Split(word, ",")
					if len(commas) > 1 {
						for i, _ := range commas {
							if i == len(commas)-1 {
								if commas[i] == "" {
									break
								} else {
									args["_name"].(map[string][]string)[lastPackageName] = append(args["_name"].(map[string][]string)[lastPackageName], commas[i])
									// 取消消费状态
									consumption = false
									lastPackageName = ""
									break
								}
							} else {
								args["_name"].(map[string][]string)[lastPackageName] = append(args["_name"].(map[string][]string)[lastPackageName], commas[i])
							}
						}
					} else {
						args["_name"].(map[string][]string)[lastPackageName] = append(args["_name"].(map[string][]string)[lastPackageName], word)
						// 取消消费状态
						consumption = false
						lastPackageName = ""
						continue
					}
				}
			} else {
				// 不是消费内容的属于package name部分
				// 检查有没有逗号
				commas := strings.Split(word, ",")
				if len(commas) > 1 {
					for i, _ := range commas {
						// 第一个位置需要package name
						if i == 0 {
							for _, spec := range pipInstallVersionSpecifiers {
								if strings.Contains(commas[i], spec) {
									specPos := strings.Index(commas[i], spec)
									packageName := commas[i][0:specPos]
									args["_name"].(map[string][]string)[packageName] = make([]string, 0)
									specLimit := commas[i][specPos:]
									args["_name"].(map[string][]string)[packageName] = append(args["_name"].(map[string][]string)[packageName], specLimit)

									lastPackageName = packageName
									break
								}
							}
						} else if i == len(commas)-1 {
							// 最后一个位置为空，以逗号结尾
							if commas[i] == "" {
								consumption = true
							} else {
								// 不以逗号结尾
								args["_name"].(map[string][]string)[lastPackageName] = append(args["_name"].(map[string][]string)[lastPackageName], commas[i])
								lastPackageName = ""
							}
						} else {
							// 中间位置直接加入
							args["_name"].(map[string][]string)[lastPackageName] = append(args["_name"].(map[string][]string)[lastPackageName], commas[i])
						}
					}
				} else {
					// 其他部分正常检查package name和版本限制
					hasSpec := false
					for _, spec := range pipInstallVersionSpecifiers {
						if strings.Contains(word, spec) {
							hasSpec = true
							specPos := strings.Index(word, spec)
							packageName := word[0:specPos]
							args["_name"].(map[string][]string)[packageName] = make([]string, 0)
							specLimit := word[specPos:]
							args["_name"].(map[string][]string)[packageName] = append(args["_name"].(map[string][]string)[packageName], specLimit)
							break
						}
					}
					if !hasSpec {
						args["_name"].(map[string][]string)[word] = make([]string, 0)
					}
				}
			}
		}
	}

	return args
}
