package analyzer

import "github.com/ChimangoScan/DITector/myutils"

func (analyzer *ImageAnalyzer) scanSensitiveParamInString(s string) []*myutils.SensitiveParam {
	res := make([]*myutils.SensitiveParam, 0)

	for _, sensitive := range analyzer.rules.SensitiveParamRules {
		matches := sensitive.CompiledRegex.FindAllString(s, -1)
		for _, match := range matches {
			tmp := &myutils.SensitiveParam{
				Type:          myutils.IssueType.SensitiveParam,
				Name:          sensitive.Name,
				Match:         match,
				RawCmd:        s,
				SensitiveType: sensitive.SensitiveType,
				Description:   sensitive.Description,
				Severity:      sensitive.Severity,
				SeverityScore: sensitive.SeverityScore,
			}
			res = append(res, tmp)
		}
	}

	return res
}
