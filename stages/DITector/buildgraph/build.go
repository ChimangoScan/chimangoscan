package buildgraph

import "github.com/anonymous/DITector/myutils"

type GraphJob struct {
	Registry      string
	RepoNamespace string
	RepoName      string
	TagName       string
	ImageMeta     *myutils.Image
}

func Build(format string, threshold int64, workers int, ip myutils.IdentityProvider, dataDir string) {
	config(format)
	switch format {
	case "mongo":
		StartFromMongo(threshold, workers, ip, dataDir)
	}
}
