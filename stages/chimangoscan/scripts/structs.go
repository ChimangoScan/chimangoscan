package scripts

type RecordWithNodeID struct {
	Namespace            string `json:"namespace"`
	RepositoryName       string `json:"repository_name"`
	TagName              string `json:"tag_name"`
	ImageDigest          string `json:"image_digest"`
	NodeId               string
	UpstreamImageCount   int      `json:"upstream_image_count"`
	UpstreamImageList    []string `json:"upstream_image_list"`
	DownstreamImageCount int      `json:"downstream_image_count"`
	DownstreamImageList  []string `json:"downstream_image_list"`
}

type InputImage struct {
	Namespace string `json:"namespace"`
	RepoName  string `json:"repository_name"`
	TagName   string `json:"tag_name"`
	Digest    string `json:"digest"`
}

type ImageWithDownstream struct {
	RepoNamespace    string   `json:"repository_namespace"`
	RepoName         string   `json:"repository_name"`
	TagName          string   `json:"tag_name"`
	ImageDigest      string   `json:"image_digest"`
	DownstreamCount  int      `json:"downstream_count"`
	DownstreamImages []string `json:"downstream_images"`
}
