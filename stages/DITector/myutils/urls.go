package myutils

import (
	"fmt"
)

const (
	RegURLTemplate                = `https://hub.docker.com/api/content/v1/products/search?q=%s&source=%s&page=%s&page_size=%s`
	NamespaceURLTemplate          = `https://hub.docker.com/v2/repositories/%s?page=%s&page_size=%s&ordering=last_updated`
	RepositoryMetadataURLTemplate = `https://hub.docker.com/v2/repositories/%s/%s/`
	RepoTagsURLTemplate           = `https://hub.docker.com/v2/repositories/%s/%s/tags/?page=%d&page_size=%d`
	TagMetadataURLTemplate        = `https://hub.docker.com/v2/repositories/%s/%s/tags/%s`
	ImageMetadataURLTemplate      = `https://hub.docker.com/v2/repositories/%s/%s/tags/%s/images`
	V2SearchURLTemplate           = `https://hub.docker.com/v2/search/repositories/?query=%s&page=%d&page_size=%d`
)

// GetRegURL 返回用于获取repository list的URL
//
// GetRegURL 要求query参数至少包含2个字符。
// 以query为关键字，获取相关repository list的JSON格式响应，最大响应结果数目为10000。
// source可选范围: official, community, publisher(可能要求url中的q换为query)。
func GetRegURL(query, source, page, size string) string {
	return fmt.Sprintf(RegURLTemplate, query, source, page, size)
}

// GetNamespaceURL 返回用于获取namespace下repository list的URL
//
// namespace为DockerHub Register下的用户名。
func GetNamespaceURL(namespace, page, size string) string {
	return fmt.Sprintf(NamespaceURLTemplate, namespace, page, size)
}

// GetRepositoryMetadataURL 返回Repository的元数据URL
//
// 主要包括star_count, pull_count, 最近更新时间等。
func GetRepositoryMetadataURL(namespace, repo string) string {
	return fmt.Sprintf(RepositoryMetadataURLTemplate, namespace, repo)
}

// GetRepoTagsURL 返回Repository TagName List的URL
//
// 主要包括Tag数量，以及每个Tag的digest、最近拉取时间、最近更新时间等。
func GetRepoTagsURL(namespace, repo string, page, size int) string {
	return fmt.Sprintf(RepoTagsURLTemplate, namespace, repo, page, size)
}

// GetTagMetadataURL 返回指定Image(Repo:TagName)的元数据URL
//
// 内容与GetRepoTagsURL中对每个Tag单独的描述完全一致，可以略过
func GetTagMetadataURL(namespace, repo, tag string) string {
	return fmt.Sprintf(TagMetadataURLTemplate, namespace, repo, tag)
}

// GetImageMetadataURL 返回指定Image(Repo:TagName)的Layer URL
//
// 主要包括镜像包含的构建信息，即各层的digest、构建命令等。
// 对于支持多种内核架构的Tag，会以列表形式记录每个架构下的构建信息。
func GetImageMetadataURL(namespace, repo, tag string) string {
	return fmt.Sprintf(ImageMetadataURLTemplate, namespace, repo, tag)
}

// GetV2SearchURL returns the official V2 search API URL
func GetV2SearchURL(query string, page, size int) string {
	return fmt.Sprintf(V2SearchURLTemplate, query, page, size)
}
