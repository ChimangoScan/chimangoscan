package myutils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// 创建一个文件用于记录tag数目过多的repo名称（目前以10000为阈值）
var repoNameWithManyTagsFile *RepoNameRecordFile

// httpClient is shared across all goroutines. Keep-alives enabled so TCP
// connections are reused — critical for throughput since each new connection
// requires a TCP handshake + TLS negotiation (~100-300ms each).
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        300,
		MaxIdleConnsPerHost: 50,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	},
}

// configEnvHTTPProxy configures http and https proxy.
func configEnvHTTPProxy(httpProxy, httpsProxy string) {
	if httpProxy != "" {
		os.Setenv("http_proxy", httpProxy)
	}
	if httpsProxy != "" {
		os.Setenv("https_proxy", httpsProxy)
	}
}

// configTLSConfig configures not to verify CA for https protocol.
func configTLSConfig() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

// ReqRepoMetadata gets repository metadata by calling Docker Hub API.
func ReqRepoMetadata(namespace, name string) (*Repository, error) {
	rMeta := new(Repository)

	url := GetRepositoryMetadataURL(namespace, name)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查http响应状态
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request %s got unexpected resp status code: %d", url, resp.StatusCode)
	}

	limitStr := resp.Header.Get("X-Ratelimit-Remaining")
	Logger.Debug("get repo metadata from API:", url, ", remained limit:", limitStr)

	repoBuf := bytes.Buffer{}
	_, err = io.Copy(&repoBuf, resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(repoBuf.Bytes(), rMeta)
	if err != nil {
		return nil, err
	}

	// 处理404
	if rMeta.Name == "" {
		return nil, fmt.Errorf("docker hub resp 404 to repo %s/%s", namespace, name)
	}

	// 根据limit控制返回节奏
	if limit, e := strconv.Atoi(limitStr); e == nil {
		if limit <= 20 {
			time.Sleep(20 * time.Second)
		}
	}

	return rMeta, nil
}

// ReqTagMetadata gets tag metadata by calling Docker Hub API.
func ReqTagMetadata(repoNamespace, repoName, name string) (*Tag, error) {
	tMeta := new(Tag)

	url := GetTagMetadataURL(repoNamespace, repoName, name)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查http响应状态
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request %s got unexpected resp status code: %d", url, resp.StatusCode)
	}

	// 对正常API报resp 0 tag错误的时候limitStr是空！！？？
	limitStr := resp.Header.Get("X-Ratelimit-Remaining")
	Logger.Debug("get tag metadata from API:", url, ", remained limit:", limitStr)

	var tagBuf bytes.Buffer
	_, err = io.Copy(&tagBuf, resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(tagBuf.Bytes(), tMeta)
	if err != nil {
		return nil, err
	}

	// 处理404
	if tMeta.Name == "" {
		return nil, fmt.Errorf("docker hub resp 404 to tag %s/%s:%s", repoNamespace, repoName, name)
	}

	tMeta.RepositoryNamespace = repoNamespace
	tMeta.RepositoryName = repoName

	// 利用limit控制返回节奏
	if limit, e := strconv.Atoi(limitStr); e == nil {
		if limit <= 20 {
			time.Sleep(20 * time.Second)
		}
	}

	return tMeta, err
}

// ReqTagsMetadata 利用Docker Hub API获取指定页的tag元数据
func ReqTagsMetadata(repoNamespace, repoName string, page, pageSize int) ([]*Tag, error) {
	pageResult := new(TagsPage)
	res := make([]*Tag, 0)

	url := GetRepoTagsURL(repoNamespace, repoName, page, pageSize)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查http响应状态
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request %s got unexpected resp status code: %d", url, resp.StatusCode)
	}

	limitStr := resp.Header.Get("X-Ratelimit-Remaining")
	Logger.Debug("get tags metadata from API:", url, ", remained limit:", limitStr)
	if limitStr == "" {
		return nil, fmt.Errorf("request API: %s got empty X-Ratelimit-Remaining", limitStr)
	}

	// body, err := io.ReadAll(resp.Body)
	tagsBuf := bytes.Buffer{}
	_, err = io.Copy(&tagsBuf, resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(tagsBuf.Bytes(), pageResult)
	if err != nil {
		return nil, err
	}

	if pageResult.Count == 0 && len(pageResult.Results) == 0 {
		// TODO: 频繁报这个错？？？？？？事实上手动查看还经常是正常响应的？？？？？？
		return nil, fmt.Errorf("docker hub resp 0 tag to repo %s/%s", repoNamespace, repoName)
	} else if pageResult.Count > 10000 {
		// 记录tag过多的镜像名
		repoNameWithManyTagsFile.Write("repo with tags over 10000:", repoNamespace, repoName)
	}

	res = pageResult.Results

	for _, tMeta := range res {
		tMeta.RepositoryNamespace = repoNamespace
		tMeta.RepositoryName = repoName
	}

	if limit, e := strconv.Atoi(limitStr); e == nil {
		if limit <= 20 {
			time.Sleep(20 * time.Second)
		}
	}

	return res, nil
}

// ReqTagsAllMetadata 获取指定repo的全部tag信息
func ReqTagsAllMetadata(repoNamespace, repoName string, page, pageSize int) ([]*Tag, error) {
	pageResult := new(TagsPage)
	res := make([]*Tag, 0)

	url := GetRepoTagsURL(repoNamespace, repoName, page, pageSize)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查http响应状态
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request %s got unexpected resp status code: %d", url, resp.StatusCode)
	}

	limitStr := resp.Header.Get("X-Ratelimit-Remaining")
	Logger.Debug("get all tags metadata from API:", url, ", remained limit:", limitStr)

	// body, err := io.ReadAll(resp.Body)
	tagsBuf := bytes.Buffer{}
	_, err = io.Copy(&tagsBuf, resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(tagsBuf.Bytes(), pageResult)
	if err != nil {
		return nil, err
	}

	res = append(res, pageResult.Results...)

	if limit, e := strconv.Atoi(limitStr); e == nil {
		if limit <= 20 {
			time.Sleep(20 * time.Second)
		}
	}

	for pageResult.Next != "" {
		// fmt.Println(pageResult.Next)
		newResp, err := httpClient.Get(pageResult.Next)
		if err != nil {
			Logger.Error("http get", pageResult.Next, "failed with:", err.Error())
			break
		}

		// 检查http响应状态
		if newResp.StatusCode != http.StatusOK {
			newResp.Body.Close()
			return nil, fmt.Errorf("request %s got unexpected resp status code: %d", url, resp.StatusCode)
		}

		limitStr = newResp.Header.Get("X-Ratelimit-Remaining")
		Logger.Debug("get all tags metadata from API:", pageResult.Next, ", remained limit:", limitStr)

		// body, err = io.ReadAll(newResp.Body)
		tmpBuf := bytes.Buffer{}
		_, err = io.Copy(&tmpBuf, newResp.Body)
		if err != nil {
			Logger.Error("io.ReadAll contents from resp of", pageResult.Next, "failed with:", err.Error())
			break
		}

		// pageResult必须刷新，不然会死循环
		pageResult = new(TagsPage)
		err = json.Unmarshal(tmpBuf.Bytes(), pageResult)
		if err != nil {
			Logger.Error("json unmarshal contents from resp of", pageResult.Next, "failed with:", err.Error())
			break
		}

		res = append(res, pageResult.Results...)

		// 手动关闭resp
		newResp.Body.Close()

		if limit, e := strconv.Atoi(limitStr); e == nil {
			if limit <= 20 {
				time.Sleep(20 * time.Second)
			}
		}
	}

	// 处理404
	if len(res) == 0 {
		return nil, fmt.Errorf("docker hub resp 0 tag all to repo %s/%s", repoNamespace, repoName)
	}

	for _, tMeta := range res {
		tMeta.RepositoryNamespace = repoNamespace
		tMeta.RepositoryName = repoName
	}

	return res, nil
}

// ReqImagesMetadata gets image metadata by calling Docker Hub API.
func ReqImagesMetadata(repoNamespace, repoName, name string) ([]*Image, error) {
	isMeta := make([]*Image, 0)

	url := GetImageMetadataURL(repoNamespace, repoName, name)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查http响应状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request %s got unexpected resp status code: %d", url, resp.StatusCode)
	}

	limitStr := resp.Header.Get("X-Ratelimit-Remaining")
	Logger.Debug("get image metadata from API:", url, ", remained limit:", limitStr)

	// body, err := io.ReadAll(resp.Body)
	imgsBuf := bytes.Buffer{}
	_, err = io.Copy(&imgsBuf, resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(imgsBuf.Bytes(), &isMeta)
	// err = json.Unmarshal(body, &isMeta)
	if err != nil {
		return nil, err
	}

	if len(isMeta) == 0 {
		return nil, fmt.Errorf("docker hub resp 404 to images %s/%s:%s", repoNamespace, repoName, name)
	}

	if limit, e := strconv.Atoi(limitStr); e == nil {
		if limit <= 20 {
			time.Sleep(20 * time.Second)
		}
	}

	return isMeta, err
}
