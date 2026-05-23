package extractor

import (
	"fmt"
	"testing"
)

func TestCheckWgetCmd(t *testing.T) {
	cmd := `FROM centos:latest

	ENV PATH=$PATH:/opt/gradle/gradle-7.0.2/bin
	
	RUN yum update -y && yum install -y \
		git \
		ccwget \
		curl \
		unzip \
		java-11-openjdk-devel \
		&& curl https://www.baidu.com -O output.html \
		&& yum clean all
	
	RUN mkdir /opt/gradle \
		&& wget -q \
		https://services.gradle.org/distributions/gradle-7.0.2-bin.zip \
		&& unzip gradle-7.0.2-bin.zip -d /opt/gradle/ \
		&& rm -f gradle-7.0.2-bin.zip`

	fmt.Println(CheckWgetCmd(cmd))

	for _, wgetCmd := range ExtractWgetCmds(cmd) {
		fmt.Println(wgetCmd)
		fmt.Println(ExtractWgetCmdURLs(wgetCmd))
	}
}
