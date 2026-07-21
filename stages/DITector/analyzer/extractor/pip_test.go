package extractor

import (
	"fmt"
	"testing"
)

func TestExtractPipInstall(t *testing.T) {
	pipInstallCmds := ExtractPipInstallCmdsFromString(`FROM ubuntu:16.04
	RUN apt-get update && apt-get install -y --no-install-recommends \
		python3.5 \
		python3-pip \
		&& \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*
	RUN pip install nibabel pydicom matplotlib pillow && pat-get install -y wget && sth
	RUN pip install med2image`)

	for _, pip := range pipInstallCmds {
		fmt.Println(pip)
	}
}

func TestParsePipInstallArgs(t *testing.T) {
	pip := `pip install requests --upgrade -r requirements.txt --constraint something --target=/path/to/install --no-cache-dir --proxy=http://user:password@proxy_server:port   numpy>1.2.0, <2.0.0,~=1.5.x`
	args := ParsePipInstallCmdArgs(pip)
	for k, v := range args {
		fmt.Println(k, ":", v)
	}
}
