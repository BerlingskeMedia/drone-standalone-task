#!/bin/bash

## Temporary script for test buildis of this plugin

## Build binaries
DRONE_REPO_OWNER=BerlingskeMedia DRONE_REPO_NAME=drone-standalone-task drone exec

if [[ ! $? -eq 0 ]]; then
	echo ERROR!
	exit 1
fi


export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0
export DRONE_BUILD_NUMBER=1
export DRONE_REPO_NAME=drone-standalone-task
go build -v -ldflags "-X main.build=${DRONE_BUILD_NUMBER}" -a -o release/linux/amd64/${DRONE_REPO_NAME}


## Build docker image
#docker build  --no-cache --rm --pull -f Dockerfile -t "drone-standalone-task:0.0.2" .
