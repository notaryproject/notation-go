module github.com/notaryproject/notation-go-lib

go 1.16

require (
	github.com/docker/go v1.5.1-1
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7
	github.com/opencontainers/artifacts v0.0.0-20210209205009-a282023000bd
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.1
)

replace github.com/opencontainers/artifacts => github.com/aviral26/artifacts v0.0.3
