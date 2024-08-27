# Release Checklist

## Overview

This document describes the checklist to publish a release for notation-go.

## Release Process

1. Check if there are any security vulnerabilities fixed and security advisories published before a release. Security advisories should be linked on the release notes.
2. Determine a [SemVer2](https://semver.org/)-valid version prefixed with the letter `v` for release. For example, `v1.0.0-rc.1`.
3. If there is new release in [notation-core-go](https://github.com/notaryproject/notation-core-go) library that are required to be upgraded in notation-go, update the dependency versions in the follow `go.mod` and `go.sum` files of notation-go:
    - [go.mod](go.mod), [go.sum](go.sum)
4. Update the value of `signingAgent` defined in file `signer/signer.go` with `notation-go/<version>`, where `<version>` is the SemVer2 value from step 2 without the `v` prefix. For example, `notation-go/1.0.0-rc.1`.
5. Open a bump up PR and submit the changes in step 3 and 4 to the notation-go repository.
6. After PR from step 5 is merged. Create a vote issue for the new release cut at the PR's commit hash. Add the link of change logs and repo-level maintainer list in the issue's description. The issue title should be `vote: tag <version>`. A majority of approvals from the [repo-level maintainers](MAINTAINERS) MUST be met before releasing. An example vote [issue](https://github.com/notaryproject/notation-go/issues/341).
7. On notation-go GitHub page, click [Releases](https://github.com/notaryproject/notation-go/releases) and then click `Draft a new release`. In the draft a new release page, create the tag with name `<version>`. Then click `Generate release notes`. Check the draft release, revise the release description, and publish the release. Close the vote issue once accomplished.
8. Announce the new release in the Notary Project community.