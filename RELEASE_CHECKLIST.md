# Release Checklist

## Overview

This document describes the checklist to publish a release for notation-go.

## Release Process from main

1. Check if there are any security vulnerabilities fixed and security advisories published before a release. Security advisories should be linked on the release notes.
2. Determine a [SemVer2](https://semver.org/)-valid version prefixed with the letter `v` for release. For example, `version="v1.0.0-rc.1"`.
3. If there is new release in [notation-core-go](https://github.com/notaryproject/notation-core-go) library that are required to be upgraded in notation-go, update the dependency versions in the follow `go.mod` and `go.sum` files of notation-go:
    - [go.mod](go.mod), [go.sum](go.sum)
4. Open a bump up PR and submit the changes in step 3 to the notation-go repository.
5. After PR from step 4 is merged. Create another PR to update the value of `signingAgent` defined in file `signer/signer.go` with `notation-go/<version>`, where `<version>` is `$version` from step 2 without the `v` prefix. For example, `notation-go/1.0.0-rc.1`. The commit message MUST follow the [conventional commit](https://www.conventionalcommits.org/en/v1.0.0/) and could be `bump: release $version`. This PR is also used for voting purpose of the new release. Add the link of change logs and repo-level maintainer list in the PR's description. The PR title could be `bump: release $version`. Make sure to reach a majority of approvals from the [repo-level maintainers](MAINTAINERS) before merging it. This PR MUST be merged using [Create a merge commit](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/about-merge-methods-on-github) method in GitHub.
6. After PR from step 5 is merged. On notation-go GitHub page, click [Releases](https://github.com/notaryproject/notation-go/releases) and then click `Draft a new release`. In the `draft a new release` page, create the tag with name `$version`. Then click `Generate release notes`. Check the draft release, revise the release description, and publish the release.
7. Announce the new release in the Notary Project community.

## Release Process from a release branch

1. Check if there are any security vulnerabilities fixed and security advisories published before a release. Security advisories should be linked on the release notes.
2. Determine a [SemVer2](https://semver.org/)-valid version prefixed with the letter `v` for release. For example, `version="v1.2.0-rc.1"`.
3. If a new release branch is needed, from main branch's [commit list](https://github.com/notaryproject/notation-go/commits/main/), find the commit that you want to cut the release. Click `<>` (Browse repository at this point). Create branch with name `release-<version>` from the commit, where `<version>` is `$version` from step 2 with the major and minor versions only. For example `release-1.2`. If the release branch already exists, skip this step.
4. If there is new release in [notation-core-go](https://github.com/notaryproject/notation-core-go) library that are required to be upgraded in notation-go, update the dependency versions in the follow `go.mod` and `go.sum` files of notation-go:
    - [go.mod](go.mod), [go.sum](go.sum)
5. Open a bump up PR and submit the changes in step 4 to the release branch. The PR also needs to include any commit from main branch that you would like to include in the release (you can do this by `git cherry-pick` command). 
6. After PR from step 5 is merged. Create another PR to update the value of `signingAgent` defined in file `signer/signer.go` with `notation-go/<version>`, where `<version>` is `$version` from step 2 without the `v` prefix. For example, `notation-go/1.2.0-rc.1`. The commit message MUST follow the [conventional commit](https://www.conventionalcommits.org/en/v1.0.0/) and could be `bump: release $version`. This PR is also used for voting purpose of the new release. Add the link of change logs and repo-level maintainer list in the PR's description. The PR title could be `bump: release $version`. Make sure to reach a majority of approvals from the [repo-level maintainers](MAINTAINERS) before merging it. This PR should be merged using [Create a merge commit](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/about-merge-methods-on-github) method in GitHub.
7. On notation-go GitHub page, click [Releases](https://github.com/notaryproject/notation-go/releases) and then click `Draft a new release`. In the `draft a new release` page, create the tag with name `$version`. Set the `Target` branch as `release-<version>` as in step 3. Then click `Generate release notes`. Check the draft release, revise the release description, and publish the release.
8. Announce the new release in the Notary Project community.