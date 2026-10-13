# Monthly patch setup

The monthly patch controller and full proposal live in the companion
[notation CLI repository](https://github.com/notaryproject/notation). This
repository installs only a dispatch workflow that calls the CLI's reusable
worker at a full commit SHA. The CLI owns the shared scripts, regression tests,
assessment schedule, and controller. Go does not require a Copilot token.

## Merge-time state

Maintainers must leave the Actions variable `MONTHLY_PATCH_ENABLED` unset or
`false` when merging the setup. Merging this change is not authorization to
activate automation, change repository settings, or publish a release. The
companion CLI controller and this repository's caller must both be installed
before activation. The draft's reusable-workflow pin must be rebound to the final
upstream CLI commit after the companion PR merges, before Go merges or activates.
Squash merging can change that commit SHA.
The current review pin is `16fcf79278a01b403233170611f94eb665bdde07`.
Maintainers must update both the caller's `uses` reference and `worker_sha`
input to the same final upstream commit.

## Repository settings

| Setting | Required setup |
| --- | --- |
| Repository features | Enable GitHub Actions and Issues. |
| Actions policy | Allow the reusable workflow `notaryproject/notation/.github/workflows/monthly-patch-worker.yml` and its required actions. The caller uses a full commit SHA, and the central worker checks out its helper code at the corresponding immutable pin. |
| Dependabot | Keep Go modules and GitHub Actions updates enabled on `main`. The existing `.github/dependabot.yml` configures both weekly and does not override the default target branch. |
| Release branch | Maintain the current latest stable `release-X.Y` branch with required CI checks and reviews. Determine the branch from the current stable release, not from the version on `main`. |
| Merge methods | Enable **Allow merge commits**. Preserve the required normal merge method for release voting PRs. |
| Stable baseline | Ensure the current stable baseline tag is signed and its signature/provenance can be verified by the worker. An unverifiable baseline blocks execution. |
| Actions secret `MONTHLY_PATCH_TOKEN` | Provide an authenticated-user token whose `GET /user` identity matches `MONTHLY_PATCH_ACTOR` across Core, Go, and CLI. Scope it to the three repositories with contents, pull requests, issues, and Actions write permissions, plus workflow write permission if workflow updates are in scope. GitHub App installation tokens are unsupported. Do not grant branch-rule bypass. |
| Actions secret `MONTHLY_PATCH_SIGNING_KEY` | Store the private release-signing key as a secret, never as a repository file, variable, issue, or PR attachment. |
| Actions variable `MONTHLY_PATCH_ACTOR` | Set the same automation actor login used by the companion Core and CLI changes. |
| Signer identity variables | Set `MONTHLY_PATCH_SIGNER_LOGIN` and `MONTHLY_PATCH_SIGNER_EMAIL`. Optionally set `MONTHLY_PATCH_SIGNER_NAME`. Ensure the identity matches the signing key. |
| Signing-key registration | Register only the public signing key on the designated signer's GitHub account. |
| Actions variable `MONTHLY_PATCH_ENABLED` | Leave unset or `false` until maintainers explicitly authorize activation after companion setup and validation. |

Maintainers must verify the configured token can perform the required operations
without bypassing required checks or reviews. The caller passes only the two
declared secrets, and passes empty values during `dry-run`; it does not inherit
all repository secrets.

## Coordination and release approvals

Go has its own third-party dependency updates. A Go cycle waits for Core only
when Core publishes a release in the same coordinated cycle. In that case, the
exact planned canonical `github.com/notaryproject/notation-core-go` version must
pass the checked producer PR before release. Fork `replace` directives are not
an acceptable substitute.

The CLI controller owns cycle assessment, policy authorization, and coordination.
Maintainers must approve that policy and activation explicitly. Worker execution
must honor the authorized cycle and preserve the release approval points in
[Release Checklist](../RELEASE_CHECKLIST.md), including a majority of repo-level
maintainer approvals on the release voting PR, the required merge-commit method,
and a signed release tag. Setup approval does not replace release voting.

The majority-maintainer vote and merge-commit requirement apply to the separate
release voting PR that updates `signingAgent`, not to the preceding dependency
bump PR. Dependency PRs still require the configured CI and reviews. The release
voting PR description must link the change logs and repo-level maintainer list.
Automation must not waive these governance gates.

The signed release tag targets the single signed commit recorded by the voting
PR. The release branch retains the normal merge commit, whose tree must match
the voted commit. The worker must recheck the exact candidate, current-head
maintainer majority, and merge provenance before publication.
The controller pins the active repo-level roster from the default branch at
assessment time. Roster changes require reassessment; a historical stable tag
does not supply the voting roster.
The worker validates the metadata delta against the exact qualified dependency
candidate. A release voting PR can include those recorded backports plus the
required metadata update without granting permission for other source changes.

## Activation

1. Maintainers review and merge the companion CLI controller and the
   Go caller, with automation still disabled. Before merging Go, rebind its
   provisional draft pin to the final upstream CLI commit and review the
   central helper checkout pin.
2. Administrators configure the settings above and confirm the required CI and
   review rules apply to the selected stable release branch.
3. Maintainers review the CLI's centralized tests and the Go caller's workflow
   lint and contract checks,
   and approve the controller's authorization policy and activation.
4. Administrators set `MONTHLY_PATCH_ENABLED` to `true` only after those approvals.
   They can return it to `false` to disable future worker execution.

The worker defaults to a no-write `dry-run`. Canonical execution requires a
controller-authorized cycle, plan digest, and attempt from the CLI, along with
the enabled setting and configured actor. A manual dispatch alone does not
authorize execution.
