# Releasing Signet

This is the maintainer procedure for building and publishing reviewed Signet releases. It is
not an end-user setup guide. A stable tag starts irreversible PyPI publication after a human
approves the protected environment, so do not push a tag while testing this procedure.

## Release contract

The distribution is `signet-gateway`; the import package and console command are `signet`.
`pyproject.toml` is the single version source. `signet.__version__` reads installed package
metadata, so source and wheel versions cannot drift independently.

The stable artifact matrix is:

| Artifact | Runner | Supported target |
| --- | --- | --- |
| Wheel | `ubuntu-24.04` | Linux x86_64 |
| Wheel | `ubuntu-24.04-arm` | Linux arm64 |
| Wheel | `macos-15` | macOS arm64 |
| Source distribution | `ubuntu-24.04` | Rebuild input for the supported targets |

Runtime requirements are Python >=3.12,<3.13 and SQLite 3.51.3 or newer. The package rejects
older SQLite at database open. Release builds use managed CPython 3.12.13 and `uv 0.11.28`.
The complete Linux/macOS runtime dependency closure is exact-pinned in package metadata and
`uv.lock`; the build and release tool closures are exact-pinned as well.

Wheels contain the `signet` modules, type marker, migrations, browser templates and static
assets, reference manifests, MIT license, and installed manpage. They intentionally exclude
tests, repository automation, and source-only tooling. The source distribution contains the
reviewed source, tests, documentation, workflows, lock, build hook, and release tools needed
to reproduce and inspect it. The build hook refuses Windows, macOS x86_64, and unreviewed
platform tags instead of emitting a misleading universal wheel.

## One-time GitHub and PyPI configuration

Create a protected `pypi` environment in GitHub before enabling stable publication. Configure
required reviewers, disallow self-review, prevent administrator bypass, and restrict
deployments to protected stable tags. Repository rules must protect `main` and require every
CI job. These controls live in GitHub settings; the workflow deliberately cannot weaken them.

Configure the PyPI trusted publisher with this exact identity:

- owner/repository: `bee-san/Signet`
- workflow: `.github/workflows/release.yml`
- environment: `pypi`

Do not add `PYPI_API_TOKEN`, a password, or another long-lived index credential to GitHub.
The publish command is `uv publish --trusted-publishing always`; `always` makes missing or
mismatched OIDC context a hard failure rather than falling back to a token.

After configuring the environment and publisher, verify both settings through their read-only
APIs. A repository transfer, workflow rename, environment rename, or package-name change
invalidates the trusted publisher and requires a new review before another tag.

## Dry run without consuming a version

The `release-dry-run.yml` workflow runs on packaging-related pull requests and can be started
manually on any reviewed branch:

```console
gh workflow run release-dry-run.yml --ref BRANCH
gh run watch --exit-status
```
The dry run builds a unique local 0.1.0 wheel and sdist on every supported runner, verifies
their contents and metadata, and uploads them with `uv publish` to a loopback-only,
fallback-disabled PyPI-compatible server. A fresh, dependency-hashed runtime environment
installs the exact version from that isolated index with dependencies already installed from
the hashed lock export. It runs installed `signet --version`, setup, doctor, and status help.
The workflow has read-only permissions, no OIDC permission, no public index credential, and
no public publication URL, so it consumes no PyPI or TestPyPI version.

A successful dry run is necessary but not sufficient. Review the pull request, exact diff,
security findings, package inventory, and hosted CI before merging.

## Prepare a stable release

1. Start from a clean branch based on current `origin/main`.
2. Set one stable `MAJOR.MINOR.PATCH` version in `pyproject.toml`; do not use a local, dev,
   prerelease, or post-release segment.
3. Move the matching changelog section from `Unreleased` to its release date. Verify upgrade,
   rollback, support, and security notes against the exact code.
4. Run the local gate:

   ```console
   UV_PYTHON=3.12.13 uv sync --frozen --group release
   UV_PYTHON=3.12.13 uv run pytest -q
   UV_PYTHON=3.12.13 uv run ruff check .
   UV_PYTHON=3.12.13 uv run ruff format --check .
   UV_PYTHON=3.12.13 uv run mypy
   actionlint
   SOURCE_SHA="$(git rev-parse HEAD)"
   rm -rf dist/release-check
   mkdir -p dist/release-check
   UV_PYTHON=3.12.13 uv run python scripts/reproducible_build.py \
     --kind sdist --source . --output-directory dist/release-check \
     --evidence dist/release-check/source.build.json \
     --source-sha "$SOURCE_SHA" --platform source
   ```

5. Open and merge the release-preparation pull request. Wait for required CI on the exact
   merge commit. Confirm the commit is on `origin/main` and no required check is pending,
   skipped, neutral, cancelled, stale, or red.
6. Obtain explicit release approval. Only then create one annotated stable tag at that exact
   reviewed main commit and push only that tag:

   ```console
   git fetch origin --prune --tags
   git switch main
   git pull --ff-only origin main
   VERSION="$(uv version --short)"
   test "v$VERSION" = "vMAJOR.MINOR.PATCH"
   git status --porcelain=v1 | test ! -s /dev/stdin
   git tag -a "v$VERSION" -m "Signet v$VERSION"
   git push origin "refs/tags/v$VERSION"
   ```

The placeholder comparison is intentional: replace `vMAJOR.MINOR.PATCH` with the exact
approved tag. Never create or move the tag from a branch or from a commit whose main-push CI
did not succeed.

## Hosted release gates

`.github/workflows/release.yml` accepts only a pushed `vMAJOR.MINOR.PATCH` tag in
`bee-san/Signet`. Before building, it proves all of the following:

- the tag peels to the exact event SHA and matches the stable project version;
- the checked-out source is byte-identical to that commit;
- the commit is an ancestor of fetched `origin/main`;
- the exact SHA has a completed successful `main` push run of `ci.yml`;
- package, build backend, release tools, Python, SQLite, and `uv` constraints match;
- all external actions are pinned to full commit SHAs.

The sdist and each native wheel are built twice with the commit timestamp as
`SOURCE_DATE_EPOCH`. Byte inequality stops the run. Each `*.build.json` binds the artifact
name, SHA-256, size, source commit, platform, Python, SQLite, `uv`, and reproducible result.
The aggregate gate rejects a missing, duplicate, renamed, universal, wrong-version,
wrong-platform, unsafe, or unexpected distribution; incomplete runtime/browser assets;
invalid wheel RECORD; dependency drift; malformed build evidence; missing or incorrect SBOM
edges; and unknown, GPL, AGPL, or LGPL license results. A deterministic runtime manifest records
the exact installed versions and `Requires-Dist` metadata used to verify every SBOM node and edge.

The release also runs Bandit, hashed dependency vulnerability auditing, license inventory,
Twine metadata checks, and the exact-source CI scan suite. It emits a reproducible CycloneDX
1.6 runtime SBOM, runtime manifest, and `SHA256SUMS`. Sigstore signs and verifies the
distributions, SBOM, runtime manifest, license report, build evidence, and checksums with identity:

```text
https://github.com/bee-san/Signet/.github/workflows/release.yml@refs/tags/vMAJOR.MINOR.PATCH
```

GitHub records build-provenance and SBOM attestations. The workflow runs `gh attestation
verify` against the exact repository before requesting protected-environment publication.
PyPI receives only the three wheels and one source distribution; evidence remains attached
to the GitHub release.

## Verify a published release

Download into a new empty directory. Do not verify in a source checkout or mix files from
multiple runs.

```console
gh release download vMAJOR.MINOR.PATCH --repo bee-san/Signet --dir signet-release
cd signet-release
shasum -a 256 -c SHA256SUMS
sigstore verify identity \
  --cert-identity \
  "https://github.com/bee-san/Signet/.github/workflows/release.yml@refs/tags/vMAJOR.MINOR.PATCH" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  signet_gateway-*.whl signet_gateway-*.tar.gz
gh attestation verify signet_gateway-*.whl signet_gateway-*.tar.gz \
  --repo bee-san/Signet
```

Also compare PyPI file hashes with `SHA256SUMS`, inspect the CycloneDX root name/version and
dependency edge, install the exact wheel in a fresh supported environment, and run `signet
--version`, `signet setup --help`, `signet doctor --help`, and `signet status --help`.
Signatures and attestations establish build identity and artifact integrity; they do not
replace review of release notes, package contents, runtime behavior, or provider effects.

## Upgrade and rollback

Before upgrade, stop mutations, run `signet backup`, verify the backup, record the installed
package hash/version and schema, then install the new reviewed wheel. Run `signet doctor` and
`signet status` before re-enabling provider paths. Schema migrations are forward,
transactional, and backed up; do not hand-edit `schema_meta`.

If startup or migration fails, keep all services stopped. Use the documented rollback plan
to restore the verified pre-upgrade database, attachments, key references, configuration,
and the exact prior wheel together. Never run an older binary against a schema it does not
support, and never restore a backup that forgets an already acknowledged request.

## Compromise or failed publication

Publication is not transactional across PyPI and GitHub. If any step becomes ambiguous,
stop and preserve the run, OIDC, package hash, and audit evidence. Do not rerun against a
moved tag.

For a compromised or incorrect release:

1. disable the release workflow and PyPI trusted publisher;
2. make the protected environment unavailable and investigate the exact run identity;
3. yank the affected PyPI version rather than deleting and silently replacing files;
4. publish a security advisory and mark the GitHub release without rewriting its evidence;
5. rotate any independently exposed credentials and rebuild from a newly reviewed commit;
6. issue a higher patch version and new tag—never reuse a package version or move/reuse the
   old tag.

A failed run before PyPI publication may be retried only at the same immutable tag after the
failure is understood and the run still proves identical source. A code or workflow fix
requires a new commit, version, and tag.
