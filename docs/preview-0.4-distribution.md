# 0.4 distribution preview

2026-09-16 기준 0.4.0-dev.1의 배포·첫 실행 계약이다. 소스 저장소는
<https://github.com/dusen0528/wakeio-security-ci>에서 공개되어 있으며, preview
Action은 `dusen0528/wakeio-security-ci@main`으로 사용할 수 있다. `main`은 움직일
수 있으므로 운영에서는 검토한 commit의 전체 SHA를 지정한다. npm package는 아직
공개되지 않았고 GitHub Release와 Marketplace 등록도 완료되지 않았다. 현재 검증
가능한 입력은 public/reviewed checkout, 검토한 source archive, 또는 consumer가
vendor한 npm tarball이다.

공개 source checkout의 첫 실행은 다음처럼 시작한다.

```sh
git clone https://github.com/dusen0528/wakeio-security-ci.git
cd wakeio-security-ci
npm ci --ignore-scripts
npm test
```

Consumer workflow를 빠르게 만들려면 [`examples/github-action.yml`](../examples/github-action.yml)을
복사한다. 이 예제는 `tools: none`을 명시하여 내장 검사만 실행하고, optional native
scanner 다운로드를 첫 preview 실행의 전제조건으로 만들지 않는다.

## 먼저 확인할 계약

- Node.js 22 이상이 필요하다. `package.json`과 `package-lock.json`의 runtime
  dependency는 `parse5@7.3.0`, `typescript@5.9.3`으로 고정되어 있고, build 도구는
  `esbuild@0.28.2`로 고정되어 있다.
- 기본 report 디렉터리는 `wakeio-security-reports`다. 이름에 `.`이 없으므로 GitHub
  Actions의 hidden-file 제외 정책에 걸리지 않는다. `report.json`, `report.sarif`,
  `report.md`와 Action 실행 상태를 이 디렉터리에 둔다.
- composite Action은 consumer job에서 `npm ci`나 `npm run build`를 실행하지 않는다.
  release/source archive의 `dist-action/wakeio-security-ci.mjs`가 의존성을 포함한
  단일 Node 22 entrypoint이고, `dist-action/THIRD_PARTY_LICENSES.txt`에 해당 bundle의
  parse5, entities, TypeScript/ThirdPartyNoticeText, esbuild 고지가 있다.
- npm CLI는 `build/src/cli.js`를 bin으로 사용한다. npm이 공개되기 전에는 consumer의
  `vendor/wakeio-security-ci/*.tgz` 같은 검토한 상대 `file:` dependency로 설치한 뒤
  `npx --no-install wakeio-security-ci ...`로 실행한다. 존재하지 않는 registry tag나
  가짜 Action 이름을 workflow에 넣지 않는다.

구현 근거는 [`package.json`](../package.json), [`scripts/build-action-bundle.mjs`](../scripts/build-action-bundle.mjs),
[`scripts/package-release.mjs`](../scripts/package-release.mjs), [`action.yml`](../action.yml),
[`scripts/action-run.mjs`](../scripts/action-run.mjs)이다. `package:release`는
source archive, npm tarball, SHA-256 checksum 파일을 함께 만든다. npm staging에서는
consumer가 실행할 수 없는 contributor용 `scripts`와 `devDependencies`를 package
metadata에서 제거하고 `build/src`만 runtime으로 보낸다. source archive에는 Action
bundle과 `scripts/`가 남아 있어 vendor한 checkout에서도 Action을 실행할 수 있다.

## npm consumer와 source archive

검토된 로컬 tarball을 consumer에 넣는 최소 흐름은 다음과 같다.

```sh
npm run build
node scripts/package-release.mjs --out-dir /tmp/wakeio-security-release
mkdir /tmp/wakeio-security-consumer
cp /tmp/wakeio-security-release/wakeio-security-ci-0.4.0-dev.1.tgz /tmp/wakeio-security-consumer/
cd /tmp/wakeio-security-consumer
npm init -y
npm install --ignore-scripts ./wakeio-security-ci-0.4.0-dev.1.tgz
printf '%s\n' 'export const ready = true;' > app.js
npx --no-install wakeio-security-ci scan --source . --tools none --fail-on none --out wakeio-security-reports
```

consumer의 `package-lock.json`에는 local tarball 경로를 계속 보관하고, CI에서는
`npm ci --ignore-scripts --no-audit --fund=false`를 사용한다. `npm install`이
dependency lifecycle script를 실행하게 두지 않는다. 실제 publish 전에는 fresh npm
cache와 offline local tarball 두 경로를 별도로 확인해야 한다. `package-release`가
생성한 source archive의 최소 Action 경로는 다음과 같다.

```text
wakeio-security-ci/dist-action/wakeio-security-ci.mjs
wakeio-security-ci/dist-action/THIRD_PARTY_LICENSES.txt
wakeio-security-ci/scripts/action-run.mjs
wakeio-security-ci/scripts/install-tools.mjs
```

source archive Action 경로에는 `node_modules`가 없어야 하며, `WAKEIO_TOOLS=none`인
합성 source scan이 세 report와 `action-status.json`을 만들 수 있어야 한다. target
checkout의 `package.json` lifecycle script는 이 경로에서 실행하지 않는다.

## Action 입력, 신뢰 경계, 실패 결과

[`action.yml`](../action.yml)의 `source`, `url`, `pages`, `max-pages`, `tools`,
`fail-on`, `project-id`, `tool-cache` 입력은 argv/env 데이터로만 전달된다. `source`
scan에서는 `gitleaks`, `osv`, `trivy`가 native installer 대상이고, Bandit은 native
archive installer가 제공하지 않는다. Python 파일이 없으면 CLI의 Bandit check는
`not_applicable`이며 setup이 실패하지 않는다. Python 파일이 있으면 사용자가 검토한
Bandit executable을 `bandit-path`로 명시해야 한다.

Action 내부와 helper Action은 immutable commit으로 고정한다. 공개 preview
예제는 Wakeio Action만 `@main`을 사용하므로, 운영 적용 전에는 검토한 Wakeio
commit의 전체 SHA로 바꾼다. 현재 helper pins는 checkout
`11d5960a326750d5838078e36cf38b85af677262`, setup-node
`49933ea5288caeca8642d1e84afbd3f7d6820020`, upload-artifact
`ea165f8d65b6e75b540449e92b4886f43607fa02`다. checkout에는
`persist-credentials: false`를 사용한다. consumer가 vendor한 Action tree는 실행할
코드이므로 pull request에서 source와 Action checkout을 분리하고, vendor 변경을
review한 뒤 사용한다. scanner는 대상 source의 package manager, lifecycle hook,
build, test, target script를 실행하지 않지만, Action 자체는 Node runtime과 사용자가
지정한 scanner/Bandit executable을 실행한다.

`action-run.mjs`는 `GITHUB_WORKSPACE`에서 child CLI를 실행하고, `GITHUB_ACTION_PATH`
아래의 prebuilt bundle과 installer만 신뢰한다. API credentials는 이름이 지정된
environment variable에서만 읽으며 summary, annotation, status artifact에는 token,
source snippet, scanner의 raw stdout/stderr를 넣지 않는다. 설정 오류와 scan 오류는
각각 `setup-status`와 `scan-status`로 나눠서 표시한다.

Action은 다음 outputs를 쓴다.

```text
report-dir, report-json, report-sarif, report-markdown
exit-code, finding-count, incomplete-count, setup-status, scan-status
```

`GITHUB_STEP_SUMMARY`에는 setup/scan 상태, exit code, finding/incomplete count,
check 상태, cache 상태, report 경로만 기록한다. annotation은 setup failure 한 줄
또는 incomplete warning 한 줄로 제한하고 workflow command의 `%`, CR/LF, `:`, `,`를
escape한다. report가 이번 실행에서 새로 쓰이지 않으면 이전 `report.json`을 결과로
재사용하지 않는다. 따라서 stale report만 남은 setup failure는 finding count 0과
`report unavailable`을 내고 exit 2가 된다.

consumer workflow는 특정 report 파일만 올리지 말고 디렉터리 전체를 `if: always()`로
artifact에 올려 setup failure 때 생성되는 `action-status.json`도 보존해야 한다.
[`examples/github-local-action.yml`](../examples/github-local-action.yml),
[`examples/gitlab-ci.yml`](../examples/gitlab-ci.yml),
[`.github/workflows/self-test.yml`](../.github/workflows/self-test.yml)은 이 형태를
예시한다. GitHub artifact 이름은
`wakeio-security-ci-reports`로 두고, report 디렉터리의 숨김 파일에 의존하지 않는다.

## Native archive cache와 advisory DB 상태

`install-tools.mjs`는 Gitleaks 8.30.1, OSV Scanner 2.6.0, Trivy 0.74.0의 Linux/macOS
x64/arm64 release asset만 사용한다. cache 파일 이름에는 tool, version, OS/arch,
원본 asset 이름, upstream archive SHA-256이 들어간다. cache hit도 sidecar manifest나
binary를 믿지 않고 원본 archive bytes를 pinned SHA-256으로 다시 해시한 뒤 extraction
한다. 손상된 regular file은 버리고 online이면 재다운로드하며, `--offline` cache miss는
exit 2다. Action summary와 `action-status.json`에는 tool별 `hit`/`miss`/`not_requested`
를 표시한다.

Action의 `tool-cache` 입력을 self-hosted의 지속 디렉터리나 사용자가 복원한 CI cache에
연결할 수 있다. GitHub-hosted runner의 `RUNNER_TOOL_CACHE`만으로는 job 사이 보존을
주장하지 않는다. 예제 workflow는 immutable `actions/cache` commit
`0057852bfaa89a56745cba8c7296529d2fc39830`으로 native archive 디렉터리를 복원하고,
OS/arch와 vendored package lock hash를 key에 포함한다. 이 cache action은 archive를
신뢰하는 근거가 아니며, installer가 매 hit에 원본 pinned SHA를 다시 검증한다.

OSV와 Trivy advisory/policy database는 native archive cache와 별개다. `action-run`은
명시된 `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`를 보존하고, 없으면 namespace hint만
전달한다. Trivy source adapter는 실행별 private cache를 사용한다. 두 database의
revision, freshness, cross-job 재사용은 현재 Action이 입증하지 않으므로 summary와
status에 모두 `unknown`으로 남긴다. `--osv-offline`은 사용자가 준비한 절대 DB
디렉터리를 요구하며 Action이 DB를 다운로드하거나 고정한다고 가정하지 않는다.

## `doctor`와 `init`

첫 실행 전에 다음 명령으로 적용 범위와 환경을 확인할 수 있다.

```sh
npx --no-install wakeio-security-ci doctor --source . --tools gitleaks,osv,trivy --json
```

`doctor`는 directory names, regular-file metadata, Python/dependency/config count와
PATH executable availability만 검사한다. source 내용을 열지 않고, target code·package
manager·scanner·network를 실행하지 않는다. `vendor`, `.venv`, `node_modules`,
`build`, `out`, report/cache directory 등 collector가 제외하는 경로도 inventory에서
제외한다. `--strict`는 inventory truncation 또는 적용 가능한 missing tool을 exit 2로
명시한다. 결과에는 Bandit applicability, 선택 tool의 expected transfer, OSV package
lookup/Trivy policy DB의 예상 network, 두 DB의 `unknown`, 실제 다음 `scan` 명령이
포함된다.

workflow를 명시적으로 만들려면 다음을 사용한다.

```sh
npx --no-install wakeio-security-ci init --source . \
  --workflow .github/workflows/wakeio-security-ci.yml \
  --tools none --out wakeio-security-reports
```

`init`은 기존 파일을 덮어쓰지 않고, source 내부의 새 workflow 하나만 생성한다.
generated workflow는 checkout/setup-node/upload-artifact를 위 commit으로 pin하고,
`npm ci --ignore-scripts` 후 `npx --no-install`로 설치된 CLI를 실행하며,
`upload-artifact`는 `if: always()`다. output path는 YAML JSON string으로, scan
command는 YAML block scalar와 shell quoting으로 기록하므로 apostrophe나 `: `가 있는
경로도 parse 가능하다. npm package가 아직 공개되지 않은 경우에는 workflow를
실행하기 전에 reviewed relative `file:vendor/*.tgz` dependency와 matching lockfile을
consumer에 넣어야 한다. `init`은 읽히지 않는 `wakeio.config.json`을 만들지 않는다.

## 플랫폼 및 확인 범위

native installer의 선언된 matrix는 Linux x64/arm64와 macOS x64/arm64다. Windows,
다른 architecture, Bandit/Python runtime은 이 installer의 지원 범위가 아니다. Node
내장 check만 `tools: none`으로 실행할 수 있고, native tool이 없는 적용 가능 check는
setup/scan incomplete로 남긴다. 이 문서의 “지원”은 asset selection, SHA verification,
metadata-only path, synthetic smoke가 통과한 선언 범위이며, 특정 운영체제의 전체
engine 실행·advisory freshness·GitHub-hosted cache persistence를 보증하지 않는다.

## 검증 명령과 acceptance

현재 변경을 재현하는 focused suite는 다음과 같다.

```sh
npm run build
node --test build/tests/distribution-v04.test.js
node --test build/tests/installer.test.js build/tests/package-release.test.js build/tests/preview-cli.test.js
```

검증할 결과는 다음과 같다.

1. build가 TypeScript와 dependency-free `dist-action` bundle/license를 생성하고,
   bundle이 `node_modules` 없이 `--help`와 `tools:none` source scan을 실행한다.
2. source archive 목록에 bundle/license와 Action scripts가 있고, archive Action이
   target lifecycle script를 실행하지 않는다.
3. npm tarball metadata에는 `scripts`/`devDependencies`가 없고 `build/src` bin과
   exact runtime dependency 계약이 남는다.
4. native installer는 verified cold download, 같은 cache의 offline hit, tampered
   archive rejection을 각각 구분한다.
5. stale report setup failure는 이전 finding을 출력하지 않고, summary/output/status에
   setup/scan phase와 `report unavailable`을 남긴다.
6. doctor는 read-only inventory를 반환하고, init은 existing workflow를 거부하며
   quote가 필요한 output path도 parse 가능한 workflow로 만든다.

이 acceptance를 통과해도 npm publish, GitHub Action marketplace/release 등록, 실제
고객 저장소의 credential 정책, 외부 advisory DB의 최신성은 별도 release 승인과
환경 검증 대상이다.
