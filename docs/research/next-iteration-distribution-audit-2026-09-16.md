# 다음 버전 배포·첫 실행 감사

분석일: 2026-09-16 KST · 대상: `wakeio-security-ci@0.3.0-dev.1`

이 문서는 첫 설치, CLI 배포물, GitHub Action, 외부 엔진 준비, Python 선택 검사, CI 결과 전달을 실제 파일과 격리된 소비자 디렉터리에서 확인한 기록이다. 실행 코드·테스트·`package.json`·Action·워크플로·패키지 배포물을 이 작업에서 변경하지 않았고, npm publish나 GitHub 쓰기 작업도 하지 않았다. 사용자 선택 npm 다운로드 통계 외 telemetry는 이 감사의 전제가 아니다.

## 판단

내장 검사만 선택한 npm tarball CLI는 Node 22 소비자 디렉터리에서 실행된다. 그러나 다음 첫 실행과 CI 흐름은 공개 배포 계약으로 보기 어렵다.

1. Action의 기본 결과 디렉터리인 `.wakeio-security-ci`가 예제의 `upload-artifact` 기본 설정에서 숨김 파일로 취급되어 결과가 업로드되지 않을 수 있다.
2. vendored source archive Action은 매 실행마다 Action 디렉터리에서 `npm ci`와 TypeScript build를 수행한다. 이 단계가 끝나기 전에는 scan 결과도 Action output도 없다.
3. npm tarball은 CLI 실행에 필요한 `build/src`는 포함하지만 `tsconfig.json`과 source/scripts 일부는 제외한다. 동시에 개발용 `build`, `test`, `package:release` script를 계속 노출해 설치 후 명령이 실패한다.
4. source scan의 기본 도구는 tarball에 들어 있지 않으며 setup 명령도 없다. 소비자가 별도 설치를 하지 않으면 정상적인 작은 JS 프로젝트도 external check가 `partial`이 되어 exit 2가 된다.
5. Python은 Bandit을 별도 설치해야 하고 Action은 Python 파일이 없는 저장소도 `bandit-path`가 없으면 먼저 실패시킨다. 결과 요약은 stdout과 `report-dir` 하나뿐이라 PR에서 완료·발견·부분 검사를 바로 읽기 어렵다.

이는 scanner 수를 늘리는 문제보다 배포물의 설치 계약, 네트워크·cache 계약, 신뢰 경계, 결과 전달 계약을 먼저 명시해야 한다는 뜻이다. 아래 우선순위는 코드 재현과 문서화된 runner 제한을 바탕으로 한 판단이며 시장 채택률이나 탐지율 측정이 아니다.

## 확인 범위와 환경

- 저장소: `wakeio-security-ci`
- 선언된 Node 요구사항: [`package.json`](../../package.json#L7-L12)의 `node >=22.0.0`
- 실행 환경: macOS arm64, Node `v22.22.1`로 clean consumer/Action을 재현했다. 현재 작업 셸의 Node 23에서도 전체 테스트가 동작했다.
- Linux hosted runner와 원격 macOS runner에서의 Action 실행은 하지 않았다. 현재 검증 기록도 macOS arm64 실행과 원격 미실행을 구분한다. [`docs/verification-0.3.md`](../../docs/verification-0.3.md#L3-L5)
- 검사 대상은 합성 JS/TS 파일과 패키지 자체다. 고객 소스, 비밀값, 실제 외부 API, GitHub PR, npm registry publish는 사용하지 않았다.

## 재현 명령과 결과

아래 명령은 기존 artifact를 읽고 `/tmp`에 소비자·Action 디렉터리를 만들었다. 네트워크가 필요한 scanner 다운로드는 기본 재현에서 의도적으로 `--tools none`을 사용했다.

| 확인 | 명령/입력 | 결과 |
| --- | --- | --- |
| 저장소 회귀 기준 | `npm test (Node.js 22.22.1)` | `1..99`, 99 passed, 0 failed. 이 수치는 현재 코드의 테스트 통과 근거이지 외부 runner·배포 성공 근거가 아니다. |
| npm archive 구성 | `tar -tzf artifacts/wakeio-security-ci-0.3.0-dev.1.tgz` | `package/build/src`, docs/examples, `scripts/install-tools.mjs`는 있으나 `src`, `tests`, `tsconfig.json`, `scripts/action-run.mjs`, `action.yml`은 없다. |
| 격리 npm 소비자 | `npm init -y`; `npm install --ignore-scripts --offline --save-dev /.../artifacts/wakeio-security-ci-0.3.0-dev.1.tgz`; `npx --no-install wakeio-security-ci --help` | install 성공, help exit 0. Node 22에서 실행 가능한 내장 CLI 진입점은 확인했다. |
| 내장 검사 | 소비자에서 `npx --no-install wakeio-security-ci scan --source fixture --tools none --out reports --fail-on high` | exit 0; 2 completed, 1 not applicable, 0 findings; `report.json`, `report.sarif`, `report.md` 세 파일 생성. |
| 기본 external 도구 | 같은 소비자에서 `npx --no-install wakeio-security-ci scan --source fixture --out default-reports` | exit 2; `source.gitleaks=partial`, `source.osv/trivy=not_applicable`. tarball만 설치한 첫 실행은 자동으로 완료되지 않는다. |
| 설치 후 개발 script | 설치된 `node_modules/wakeio-security-ci`에서 `npm run build` | exit 1, `TS5058: The specified path does not exist: 'tsconfig.json'`. `files` allowlist와 packed scripts 계약이 어긋난다. |
| vendored Action 2회 | source archive를 `vendor/wakeio-security-ci`에 풀고 `WAKEIO_TOOLS=none ... node vendor/wakeio-security-ci/scripts/action-run.mjs`를 두 번 실행 | 각 실행에서 `npm ci`, `npm run build`, scan을 다시 수행하고 exit 0. `GITHUB_OUTPUT`에는 `report-dir=.wakeio-security-ci` 한 줄만 기록되며 job summary 파일은 생성하지 않는다. |
| Bandit 사전 조건 | 같은 Action에서 `WAKEIO_TOOLS=bandit`, `WAKEIO_BANDIT_PATH` 없음 | npm/build 뒤 `tools includes bandit; prepare Bandit separately and set bandit-path`, exit 2. Python 파일이 없는 경우에도 core의 `not_applicable`까지 도달하지 않는다. |

README의 “61 tests passed” 문구는 현재 재현된 99개와 불일치한다. [`README.md`](../../README.md#L125-L138)는 61개를, [`docs/verification-0.3.md`](../../docs/verification-0.3.md#L11-L19)는 99/99를 기록한다. 이는 배포 차단 버그는 아니지만 첫 설치 문서의 신뢰를 낮추므로 다음 릴리스에서 한 출처로 고정해야 한다.

## 우선순위별 배포 갭과 완료 조건

### P0 — 숨김 결과 디렉터리와 artifact 업로드 계약

**증거.** Action input `out`의 기본값은 `.wakeio-security-ci`다. [`action.yml`](../../action.yml#L18-L25)의 설명과 [`scripts/action-run.mjs`](../../scripts/action-run.mjs#L20-L31)가 같은 기본값을 사용한다. GitHub 예제도 이 경로를 그대로 쓰고, [`examples/github-local-action.yml`](../../examples/github-local-action.yml#L20-L35)과 [`self-test.yml`](../../.github/workflows/self-test.yml#L35-L51)은 `actions/upload-artifact@v4`에 `path: .wakeio-security-ci`만 지정한다. `include-hidden-files`가 없다.

현재 [upload-artifact 공식 README](https://github.com/actions/upload-artifact#uploading-hidden-files)는 점으로 시작하는 파일과 그런 디렉터리 안의 파일을 기본적으로 숨김으로 제외하며 `include-hidden-files: true`를 별도로 요구한다. 따라서 현재 예제는 세 report 파일을 찾지 못하거나 `if-no-files-found: error`를 사용할 때 upload 단계가 실패할 수 있다. 로컬 Action smoke에서 report 파일이 생성된 사실은 hosted artifact에 들어갔다는 증거가 아니다.

**권고.** 기본값을 `wakeio-security-reports`처럼 숨김이 아닌 경로로 바꾸고 예제·문서·output 설명을 함께 갱신한다. 숨김 경로를 유지할 이유가 있으면 모든 업로더에 `include-hidden-files: true`를 명시하고, 보고서에 들어갈 수 있는 로컬 경로·package ID·URL의 민감도를 문서화한다. 어느 선택이든 exit 0, exit 1, exit 2, Action preflight 실패 각각에서 artifact가 어떻게 되는지 원격 runner에서 확인한다.

**완료 조건.** clean GitHub runner가 합성 fixture를 검사한 뒤 artifact 안에서 `report.json`, `report.sarif`, `report.md`를 확인한다. 파일이 없을 때는 의도한 진단이 나오고, 발견·부분 검사로 exit 1/2가 되어도 결과 보존 여부가 문서와 일치한다. 결과 경로를 바꾼 예제와 Action output이 같은 계약을 사용한다.

### P0 — Action runtime build/install 의존성

**증거.** Action은 [`action.yml`](../../action.yml#L52-L74)에서 매 실행 Node 22를 설정하고, [`scripts/action-run.mjs`](../../scripts/action-run.mjs#L31-L46)에서 Action checkout을 cwd로 삼아 `npm ci --ignore-scripts`와 `npm run build`를 먼저 실행한다. source archive는 `build`를 포함하지 않고 source/scripts를 포함하는 형태다. 따라서 매 job에서 npm registry/cache와 TypeScript compiler가 필요하고, install/build 실패 시 CLI는 실행되지 않아 report-dir output도 없다. 두 번의 로컬 Action smoke 모두 npm install과 build를 반복했으며, 이는 dependency cache hit를 검증한 결과가 아니다.

**권고.** 공개 Action 배포물에 검토된 `build` 결과 또는 단일 bundled entrypoint를 포함해 consumer job에서 npm install/build를 제거한다. source archive를 계속 지원한다면 runtime build를 보조 경로로 분리하고 Node/npm/cache miss를 명시적으로 진단한다. `actions/setup-node`의 npm cache 기능은 lockfile hash를 기반으로 동작한다는 [GitHub 공식 문서](https://docs.github.com/en/actions/tutorials/build-and-test-code/nodejs)를 기준으로, cache를 도입할 경우 Node major, lockfile, Action 버전, OS/arch를 key에 포함한다.

**완료 조건.** npm registry 접근을 차단한 clean consumer가 이미 제공된 Action build를 이용해 `tools: none` source 또는 URL 검사까지 실행한다. scanner asset, OSV advisory, Trivy rule 같은 명시적인 외부 네트워크 동작은 별도로 표시된다. Action install/build 실패 시에는 exit code와 진단이 남고 성공으로 보이지 않는다. source archive와 npm CLI의 책임 범위가 README 한 곳에 정리된다.

### P1 — 외부 엔진 설치·cache·offline 계약

**증거.** installer는 [`scripts/install-tools.mjs`](../../scripts/install-tools.mjs#L32-L102)에 Gitleaks 8.30.1, OSV Scanner 2.6.0, Trivy 0.74.0과 Linux/macOS x64/arm64 asset/checksum만 선언한다. 기본 destination은 매번 새 temp 디렉터리다. [`scripts/action-run.mjs`](../../scripts/action-run.mjs#L31-L45)는 Action 실행마다 새 `mkdtemp` root를 만들고 native tools를 순차 설치한다. 이어 [`scripts/action-run.mjs`](../../scripts/action-run.mjs#L59-L70)는 `TRIVY_CACHE_DIR`를 child environment에 넣지만, 실제 환경 필터는 [`src/source/process.ts`](../../src/source/process.ts#L25-L41)에서 이 변수를 허용하지 않는다. Trivy adapter는 별도로 stage 임시 디렉터리의 private cache/module dir를 사용하고 정리한다. [`src/source.ts`](../../src/source.ts#L329-L369)

결과적으로 같은 job의 Action 재실행은 binary 다운로드를 반복할 수 있고, 현재 Action에는 tool binary, Trivy rule/cache, OSV advisory DB를 재사용하는 입력이나 cache 단계가 없다. `--osv-offline`은 미리 준비한 절대 DB 경로를 요구하지만 Action이 그 DB를 준비하거나 cache hit를 판별해 주지 않는다. installer도 checksum을 확인하지만 binary version output, rule bundle, advisory DB 시점, network mode를 report에 넣지 않는다.

**권고.** 설치 root와 cache root를 계약으로 분리하고, tool/version/OS/arch/asset checksum/ruleset 또는 DB revision을 포함한 immutable key로 binary·Trivy cache·OSV DB를 캐시한다. cache miss/hit, 필요한 URL, offline 가능 여부를 preflight에 출력한다. 실제 실행에 전달되지 않는 `TRIVY_CACHE_DIR`와 adapter의 `--cache-dir`를 하나의 명시적인 설정으로 정리한다. 설치가 끝나면 binary `--version`과 checksum, 사용한 rule/DB 상태를 안전한 provenance 메타데이터로 남긴다. 원문 소스·토큰·응답을 외부로 보내는 telemetry는 추가하지 않는다.

**완료 조건.** 동일한 Node/OS/arch와 lock/tool version으로 두 번째 CI 실행에서 binary 재다운로드가 없고 cache hit가 로그에 보인다. cache miss에서는 정확한 네트워크 대상과 다운로드 이유가 보인다. checksum 또는 version 불일치는 exit 2와 명시된 원인으로 끝난다. `osv-offline`은 준비된 DB로 성공하고 DB가 없으면 “offline DB를 준비하라”는 partial/error를 남긴다. 캐시되지 않은 advisory/rule을 완료로 오인하지 않는다.

### P1 — npm tarball의 첫 실행과 packed script 계약

**증거.** [`package.json`](../../package.json#L17-L34)의 `files`는 `build/src`와 문서를 넣지만 `src`, `tests`, `tsconfig.json`, `scripts/action-run.mjs`, `action.yml`은 넣지 않는다. 동시에 `build`, `test`, `benchmark`, `package:release` script를 packed `package.json`에 남긴다. 실제 tarball 소비자에서 `npm run build`는 `tsconfig.json`이 없어 `TS5058`로 실패했다. 이는 `npx --no-install wakeio-security-ci ... --tools none` 실행에는 영향을 주지 않지만, 설치자가 package script를 보고 rebuild·test할 때 실패하는 공개 계약이다.

더 큰 첫 실행 문제는 기본 source tool set이다. README는 native scanner를 별도 설치하라고 설명하지만 [`README.md`](../../README.md#L51-L80) npm consumer가 tarball만 설치해 setup하는 명령이나 `install-tools` package CLI를 제공하지 않는다. tarball에는 binary도 없다. 위 소비자에서 작은 JS fixture를 기본값으로 검사하자 Gitleaks는 `partial`, OSV/Trivy는 `not_applicable`, 전체 exit는 2였다. 내장 검사만 하려면 사용자가 문서의 `--tools none`을 알아야 한다.

**권고.** 다음 중 하나를 명시적으로 선택한다.

- packed package를 CLI-only artifact로 만들고 dev-only script를 제거하거나 publish 전용 `package.json`으로 교체한다. `npm pack --dry-run`을 release gate로 둔다.
- `init` 또는 `doctor`와 같은 첫 실행 명령을 제공해 현재 플랫폼, Node, source applicability, 선택한 engine, 필요한 network/cache를 계획으로 보여준다. postinstall에서 binary를 몰래 다운로드하지 않는다.
- `install-tools`를 사용자-facing 명령으로 만들 경우, 현재의 pinned asset/checksum과 destination·cache·offline 상태를 manifest로 남기고, 기본 검사와 선택 검사 결과를 구분한다.

repository·homepage·bugs·package manager/Node 고정 정보도 package metadata와 문서의 단일 source of truth로 정리한다. npm의 [`files`, `bin`, `engines`, `os`, `cpu` package.json 계약](https://docs.npmjs.com/cli/v11/configuring-npm/package-json)을 기준으로, `engines`만으로 unsupported runtime을 강제할 수 없다는 점도 첫 실행 오류로 설명한다.

**완료 조건.** 빈 Node 22 consumer에서 공개 문서의 한 명령으로 내장 검사까지 완료하거나, external engine을 선택했을 때 설치 계획과 정확한 누락 명령이 표시된다. tarball을 `npm install --ignore-scripts`한 뒤 `npx --no-install`이 동작한다. packed package에서 노출한 `npm run` 명령은 모두 동작하거나, dev-only 명령이 tarball metadata에 노출되지 않는다. fresh npm cache와 offline local tarball 두 경우를 각각 검증한다.

### P1 — Python applicability와 Bandit 준비

**증거.** Python 문서는 Bandit을 별도 venv에 설치하고 실행 파일을 `--bandit`/`bandit-path`로 전달하라고 한다. [`docs/preview-0.3.md`](../../docs/preview-0.3.md#L5-L18)는 Bandit이 기본 세 도구에 포함되지 않으며 `--tools`가 목록을 대체한다고 설명한다. Core adapter는 Python 파일이 없으면 [`src/source/python.ts`](../../src/source/python.ts#L289-L295)의 `not_applicable`을 반환하고, 파일이 있을 때 path가 없으면 `partial`을 반환한다. 반면 Action preflight는 [`scripts/action-run.mjs`](../../scripts/action-run.mjs#L37-L46)에서 source를 검사하기 전에 Bandit path가 없으면 throw한다. Python이 없는 JS/TS 저장소도 `tools: bandit`을 선택하는 순간 exit 2다. installer의 pinned native tool 목록에는 Bandit이 없으므로 Python 설치·pip cache·버전 hash도 Action 계약 밖에 있다.

현재 Bandit B603 결과의 remediation URL도 [`src/source/python.ts`](../../src/source/python.ts#L150-L155)에 `.../plugins/subprocess_without_shell_equals_true.html`로 기록되어 있다. 공식 페이지는 [`b603_subprocess_without_shell_equals_true.html`](https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html)이므로 현재 링크는 404가 된다. 검사 결과가 발견되더라도 사용자가 바로 따라갈 수 없는 결과 사용성 결함이다.

**권고.** source applicability를 먼저 계산해 Python 파일이 없으면 Bandit setup 없이 `not_applicable`로 끝내거나, `tools: bandit` 선택 시의 사전 조건을 help와 Action output에 동일하게 표시한다. Python이 있으면 `actions/setup-python`과 exact Bandit version/hash, venv path, pip cache, Python support matrix를 제공한다. `tools`가 기본 목록을 대체한다는 현재 계약은 유지하되, Action input 설명에서 기존 native tools를 함께 쓰려면 네 개를 모두 적어야 함을 명시한다. B603를 포함한 remediation 링크는 release check에서 HTTP status 또는 known official URL 목록으로 확인한다.

**완료 조건.** Python이 없는 JS-only source에서 `tools: bandit`은 setup 실패 없이 `source.bandit=not_applicable`을 보고한다. Python source에서 path가 없으면 exit 2와 실행 가능한 설치 명령이 나온다. Python source에서 준비된 Bandit은 발견·부분·오류를 core와 Action에서 같은 의미로 보고한다. B603 보고서 링크가 공식 페이지를 열고, token·raw source 없이 remediation이 표시된다.

### P1 — Job Summary, outputs, gating과 부분 검사 UX

**증거.** Action metadata는 [`action.yml`](../../action.yml#L47-L50)의 `report-dir` output 하나만 선언한다. runner script는 [`scripts/action-run.mjs`](../../scripts/action-run.mjs#L119-L126)에서 `GITHUB_OUTPUT`에 그 경로 한 줄만 쓴다. CLI stdout에는 counts와 report 경로가 있지만 Action은 `$GITHUB_STEP_SUMMARY`에 쓰지 않고, finding count·incomplete count·effective threshold·check status를 별도 output으로 노출하지 않는다. [`examples/github-local-action.yml`](../../examples/github-local-action.yml#L20-L35)은 사용자가 artifact를 내려받아야 결과를 볼 수 있는 구조다.

현재 report/exit 계약 자체는 보수적이다. CLI는 incomplete가 있으면 exit 2, 문턱 이상의 finding이 있으면 exit 1, 완료·무발견이면 exit 0을 사용한다. [`src/report.ts`](../../src/report.ts#L123-L160) `fail-on none`도 incomplete를 성공으로 바꾸지 않는다. 문제는 이 세 상태가 PR 화면에서 구분된 요약으로 보이지 않고, Action preflight 실패 시 report 자체도 없다는 점이다.

[GitHub workflow command 공식 문서](https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#adding-a-job-summary)는 `$GITHUB_STEP_SUMMARY`에 Markdown을 쓰면 run summary에 표시된다고 설명한다. 이를 이용해 mode/source label, completed/partial/error/not-applicable counts, finding severity, threshold, report artifact path, next command를 짧게 보여준다. raw response·secret·전체 source snippet은 요약에 넣지 않는다. SARIF 업로드는 부모 분석의 fingerprint 세부와 별도로, 사용자가 opt-in할 수 있는 job으로 [`security-events: write` 권한을 요구한다는 공식 문서](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)를 따로 문서화한다.

**권고.** `report-dir`를 유지하면서 `report-json`, `report-sarif`, `report-markdown`, `exit-code`, `finding-count`, `incomplete-count`처럼 소비자가 안정적으로 읽을 outputs를 추가한다. Job Summary는 1 MiB 제한을 넘지 않도록 요약만 쓴다. partial/error/not-applicable의 차이, `--fail-on none`의 범위, setup failure와 scan result failure를 모두 Summary에 표시한다. 예제는 exit 1/2에서도 artifact 보존이 가능한 `if: always()` 흐름을 보여준다.

**완료 조건.** 실제 PR run의 Summary만 읽어도 검사 모드, check 상태, 문턱, 발견 수, 부분 검사, report 링크를 알 수 있다. exit 0/1/2와 preflight exit 2가 서로 다른 문구·outputs를 만든다. report가 없는 preflight 실패는 “결과 없음”을 “무발견”으로 보이지 않게 한다. 권한이 없는 repo에서도 기본 Action은 Summary/artifact를 사용할 수 있고, SARIF 선택 job은 필요한 entitlement/permission을 명시한다.

### P1 — GitHub Action checkout과 코드 실행 신뢰 경계

**증거.** Action은 consumer checkout을 하지 않고 `github.action_path`에서 `npm ci`, build, `scripts/action-run.mjs`를 실행한다. [`action.yml`](../../action.yml#L52-L74) 자체에는 checkout이 없고, local-vendor 예제는 [`examples/github-local-action.yml`](../../examples/github-local-action.yml#L8-L24)처럼 Action source archive를 consumer repository 안에 둔 뒤 실행한다. `action-run.mjs`는 shell 없이 argv로 child를 실행하는 점은 안전한 입력 전달에 도움이 되지만, Action 코드 자체를 build·실행한다는 신뢰 문제를 없애지 않는다. PR이 vendor 디렉터리 또는 Action ref를 바꿀 수 있는 workflow에서 secret/API policy가 같은 job에 있으면 그 코드가 trusted executable이라는 전제가 깨진다.

예제와 self-test는 `actions/checkout@v4`, `actions/setup-node@v4`, `actions/upload-artifact@v4` 같은 moving tag를 사용하며 full commit SHA pin이 없다. checkout의 기본 `persist-credentials`가 true인 점은 [checkout 공식 README](https://github.com/actions/checkout#usage)에 명시되어 있다. 현재 workflow의 `permissions: contents: read`는 권한을 줄이지만, untrusted code와 credential 전달을 별도 설계하지 않았다는 사실은 바꾸지 않는다. README가 fork PR에서 secret을 넣지 말라고 경고하는 것은 좋은 제한이지만, 사용자가 복사하는 예제 자체가 trust boundary를 강제하지는 않는다. GitHub는 third-party action을 full SHA로 pin하고 least privilege를 쓰며 untrusted PR checkout/build를 privileged `pull_request_target`와 섞지 말라고 [secure use 공식 문서](https://docs.github.com/en/actions/reference/security/secure-use)에서 안내한다.

**권고.** 공개 Action은 immutable full SHA ref 또는 검증된 release archive를 기준으로 사용하고 helper action도 같은 정책을 적용한다. trusted Action checkout과 검사할 untrusted source checkout을 서로 다른 경로로 유지한다. `persist-credentials: false`, 최소 `permissions`, secret/API policy가 필요한 trusted push 또는 승인된 별도 job, fork PR용 무자격 source job을 문서의 copy-ready 예제로 나눈다. `pull_request_target`에서 PR이 제공한 Action path를 build·실행하지 않는다. source archive의 checksum을 release 검증에 연결하고, target repository scripts를 실행하지 않는 현재 계약을 workflow 수준에서도 확인한다.

**완료 조건.** 합성 malicious PR fixture가 Action 경로·workflow 입력을 바꾸어도 scan job의 secret을 읽거나 외부로 전송할 수 없다. workflow lint/review에서 helper action ref가 full SHA이고 permission이 최소임을 확인한다. trusted push와 fork PR의 source/API job이 서로 다른 권한·secret 경로를 사용한다. 실제 runner에서 `source`가 대상 checkout으로만 전달되고 target `npm run`/build script가 실행되지 않는지 로그로 확인한다.

### P2 — Node/Linux/macOS 플랫폼 주장과 release matrix

**증거.** package는 Node `>=22.0.0`만 선언하고, Action은 [`actions/setup-node@v4`](../../action.yml#L52-L58)에서 `22` major를 요청한다. installer는 Linux/macOS x64/arm64 네 조합만 asset을 갖고, unsupported runner에서 그 사실을 오류로 말한다. [`scripts/install-tools.mjs`](../../scripts/install-tools.mjs#L121-L149)와 [`README.md`](../../README.md#L98-L104)는 macOS arm64 local exercise만 확인하고 Ubuntu workflow를 원격으로 실행하지 않았다고 기록한다. Windows asset과 Action `runs-on` 지원 표는 없다. 내장 JS/TS CLI 자체가 어느 Node 22 플랫폼에서 실행될 수 있다는 것과 native scanner 전체가 지원된다는 것은 같은 주장으로 문서화할 수 없다.

npm의 `engines`는 일반적으로 advisory이고 `os`/`cpu`는 package installation constraints라는 [npm 공식 package.json 문서](https://docs.npmjs.com/cli/v11/configuring-npm/package-json)의 구분을 따른다. 현재 package metadata와 README에는 native tool 지원 matrix, Node/npm exact version, GitHub runner/Enterprise Server 범위가 한 표로 고정되어 있지 않다.

**권고.** 다음 릴리스 전에 CLI 내장 검사와 external engine/Action을 분리한 지원표를 만든다. 최소한 Node 22 minor/architecture, Linux x64/arm64, macOS x64/arm64, Windows 미지원 여부, hosted runner와 GHES, Python/Bandit을 각각 표시한다. release CI는 실제 Linux와 macOS matrix에서 install·built-in scan·native engine smoke를 수행하고, unsupported platform은 download 전에 명확히 중단한다. Node/npm은 exact tested version 또는 `packageManager`/lockfile policy로 고정한다. 지원하지 않는 Windows에서 내장 CLI를 의도적으로 허용할지, native tool이 없는 상태를 `--tools none`으로 허용할지를 문서에서 분리한다.

**완료 조건.** 문서의 각 “지원” 셀에 최소 한 번의 clean install/action smoke 증거가 있다. Linux/macOS x64/arm64의 pinned tools가 checksum·version 확인 후 실행되고, unsupported OS/arch는 partial과 성공을 혼동하지 않는 exit 2 및 해결 안내를 낸다. Node 22 minor와 npm cache 상태를 바꾼 소비자 테스트가 재현된다. README, Action metadata, package metadata, release workflow의 표가 서로 다르지 않다.

### P2 — 공개 release/publish 경로의 부재

**증거.** README와 [`docs/distribution.md`](../../docs/distribution.md#L24-L31)는 현재 npm/Marketplace/GitHub public release가 없다고 명시한다. `package:release`는 local npm tarball, source archive, checksum을 만들 뿐이고 [`scripts/package-release.mjs`](../../scripts/package-release.mjs#L407-L483)에는 publish가 없다. [`release-check.yml`](../../.github/workflows/release-check.yml#L1-L60)도 test·benchmark·package와 workflow artifact upload까지만 수행한다. 버전 tag, npm provenance, GitHub Release, Action immutable release ref를 생성하는 workflow는 없다.

**권고.** 먼저 P0/P1 계약과 remote matrix를 통과시킨 뒤, tag version과 package version 일치·checksum·archive content·clean registry consumer·Action ref를 검토하는 별도 publish workflow를 설계한다. npm provenance나 registry token을 넣는다면 최소 권한과 dry-run/rollback 문서를 함께 둔다. 공개 전까지는 README의 “unpublished” 문구를 유지하고 `npx wakeio-security-ci` 같은 registry 경로를 암시하지 않는다.

**완료 조건.** release candidate에서 publish 이전 dry-run이 packed files, CLI help, built-in scan, external setup 안내, checksums를 검증한다. 실제 publish가 승인된 경우에만 tag·registry·GitHub Release가 생성되고, 새 consumer가 해당 registry 버전을 설치해 문서 명령을 실행한다. public distribution을 하지 않는 경우에도 source archive/npm tarball의 이름·checksum·보존 위치가 자동으로 기록된다.

## 우선 실행 순서

1. P0 artifact 경로와 Action preflight 결과 보존을 먼저 고친다. 원격 runner에서 exit 0/1/2를 확인한다.
2. Action의 runtime build/install을 prebuilt/bundled 배포물로 줄이고, 남는 network·cache 동작을 명시한다.
3. npm tarball의 packed script를 정리하고 첫 실행 `doctor`/setup 계획과 external tool 누락 안내를 제공한다.
4. Python applicability와 Bandit setup/cache를 core·Action·문서에서 같은 계약으로 맞추고 remediation 링크를 검증한다.
5. Job Summary와 안정적인 outputs를 붙여 partial/error/not-applicable와 gating을 PR UI에서 구분한다.
6. immutable action refs, checkout 분리, permissions·secret 경계를 검토한 뒤 Linux/macOS release matrix를 실제로 실행한다.
7. 위 증거가 모인 후에만 npm/GitHub public release workflow를 연다.

이 순서는 새 scanner를 추가하는 순서가 아니다. 소비자가 “설치됨”, “검사 완료”, “일부만 검사됨”, “발견이 있어 실패함”, “Action 코드가 신뢰됨”을 서로 혼동하지 않게 만드는 순서다.

## 이번 감사에서 확인하지 않은 것

실제 GitHub-hosted artifact 업로드, PR Summary/annotation 표시, Linux runner의 native binary 실행, GHES, fresh public npm registry install, 실제 고객 API·repository secret, public release는 실행하지 않았다. 따라서 위 완료 조건은 아직 제안 acceptance이며 구현 완료 주장이 아니다. 부모 통합 분석이 다루는 compare identity와 GitHub SARIF fingerprint 계약은 여기서 재현·중복하지 않았다.

## 참고한 공식 문서

- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use) — third-party action pinning, least privilege, untrusted code 경계.
- [GitHub securely using `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target) — base trust/secrets와 PR checkout 실행의 위험.
- [GitHub workflow commands: job summary](https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#adding-a-job-summary) — `$GITHUB_STEP_SUMMARY` 사용.
- [GitHub dependency caching for Node.js](https://docs.github.com/en/actions/tutorials/build-and-test-code/nodejs) — setup-node npm cache와 lockfile 기반 key.
- [actions/upload-artifact README](https://github.com/actions/upload-artifact#uploading-hidden-files) — hidden file 기본 제외와 `include-hidden-files`.
- [actions/checkout README](https://github.com/actions/checkout#usage) — `persist-credentials` 기본값과 checkout 입력.
- [Upload SARIF results to GitHub](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file) — `security-events: write`와 code scanning 업로드 조건.
- [npm package.json](https://docs.npmjs.com/cli/v11/configuring-npm/package-json) — `files`, `bin`, `engines`, `os`, `cpu` metadata 계약.
- [Bandit B603](https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html) — report remediation link target.
