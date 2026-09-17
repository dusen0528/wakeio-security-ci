# Wakeio Security CI

**출시 전에 보안 후보를 찾고, CI에서 누락된 검사를 숨기지 않는 무료 독립형 CLI·GitHub Action입니다.**

사용자가 지정한 소스 코드, HTTP 응답, 선택적인 읽기 전용 API 정책을 검사합니다. 발견 결과만 보여 주는 대신 근거·검사 범위·미완료 상태·한계를 같은 보고서에 남겨, 깨끗한 결과가 확인하지 않은 영역을 가리지 않도록 설계했습니다.

[English](README.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md) · [구현 체크리스트](docs/checklist.md) · [0.4 사용법](docs/preview-0.4.md) · [검증 기록](docs/verification-0.4.md)

**프리뷰:** `0.4.0-dev.1` · Apache-2.0 · Node.js 22+

무료로 로컬에서 실행합니다. Wakeio 계정·구독·호스팅된 Wakeio 서비스·LLM·소스 업로드가 필요하지 않으며 사용 텔레메트리도 전송하지 않습니다. 이 프리뷰는 아직 npm 레지스트리 배포를 사용하지 않으므로 아래 Git checkout 또는 GitHub Action으로 실행합니다.

## 무엇을 검사하나요?

| 범위 | 확인할 수 있는 내용 | 기억해야 할 한계 |
| --- | --- | --- |
| 소스 코드 | 요청 입력이 SQL·HTML·프로세스·외부 요청·리디렉션 sink로 흐르는 제한된 JS/TS AST 후보, 동적 코드 실행, 일부 자격증명 형태, 선택적인 Next/React·Supabase migration 후보 | 같은 함수와 제한된 로컬 흐름 중심. 일반적인 함수 간·파일 간·타입 기반·런타임·빌드·실제 DB 검증은 제공하지 않음 |
| 공개 URL | 명시한 페이지와 같은 origin의 정적 JavaScript 모듈, 전송, 보안 헤더, CSP, 쿠키, CORS, 혼합 콘텐츠, source map/debug/version 단서, DOM·비밀값 형태 후보 | 명시된 제한적 GET만 실행. 브라우저 실행, 로그인, endpoint 탐색, API 퍼징, 결제 흐름, 전체 사이트 자동 순회는 하지 않음 |
| 읽기 전용 API 정책 | 선언한 리소스 식별자와 별도의 보호 데이터 canary를 기준으로 identity, 소유자·다른 계정·비로그인 사용자의 접근 결과 | 정책에 정의한 GET 요청만 실행. 쓰기, 자동 로그인, endpoint 탐색, 일반 퍼징은 하지 않음 |
| 전후 보고서 | 논리적 프로젝트 식별자, 의미 기반 source anchor, 새 문제·변경 문제·같은 문제, `not_observed`·`unverified` 상태 | 나중에 발견되지 않았다는 사실만으로 수정 완료라고 판단하지 않음 |

소스와 URL 범위는 한 보고서에 함께 담을 수 있습니다. API 정책은 선택 사항이며 환경변수 이름으로 자격증명을 참조합니다. 토큰과 canary 값은 보고서에 기록하지 않습니다. [API 정책 예제](examples/api-authorization-policy.json)와 [API 안내](docs/preview-0.4-api.md)를 참고하세요.

내장 소스 규칙은 의도적으로 좁게 잡았습니다. 예를 들어 요청값이 로컬 변수를 거쳐 raw SQL 호출·JSX HTML sink·프로세스 호출·외부 요청·리디렉션으로 전달되는 장면을 후보로 표시합니다. 구조 분해·반복문 binding, 일부 Next route 입력, 정적 client/server 환경변수 노출, Supabase migration 이력 후보도 확인합니다. 결과는 검토할 후보이며 exploit 재현이나 애플리케이션 전체의 안전 보장이 아닙니다.

## 빠른 시작: 내장 검사만 실행하기

공개 저장소를 clone한 뒤 로컬에서 빌드합니다.

```sh
git clone --branch main https://github.com/dusen0528/wakeio-security-ci.git
cd wakeio-security-ci
npm ci --ignore-scripts
npm run build

node build/src/cli.js doctor --source /path/to/your-app --tools none
node build/src/cli.js scan \
  --source /path/to/your-app \
  --tools none \
  --out wakeio-security-reports
```

`doctor`는 읽기 전용으로 대상 디렉터리의 파일 수와 적용 가능성을 확인하며 대상 코드·패키지 매니저·scanner·네트워크 요청을 실행하지 않습니다. `--tools none`은 내장 검사만 선택해 외부 엔진을 준비하지 않습니다. 검사 대상 파일은 데이터로 읽으며 대상 프로젝트의 install script·hook·build·test는 실행하지 않습니다.

URL만 검사할 때는 시작 URL과 추가 페이지를 직접 지정합니다.

```sh
node build/src/cli.js scan \
  --url https://your-app.example \
  --page https://your-app.example/pricing \
  --tools none
```

소스와 URL을 한 보고서에 함께 넣을 수도 있습니다.

```sh
node build/src/cli.js scan \
  --source /path/to/your-app \
  --url https://your-app.example \
  --tools none
```

로컬·사설 URL/API 대상은 `--allow-private`를 명시해야 하며 metadata 주소 차단은 계속 적용됩니다. URL 수집은 지정한 페이지, 같은 origin의 정적 모듈 그래프, 요청·바이트·시간 예산 안에서만 동작하고 전체 페이지 수는 최대 8개입니다.

## GitHub Actions

가장 간단한 CI 경로는 초기 `main` 브랜치의 공개 Action입니다. 아래 예제는 내장 검사만 명시적으로 선택하고, 발견 결과로 job이 실패해도 보고서를 artifact로 보관하며, 주변 Action은 현재 저장소의 고정 SHA를 재사용합니다.

```yaml
name: wakeio-security-ci

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: 애플리케이션 checkout
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false

      - name: Wakeio Security CI 실행
        uses: dusen0528/wakeio-security-ci@main
        with:
          source: .
          tools: none
          out: wakeio-security-reports
          fail-on: high

      - name: 검사 보고서 업로드
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: wakeio-security-ci-reports
          path: wakeio-security-reports
          if-no-files-found: error
```

복사해서 쓸 수 있는 파일은 [`examples/github-action.yml`](examples/github-action.yml)입니다. `@main`은 프리뷰를 바로 시험하기 좋은 이동형 참조입니다. 운영 workflow에서는 `dusen0528/wakeio-security-ci`를 검토한 commit SHA로 고정하고 변경을 직접 검토하세요. 주변 Action도 검토한 SHA를 유지하는 편이 좋습니다. 이 Action은 Node.js 22를 준비하고 대상 프로젝트의 script를 실행하지 않으며 Job Summary와 `report.md`, `report.json`, `report.sarif`, `action-status.json`을 출력 디렉터리에 남깁니다.

## 선택형 외부 엔진

예제에서는 외부 엔진을 명시적으로 선택합니다. 소스 CLI의 기존 기본값은 `gitleaks,osv,trivy`이므로 내장 검사만 원하면 `--tools none`을 지정하고, 외부 엔진을 사용할 때는 검토한 목록을 정확히 지정하세요. Bandit은 자동으로 켜지지 않습니다.

| 엔진 | 이 프리뷰에서 사용한 버전 | 추가하는 검사 | 중요한 한계 |
| --- | ---: | --- | --- |
| Gitleaks | 8.30.1 | 수집한 파일의 Secret 패턴 | 현재 수집 파일 기준이며 전체 Git 이력·키 유효성은 확인하지 않음 |
| OSV-Scanner | 2.6.0 | 지원 lockfile과 자체 포함된 고정 Python requirements의 advisory | advisory 조회이며 source reachability·악성코드 분석 아님. 온라인 모드에서는 패키지 식별자가 공개 OSV 서비스로 전송될 수 있음 |
| Trivy | 0.74.0 | Dockerfile·Kubernetes·Terraform 설정 | 설정 검사만 하며 이미지 CVE·실제 클라우드 상태·외부 module까지 검증하지 않음 |
| Bandit | 1.9.4 | 선택적인 Python AST 검사 | 별도 실행 파일을 준비해야 하며 선택한 Python 파일만 검사하고 대상 코드는 실행하지 않음 |

예시는 다음과 같습니다.

```sh
# 검토한 native engine만 명시적으로 켭니다.
node build/src/cli.js scan --source /path/to/app --tools gitleaks,osv,trivy

# Bandit은 별도로 준비한 뒤 명시적으로 선택합니다.
node build/src/cli.js scan \
  --source /path/to/python-app \
  --tools bandit \
  --bandit /path/to/venv/bin/bandit
```

선택형 엔진 명령을 실행하기 전에 고정된 native binary를 준비하거나 신뢰할 수 있는 실행 파일 경로를 지정해야 합니다. 설치기·cache·provenance는 [배포 안내](docs/preview-0.4-distribution.md)에 정리했습니다. 설치기는 native release asset의 SHA-256을 확인합니다. OSV는 `--osv-offline`과 준비된 로컬 DB를 사용할 수 있으며 DB가 없으면 완료로 처리하지 않습니다. Trivy는 scanner가 관리하는 policy 또는 DB 데이터를 내려받을 수 있습니다. 이 외부 네트워크 동작은 Wakeio 자체의 동작과 별개이며, Wakeio는 소스를 업로드하거나 LLM을 호출하지 않습니다.

## 보고서와 종료 코드

각 검사는 `wakeio-security-reports/`(또는 `--out DIR`)에 다음 세 파일을 기본으로 만듭니다.

- `report.md`: 사람이 읽는 요약, 근거, 한계, 수정 방향;
- `report.json`: 구조화된 검사·범위·provenance·발견·미완료 상태;
- `report.sarif`: 선택적인 code-scanning workflow용 SARIF 2.1.0.

발견 결과는 candidate·observation·advisory를 구분합니다. 도구 누락, timeout, 변경되거나 알 수 없는 provenance, 지원하지 않는 입력, 중복된 의미 anchor, 수집 한계는 보고서에 남고 검사를 미완료로 만들 수 있습니다.

| 종료 코드 | 의미 |
| ---: | --- |
| `0` | 적용 가능한 검사가 끝났고 선택한 기준 이상 발견이 없음 |
| `1` | 선택한 `--fail-on` 기준 이상의 발견이 있음(기본 high) |
| `2` | 설정 오류, 실패·미완료 검사, 또는 적용 가능한 보안 검사가 없음 |

`--fail-on none`은 발견 결과에 따른 실패만 끄며 미완료 검사를 통과로 바꾸지 않습니다. 보고서는 원문 소스와 Secret 값을 제외하지만 프로젝트 경로·패키지 식별자·URL을 포함할 수 있으므로 CI artifact 공개 범위를 확인하세요.

## 읽기 전용 API 정책과 비교

API 정책은 identity endpoint와 기대 principal, 소유자·다른 계정·비로그인 actor, 리소스 식별자, 보호 데이터 canary, 허용할 거부 상태를 선언합니다. 자격증명은 환경변수 이름으로 참조합니다. identity와 소유자의 정상 접근을 deny probe 전후에 확인합니다. 다른 actor가 보호 canary를 받으면 HTTP 상태가 `403`이어도 발견 결과입니다. 오류 응답에 공개 ID만 반복된 경우만으로 정보 유출을 확정하지 않습니다.

```sh
node build/src/cli.js scan \
  --api-policy /path/to/your-api-policy.json \
  --tools none
```

저장소에 포함된 정책은 `127.0.0.1:8877`의 합성 서버를 대상으로 합니다. 재현하려면 다른 터미널에서 `node examples/api-authorization-demo.mjs --vulnerable`을 실행하고 두 demo authorization 환경변수를 export한 뒤 `--allow-private`를 추가하세요. 전체 명령과 수정된 fixture 실행은 [API 안내](docs/preview-0.4-api.md)에 있습니다.

쓰기·결제·자동 로그인·endpoint 탐색·일반 퍼징은 수행하지 않습니다. 만료된 자격증명, 구분되지 않는 actor, rate limit, 예상하지 못한 응답, 불완전한 control은 partial 또는 unverified로 남습니다.

수정 전후를 비교하려면 논리적 프로젝트 식별자와 검사 옵션을 유지하세요.

```sh
node build/src/cli.js scan \
  --source /path/to/app \
  --project-id team/app \
  --tools none \
  --out /tmp/wakeio-before

# 수정한 뒤 같은 범위와 옵션으로 다시 검사합니다.
node build/src/cli.js scan \
  --source /path/to/app \
  --project-id team/app \
  --tools none \
  --out /tmp/wakeio-after

node build/src/cli.js compare \
  --before /tmp/wakeio-before/report.json \
  --after /tmp/wakeio-after/report.json \
  --out /tmp/wakeio-comparison
```

범위가 다르거나 미완료인 검사를 깨끗한 결과로 보여 주지 않습니다. 이전 발견이 사라져도 `not_observed`이며 자동 수정 인증서가 아닙니다. [비교 안내](docs/preview-0.4-comparison.md)를 참고하세요.

## 작은 합성 예시

다음은 실제 애플리케이션 결과가 아니라 명시적으로 표시한 회귀 fixture입니다.

```text
candidate · high · ast:sql-input-sink
app/routes/users.ts:4
evidence: req.query.id -> statement -> db.query(...)
review: DB driver의 parameter binding을 사용하고 생성된 query를 확인하세요
```

Wakeio는 인식한 코드 흐름과 검토가 필요한 이유를 보고합니다. fixture를 실행하거나 exploit을 보내지 않으며 주변 애플리케이션의 안전을 보장하지 않습니다.

## 검증 기록과 알려진 한계

현재 `0.4.0-dev.1` 로컬 검증 기록에서 `npm test`는 **144/144** 통과했습니다. 30개 합성 JS/TS benchmark는 취약 15개·수정 15개로 구성되며, 취약 기대 결과 15개 중 13개를 탐지했고 수정 사례의 false positive는 0개였습니다. 함수 간·파일 간 흐름 2개는 알려진 미지원 항목으로 남아 있습니다. 이는 제한된 detector의 회귀 신호이며 실제 운영 탐지율·전체 커버리지·보안 인증이 아닙니다.

로컬 검증은 다음과 같이 재현할 수 있습니다.

```sh
npm test
npm run benchmark -- --strict
```

[구현 체크리스트](docs/checklist.md), [0.4 안내](docs/preview-0.4.md), [검증 기록](docs/verification-0.4.md)에 실제 범위가 적혀 있습니다. 완전한 침투 테스트, exploit 생성, 브라우저·런타임 검증, 광범위한 API 퍼징, 실제 DB·클라우드 검사, 이미지 CVE 검사, 서비스 전체 안전 판정은 이 프로젝트의 계약에 포함되지 않습니다.

## 기여와 라이선스

규칙을 추가할 때는 취약·수정 합성 fixture, 근거와 한계, 호환 가능한 라이선스를 함께 남겨 주세요. [CONTRIBUTING.md](CONTRIBUTING.md)와 [SECURITY.md](SECURITY.md)를 참고하세요. Wakeio Security CI는 Apache-2.0이며 외부 scanner와 rule은 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)의 각 라이선스를 따릅니다.
