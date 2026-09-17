# OSS 고도화 검증 — 0.2.0-dev.1

검증일: 2026-09-15. 환경: 로컬 macOS arm64, Node.js 22.22.1. 공개 registry·GitHub Release·원격 CI 실행과 구분한 로컬 검증 기록이다. 이전 버전은 [v0.1 검증](verification.md)을 보존한다.

## 실제 변경

- JS/TS의 직접 입력 후보를 같은 함수의 변수·구조 분해·재대입·조건 분기까지 확장했다. 입력에 관계된 불명확한 helper 반환값은 낮은 confidence 후보로 남긴다.
- CLI 시작 표시와 발견 수·미완료 검사 수·심각도·종료 기준·보고서 위치 요약을 추가했다. 원문 소스·Secret은 터미널 요약에 출력하지 않는다.
- 위험 코드 15개와 정상 코드 15개의 합성 corpus, 룰/위치 기반 비교, 알려진 미탐 포함 집계, strict gate를 추가했다.
- 필터링된 소스/npm archive와 버전별 SHA-256 manifest를 만드는 스크립트, 기여 지침, issue 양식, release-check workflow를 추가했다.
- 영문 README를 기본 진입점으로 정리하고 한국어 사용법을 별도로 보존했다. 첫 화면의 기능·예시·수치는 현재 구현과 합성 검증 범위에 한정한다.
- Next.js/React/Supabase, Node/Python, API·권한 검사 세 영역을 [OSS 고도화 설계](oss-product-design.md)에 반영했다. Python adapter·프레임워크 전용 검사·API·권한 runner는 이번 실행 기능에 포함되지 않는다.

## 부모 에이전트 검토와 테스트

Luna max 서브에이전트가 분석기·벤치마크·패키징을 나누어 구현하고, 부모 에이전트가 코드 검토와 아래 통합 검증을 수행했다.

`npm test`: **61개 통과, 실패 0, 건너뜀 0**. TypeScript 빌드를 포함한다.

검토 과정에서 보완한 항목:

- 조건부 고정값 대입이 다른 실행 경로의 입력을 지우지 않도록 보수적으로 합친다.
- block/loop shadowing이 바깥 변수의 입력 흐름을 지우지 않도록 한다.
- 지원하지 않는 property 대상 구조 분해가 분석기를 중단시키지 않도록 한다.
- 정상 SQL 매개변수 전달과 주석·문자열 속 입력 이름을 위험 흐름과 구분한다.
- 합성 벤치마크의 정상 코드 오탐 비율은 정상 코드에서 발생한 오탐만 분자로 사용한다. 중복 탐지를 포함한 per-rule/global 집계도 검증했다.
- 패키징의 symlink·중첩 출력 경로·민감/생성 파일 제외, 반복 archive 무결성을 검증했다.

## 동일 corpus로 구버전과 비교

기존 v0.1 npm archive를 별도 디렉터리에 설치한 엔진과 현재 빌드를 동일한 최종 corpus에 실행했다. `runSource({root, tools: []})`를 사용했으며 fixture를 설치·빌드·실행하지 않았다. 외부 취약점 DB도 사용하지 않는다.

| 측정 | v0.1.0 | 0.2.0-dev.1 |
| --- | ---: | ---: |
| 위험 사례의 기대 finding | 15 | 15 |
| 기대 finding 탐지 | 6 | 13 |
| 전체 미탐, 알려진 한계 포함 | 9 | 2 |
| 정상 사례에서 오탐이 나온 사례 | 0 / 15 | 0 / 15 |
| 전체 추가/중복 오탐 finding | 0 | 0 |
| 현재 지원 범위 내 미탐 | 7 | 0 |
| strict 종료 코드 | 1 | 0 |

남은 두 사례는 호출 함수 내부와 파일 경계를 거쳐 sink에 도달하는 SQL 입력이다. 이 분석기는 호출 관계나 타입을 해결하지 않는다. 불명확한 helper 호출에서 후보를 찾았다는 사실도 함수 내부를 분석했다는 증거가 아니다.

다섯 룰 계열(SQL·HTML·프로세스·외부 요청·redirect)의 작은 합성 집합이다. **13/15를 실서비스 탐지율이나 전체 보안 커버리지로 해석하면 안 된다.** 해당 집합 밖의 미탐·오탐과 실제 프레임워크 동작은 별도 검증이 필요하다.

측정 원본의 집계·룰별 결과·corpus SHA-256은 [benchmark-comparison.json](benchmark-comparison.json)에 있다. 실행 방법과 기대값은 [벤치마크 문서](../benchmarks/README.md)에 있다. `--strict`는 지원 범위의 FP/FN을 gate하며 알려진 미탐을 전체 집계와 별도 목록에 계속 표시한다.

## 실제 외부 엔진과 CLI

합성 source fixture에 Gitleaks 8.30.1, OSV-Scanner 2.6.0, Trivy 0.74.0 실제 실행 파일을 사용했다.

- inventory·내장 AST·Gitleaks·OSV·Trivy **5개 check completed**, incomplete 0.
- findings 10개, high 기준 종료 코드 1. 이는 알려진 합성 fixture의 실행 확인이며 일반적인 탐지율 측정이 아니다.
- 새 버전 JSON·SARIF·Markdown을 생성했다. 기존 파서·보고서·경계 테스트도 함께 통과했다.

생성한 npm tarball을 독립 consumer 디렉터리에 `npm install --ignore-scripts --offline`으로 설치했다. 기존 로컬 npm cache로 의존성이 준비되었으므로 이 설치가 모든 새 환경의 오프라인 설치를 보장하지는 않는다.

실제 `node_modules/.bin/wakeio-security-ci` 심볼릭 링크를 통해 확인했다.

| 입력 | 관찰 |
| --- | --- |
| help | 도움말 출력, exit 0 |
| 변수로 전달되는 SQL 입력 fixture | finding 1개, exit 1 |
| 정상 매개변수 SQL fixture | exit 0 |
| 존재하지 않는 소스 경로 | INCOMPLETE, exit 2 |
| 로컬 HTTP fixture, URL만 제공 | `/`, `/app.js` GET 확인, check completed, exit 0 |

URL fixture는 `--allow-private`로 명시한 로컬 테스트 서버다. 공개 고객 사이트, 로그인 뒤 화면, 실제 악용·결제 동작을 검사한 것이 아니다.

## 배포 파일 검증

`npm run package:release`는 버전을 읽어 소스 archive, npm tarball, 두 파일의 체크섬 manifest를 만든다. 공개 업로드는 수행하지 않는다.

- 소스 archive에 action, lockfile, 소스, tests, scripts, docs, benchmark corpus가 포함됨을 확인했다.
- npm tarball에서 built CLI가 실행됨을 확인했다.
- 두 archive에서 `.git`, `node_modules`, `.env*`, 실제 보고서 디렉터리, `benchmarks/results`, 불필요한 `build/tests` 제외를 확인했다.
- 출력 파일/디렉터리 및 조상 symlink, `docs/releases`처럼 복사 대상 안에 둔 출력 경로를 거절하는 회귀 테스트가 통과했다.
- 기존 일반 artifact는 교체 가능하며 symlink 대상 내용은 보존한다. source/npm 반복 생성의 동일 SHA-256은 이 로컬 환경의 테스트로 확인했다. 서로 다른 OS·tar·npm 버전 간 동일 바이트는 보증하지 않는다.
- `shasum -a 256 -c`로 manifest를 확인했다. 최종 배포 파일의 체크섬은 artifact manifest를 기준으로 한다.

원래 Wakeio 프로젝트에서 기록해 둔 백엔드 72개 파일의 SHA-256은 변경 0개였다. 이번 수정은 별도 `wakeio-security-ci` 저장소에 있다.

## 남은 검증과 범위

GitHub-hosted Linux workflow, registry 설치, Docker 배포, 실제 외부 개발자의 첫 실행·수정·재검사는 수행하지 않았다. 현재 정적 분석은 전체 프로그램·프레임워크 의미를 분석하지 않으며, URL 검사는 공개 응답 범위다. API·계정별 인가·결제 sandbox·실제 RLS/cloud 점검은 설계 상태다. 세 사용자층을 모두 지원하는 제품 전체가 완성됐다는 기록이 아니다.
