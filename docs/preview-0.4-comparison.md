# 0.4 개발 프리뷰: 비교와 반복 검사

0.4의 비교 기능은 이전 보고서의 경고를 다음 실행에서 다시 확인할 때 사용할 수 있는 근거를 정리한다. `compare`는 baseline을 숨기거나 발견을 지우지 않는다. 두 보고서가 같은 범위와 완료 상태라는 선언을 검증할 수 없으면 exit 2를 반환한다.

## 논리 프로젝트와 실행 범위

CI checkout과 도구 cache는 실행마다 다른 임시 경로를 사용할 수 있다. 반복 비교가 필요한 경우 저장소에 재사용할 논리 ID를 지정한다.

```sh
node build/src/cli.js scan --source . \
  --project-id acme/example \
  --tools none --out results/current
```

`--project-id`가 있으면 scope fingerprint는 절대 checkout 경로와 도구 설치 경로를 포함하지 않는다. URL, 선택한 check, 요청 옵션, 규칙 세트, project ID는 계속 범위에 포함된다. Action에서는 `project-id` 입력을 사용하며 비워 두면 `github.repository`를 기본값으로 전달한다. 서로 다른 프로젝트 ID는 비교할 수 없다.

실행 report에는 선택한 engine의 이름·상태·bounded SHA-256과 source 내용 hash가 provenance로 기록될 수 있다. 실제 engine SHA가 달라지면 비교할 수 없고, missing·unreadable·unknown engine도 같은 이유로 unverified다. Bandit은 보통 짧은 virtualenv wrapper를 실행하므로 wrapper SHA만으로 Python package/runtime까지 증명하지 않으며 `banditRuntime=unknown`으로 남긴다. OSV database나 Trivy rule bundle처럼 시점을 확인하지 못한 외부 데이터도 `unknown`으로 남기며 같은 데이터라고 주장하지 않는다. source 내용 hash는 실행 증거이지 scope 동일성 조건이 아니다.

완료된 외부 check마다 provenance에 해당 engine의 `available` 상태와 유효한 소문자 SHA-256이 있어야 한다. OSV는 `osvDatabase`, Trivy는 `trivyDatabase`와 `trivyChecksBundle`, Bandit은 `banditRuntime` 데이터 소스 항목도 요구하며 값이 없거나 `unknown`이면 비교를 unverified로 남긴다. Gitleaks에는 별도 advisory 데이터 소스 항목을 요구하지 않지만 engine 증거는 동일하게 필요하다. source 내용 hash만 있거나 다른 engine만 기록한 report를 외부 scanner 실행의 증거로 간주하지 않는다.

논리 ID를 지정하지 않은 로컬 실행은 이전 호환성을 위해 보수적으로 절대 source 경로를 scope에 사용한다. 보고서에 scope가 없거나 규칙 세트·Wakeio 버전·check 집합·완료 상태가 달라도 비교 결과는 unverified다.

## 경고 매칭

검사기가 64자리 소문자 hex `comparisonKey`를 제공하면 `compare`는 같은 check 안에서 그 key를 우선 사용한다. 파일의 line·column은 표시 위치이므로 상단에 주석이나 import가 추가되어도 같은 semantic key는 `unchanged`로 남을 수 있다. key가 없는 legacy finding은 위치 기반 ID를 사용하므로 이동 시 `new`와 `not_observed`가 될 수 있다.

같은 check에서 동일한 semantic key가 두 번 나오면 어느 경고가 어느 경고인지 결정하지 않는다. 관련 항목은 `unverified`로 보존되고 비교 exit code는 2다. 위치가 같다는 이유로 중복을 임의로 합치지 않는다. `not_observed` 역시 코드 삭제나 detector 변화의 결과일 수 있으므로 수정 완료나 안전을 증명하지 않는다.

## 비교 명령과 결과

```sh
node build/src/cli.js compare \
  --before results/before/report.json \
  --after results/after/report.json \
  --out results/comparison \
  --fail-on high
```

결과의 상태는 다음과 같다.

- `new`: after에서 새로 관찰된 finding
- `changed`: 같은 finding의 severity 또는 confidence가 바뀜
- `unchanged`: 같은 finding이 같은 수준으로 다시 관찰됨
- `not_observed`: comparable한 after에서 이전 finding이 관찰되지 않음
- `unverified`: 범위·provenance·check 완료 상태 또는 매칭이 검증되지 않음

비교가 unverified이면 `comparison.json`과 `comparison.md`를 계속 쓰지만 exit 2다. comparable한 결과에서 fail threshold 이상의 `new`/`changed`가 있으면 exit 1, 그 외는 exit 0이다. `--fail-on none`은 finding threshold만 끄며 unverified 비교를 성공으로 바꾸지 않는다.

## SARIF와 PR 업로드

`report.sarif`는 Wakeio 자체 위치 fingerprint와 별도로 `partialFingerprints`를 기록한다. detector가 semantic `comparisonKey`를 제공하면 그 값을 사용하고, 그렇지 않으면 위치 기반 fingerprint를 사용한다. 실행 category와 automation ID는 `wakeio-security-ci/<mode>`로 안정화한다. SARIF 표준 알고리즘을 확인하지 않은 `primaryLocationLineHash`를 만들어 내지 않는다. GitHub 업로드에서 파일 경로와 commit/category를 어떻게 연결할지는 사용하는 업로드 action의 설정도 함께 확인한다. [GitHub SARIF 지원 문서](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)

## URL의 선택 페이지

URL scan은 root URL을 항상 먼저 가져온다. 추가 페이지는 같은 origin URL로만 반복 지정할 수 있다.

```sh
node build/src/cli.js scan --url https://example.test \
  --page /docs --page /settings --max-pages 3 \
  --out results/url
```

`--max-pages`는 root를 포함해 최대 8이며, 페이지·GET·응답 바이트·시간 예산은 공유된다. cross-origin, dynamic import, browser execution, form submission, authentication, 전체 사이트 crawl은 이 옵션으로 활성화되지 않는다. 제한에 걸린 페이지와 미검사 범위는 check note와 metric에 남는다.

이 프리뷰는 두 보고서가 같은 선언 범위인지 확인하는 도구다. 외부 scanner의 탐지 정확도, advisory database의 완전성, 전체 서비스의 안전, 사라진 finding의 수정 여부를 보증하지 않는다.
