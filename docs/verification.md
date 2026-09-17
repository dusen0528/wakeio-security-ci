# v0.1 검증 기록

검증일: 2026-09-15. 구현 환경: macOS arm64, Node.js 22.22.1. 검사는 로컬 합성 프로젝트와 HTTP fixture에서 수행했다. 실제 고객 시스템을 검사한 결과가 아니다.

## 구현 범위

| 입력 | 구현된 검사 | 범위 밖 |
| --- | --- | --- |
| 소스 | 제한된 파일 수집, JS/TS AST 후보, Gitleaks CLI, OSV lockfile 의존성 조회, Trivy Dockerfile/Kubernetes/Terraform 설정 | 전체 언어의 SAST, 앱 실행, 빌드·설치 스크립트, 컨테이너 이미지 CVE 및 런타임 |
| URL | 제한된 HTML 및 같은 origin 연결 JS GET, 헤더·쿠키·전송·노출·DOM 후보 | 로그인, 사용자 데이터, 결제·관리자 인가, 퍼징, 전체 DAST |
| CI | CLI와 composite Action, JSON/SARIF/Markdown, 심각도 기준 실패 및 검사 오류 구분 | GitHub/npm/Marketplace 공개 배포, 호스팅된 CI 실운영 |

적용 대상이 없는 개별 검사는 `not_applicable`로 표시한다. 요청한 검사가 실패하거나 제한 때문에 누락되면 `error` 또는 `partial`이다. 파일 목록만 수집하고 보안 검사를 하나도 수행하지 못한 실행은 성공으로 처리하지 않는다.

## 확인한 동작

- TypeScript 빌드 및 자동 테스트 41개가 통과했다. 검사는 실제 로컬 HTTP 요청, 기본 사설 주소 차단, 다른 origin 요청 차단, 응답 크기 제한, scanner 오류·비정상 JSON, Secret 마스킹, 보고서 쓰기와 CI 종료 코드를 포함한다.
- 설치기를 직접 실행하여 Gitleaks 8.30.1, OSV-Scanner 2.6.0, Trivy 0.74.0의 macOS arm64 release를 내려받고 고정 SHA-256 검증에 성공했다. Linux 및 macOS x64 asset은 고정되어 있지만 해당 운영체제에서 실제 설치한 결과는 아니다.
- 위 실제 바이너리 세 개로 합성 소스 프로젝트를 검사했다. JS/TS 후보 1개, Gitleaks 후보 2개, OSV advisory 5개, Trivy 설정 결과 2개가 정규화되었다. 기준 이상 발견에 따른 exit 1과 세 보고서 생성을 확인했다. advisory 수는 DB 갱신에 따라 달라질 수 있다.
- OSV는 이 테스트에서 공개 패키지 식별자를 온라인 조회했다. 준비된 DB를 이용한 offline 성공 경로는 아직 실행하지 않았다. DB 없는 offline 실행을 성공으로 처리하지 않는 동작은 확인했다.
- Trivy가 일반 `tsconfig.json`에서 `Results` 없이 반환하는 실제 정상 출력과, Dockerfile에서 PASS/FAIL 항목을 함께 반환하는 출력을 확인했다. 외부 module·파일 접근이 필요한 Terraform 설정은 별도 partial로 기록하고 해당 파일을 Trivy에 전달하지 않는다.
- 별도 도구 checkout과 소비자 checkout에서 Action entrypoint를 직접 실행했다. 공백과 세미콜론이 들어간 소스 경로가 데이터로 전달되었고, 소비자의 npm 설치 스크립트는 실행되지 않았다. 보고서는 소비자 workspace의 지정 경로에 생성되었고 exit 1 및 `GITHUB_OUTPUT` 경로가 유지되었다.
- 소스 Action archive를 새 소비자 디렉터리의 `vendor/`에 풀고 URL 전용 Action entrypoint를 실행했다. 외부 scanner 설치 없이 로컬 HTML과 연결 JS의 GET 두 번만 발생했고, 보고서 생성·exit 0·`GITHUB_OUTPUT`을 확인했다. 이는 macOS 로컬 실행이며 GitHub의 Linux runner 실실행은 아니다.
- npm tarball을 별도의 프로젝트에 실제 설치했다. npm이 생성한 CLI 심볼릭 링크를 통해 도움말, 깨끗한 JS 파일의 exit 0, 위험 후보가 있는 JS의 exit 1, 잘못된 옵션의 exit 2와 세 보고서를 확인했다.
- 실제 소스 결과 SARIF와 특수문자·참조 URL을 포함한 SARIF를 [OASIS SARIF 2.1.0 공식 스키마](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json)로 검증했다.
- 기존 Wakeio 백엔드·테스트·설정 72개 파일의 SHA-256을 분리 작업 전후 비교하여 변경이 없음을 확인했다. 기존 백엔드 114개 테스트 기록과 이 패키지의 테스트 수는 별개다.

## 배포 검증

| 항목 | 결과 |
| --- | --- |
| 전체 자동 테스트 | 41개 통과, 실패·skip 0, Node.js 22.22.1 |
| 독립 npm tarball 설치 및 실행 | 도움말, exit 0/1/2, JSON/SARIF/Markdown 생성 통과 |
| 전체 소스 Action archive | 소스·lockfile·빌드·실행 파일 포함 확인, 새 폴더에서 압축 해제 후 URL Action 실행 통과 |
| npm 의존성 audit | 조회 시점 알려진 취약점 0개 |

## 사용·운영 시 구분

npm tarball은 빌드된 CLI와 문서·설치기를 담는다. 소스 Action archive는 `action.yml`, 소스·테스트, lockfile, 빌드 설정, 설치·실행 스크립트와 예제를 담는다. Action에는 전체 소스 archive를 사용한다. 두 산출물 모두 `node_modules`, 실제 고객 소스, 원본 Secret, 스캔 보고서를 포함하지 않는다.

새 저장소는 무료 Apache-2.0 코드이며 Wakeio 서버·AI 토큰·가입이 필요 없다. runner의 실행 시간·디스크·네트워크는 실행 환경의 정책을 따른다. OSV의 패키지 조회 및 scanner/정책 다운로드에는 네트워크가 필요할 수 있다.

검사 범위와 결과 근거를 유지하는 개발자용 도구의 v0.1이다. 고객 프로젝트에서의 정확도, 원격 CI 운영, 실제 인증·인가·결제 취약점 검증 또는 전문 침투 테스트 완료를 뜻하지 않는다.
