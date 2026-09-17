# 독립 OSS 범위와 공개 배포

2026-09-17 공개 배포 점검 기준으로 `wakeio-security-ci`는 별도 Apache-2.0
저장소에서 동작하는 무료 CI 도구다. 사용자는 계정, 구독, 호스팅 서버, AI
토큰 없이 자신의 checkout 또는 CI runner에서 검사를 실행한다. 공개 source
저장소는 <https://github.com/dusen0528/wakeio-security-ci>이며, npm package는
아직 공개되지 않았다.

## 제품 요구사항

- 요금제나 서버 연결 없이 코어 검사를 실행한다.
- 소스가 있는 프로젝트와 공개 URL만 있는 프로젝트를 각각 검사하고, 두 입력을
  함께 사용할 때 결과의 범위와 불확실성을 구분한다.
- Next.js/React·Supabase, Node.js·Python, API·권한 검증을 하나의 공개 CLI와
  결과 형식으로 다룬다. 지원 범위를 넘어서는 항목은 `partial`, `unknown`,
  `not_applicable` 또는 `not_observed`로 남긴다.
- JSON, SARIF, Markdown 결과에서 비밀값과 원문 소스를 노출하지 않는다. 결과에
  포함될 수 있는 경로, 패키지 이름, URL, 도구 메시지는 사용자가 artifact 공개
  범위를 검토한다.
- CI에서 검사 완료, 발견, 설정·도구 오류를 exit code 0, 1, 2로 구분한다. exit
  0은 검사한 범위에서 기준을 넘는 발견이 없다는 뜻이며 전체 서비스의 안전을
  보증하지 않는다.

| 입력 | 검사 범위 | 자동으로 증명하지 않는 것 |
| --- | --- | --- |
| 소스 디렉터리 | 내장 JS/TS 및 framework 후보, 선택한 Gitleaks·OSV-Scanner·Trivy·Bandit 결과 | 실행 중 서비스의 실제 인가, 운영 설정, 악용 가능성 |
| 공개 URL | 제한된 HTML 및 같은 origin JS GET, 전송·헤더·쿠키·mixed content·공개 노출·DOM 관찰 | 로그인 뒤 데이터, 서버 코드, DB·결제 동작, 일반적인 퍼징 |
| 명시된 API 정책 | 환경변수 credential을 사용한 제한된 읽기와 positive/negative control | 미정의 endpoint, 쓰기 작업, 범용 침투 테스트 |

## 공개 코드와 경계

공개 저장소에는 CLI, 공개 검사 규칙, 선택적 오픈소스 도구 adapter, 결과
정규화·보고서, composite Action, 예제, 테스트와 문서가 들어간다. 사용자는
이 코드를 읽고 수정하고 자신의 CI에서 실행할 수 있다.

검사 대상 프로젝트의 package manager, lifecycle hook, build, test, target
script는 실행하지 않는다. URL 요청은 지정된 범위와 제한을 따르고, 사설 주소는
명시적 옵션이 있을 때만 허용한다. API credential은 정책이 지정한 환경변수에서만
읽고 결과·summary·annotation에 토큰과 raw scanner output을 기록하지 않는다.

이 저장소의 범위에는 특정 고객의 운영 데이터, 고객별 테스트 계정과 비공개
시나리오, 별도 서비스의 결제·계정·납품 흐름, 내부 문서와 비공개 프롬프트가
포함되지 않는다. 그런 요구가 필요하면 공개 CLI의 입력·출력 계약을 유지하는
별도 통합으로 다룬다. 무료 검사 실행은 별도 유료 기능이나 계정에 종속되지
않는다.

## 공개 배포 상태

GitHub source checkout은 다음처럼 사용할 수 있다.

```sh
git clone https://github.com/dusen0528/wakeio-security-ci.git
cd wakeio-security-ci
npm ci --ignore-scripts
npm test
```

GitHub Action preview는 `dusen0528/wakeio-security-ci@main`으로 제공한다. `main`
은 mutable preview ref이므로 운영 workflow에는 먼저 검토한 commit의 전체 SHA를
지정한다. 존재하지 않는 tag나 registry 경로를 문서에 만들지 않는다.

현재 npm 등록과 GitHub Marketplace listing/release는 완료되지 않았다.
`npm run package:release`는 로컬 npm tarball, source archive, SHA-256 manifest만
만들며 registry를 변경하지 않는다. 실제 실행과 범위는
[검증 기록](verification.md) 및 [배포 문서](distribution.md)에 기록한다.
