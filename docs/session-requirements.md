# 공개 OSS 요구사항과 유지 기준

2026-09-17 기준의 제품 범위와 공개 배포 요구사항을 정리한 문서다. 구현 완료
표가 아니며, release별 검증 결과는 [검증 기록](verification.md)과
[0.4 검증 기록](verification-0.4.md)에서 확인한다. 이 저장소에 없는 기능을
현재 제공한다고 해석하지 않는다.

| 유지할 요구 | 공개 제품에 적용하는 방식 |
| --- | --- |
| 독립 무료 CI 도구 | 계정, 구독, 전용 서버, AI token 없이 로컬 CLI와 composite Action을 실행한다. 사용자의 runner 시간·디스크·네트워크 비용은 사용자의 환경에서 발생한다. |
| 코드가 있거나 없는 경우 | 소스 디렉터리, 공개 URL, 두 입력의 조합을 지원하고 각 입력의 검사 범위와 한계를 결과에 남긴다. |
| 개발자와 비개발자 모두가 읽을 수 있는 결과 | JSON, SARIF, Markdown에 finding kind, severity, confidence, evidence, remediation, uncertainty를 함께 기록한다. |
| 세 영역의 공통 범위 | Next.js/React·Supabase, Node.js·Python source checks와 API·권한 정책 checks를 하나의 CLI 계약으로 제공한다. 적용되지 않는 영역은 clean으로 위장하지 않는다. |
| 명시적 로컬 데이터 경계 | 대상 package script, build, test, hook, 자동 로그인·결제·쓰기 작업을 실행하지 않는다. 소스 업로드나 telemetry를 기본 동작으로 추가하지 않는다. |
| 비교 가능한 안전 결과 | partial, error, skipped, not_applicable, unknown, not_observed를 completed clean과 구분하고, provenance가 없거나 범위가 바뀌면 비교를 unverified로 둔다. |
| 재배포 가능한 공개 코드 | Apache-2.0과 third-party notice를 지키고, 외부 rule·advisory·fixture를 복사할 때 license와 출처를 확인한다. |
| 근거 기반 고도화 | 외부 도구를 참고하더라도 현재 구현, planned 기능, 제한사항, 실제 검증을 문서에서 분리한다. |

초기 범위는 2026-09-15에 소스·URL·API 권한 검증을 함께 다루는 방향으로
정리되었다. 특정 framework나 scanner 하나로 전체 보안을 대체한다는 약속은
하지 않는다. WAF, EDR, SIEM, 완전한 penetration test, certification과 같은
별도 운영 영역은 이 도구의 결과 계약에 포함하지 않는다.

`oss-product-design.md`의 planned 기능과 release별 구현·검증 기록을 구분한다.
새 요구사항은 public input boundary, observable output, uncertainty, test
evidence를 함께 정의해야 하며, 개인 작업 상태 파일을 source archive에 넣지
않는다.

## 배포 기준

GitHub source repository는
<https://github.com/dusen0528/wakeio-security-ci>에서 공개되어 있다. 공개
preview Action은 `dusen0528/wakeio-security-ci@main`으로 사용할 수 있지만,
`main`은 변경될 수 있으므로 운영 workflow는 검토한 전체 commit SHA를 사용한다.
npm package와 GitHub Marketplace listing/release는 아직 공개되지 않았다. 문서,
예제, 생성 workflow에는 존재하지 않는 registry tag나 release를 넣지 않는다.
