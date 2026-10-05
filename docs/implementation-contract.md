# 독립 CI 패키지 구현 계약

이 문서는 공개 OSS의 입력·출력·신뢰 경계를 정의한다. 구현과 검증 시점은
별도 [검증 기록](verification.md)에서 확인한다.

- 프로젝트: Wakeio Security CI, npm 이름 `wakeio-security-ci`, Apache-2.0.
- 공개 저장소: <https://github.com/dusen0528/wakeio-security-ci>.
- 기본 scan 실행 경계: 로그인, 요금제, 전용 서버, LLM 호출 없이 local CLI와 composite
  Action을 실행한다. CI runner 시간·저장 공간·네트워크 사용량은 사용자의
  환경에서 소비된다.
- 소스 모드: 제한된 파일 수집, JS/TS 기본 정적 후보, Gitleaks CLI,
  OSV-Scanner CLI, Trivy config CLI, 선택 Bandit Python AST, 제한된
  Next/Supabase 규칙. 대상 코드와 package manager script를 실행하지 않는다.
- URL 모드: 제한된 GET, 같은 origin의 HTML과 연결된 JS, 헤더·쿠키·전송·노출·
  DOM 후보. 자동 폼 제출·로그인·결제·퍼징은 하지 않는다.
- API 정책 모드: 환경변수 인증정보, 같은 origin의 GET과 소유자 전후 대조,
  다른 계정·익명 거절 검증. 제한된 명시 정책만 실행하며 자동 로그인·결제·쓰기
  요청·퍼징은 하지 않는다.
- 기본 scan 결과: `report.json` + `report.sarif`(SARIF 2.1.0) + `report.md` + `agent-report.json`. 민감값과 원문 코드를 결과에 담지
  않으며, `partial`, `error`, `skipped`, `not_applicable`, `unknown`,
  `not_observed`를 completed clean과 구분한다.
- CLI: `wakeio-security-ci scan --source .`, `scan --url https://example.com`,
  두 인자 조합을 지원한다.
- CLI 옵션: `--out DIR`, `--tools gitleaks,osv,trivy,bandit|none`,
  `--fail-on high|critical|medium|low|info|none`, `--allow-private`,
  `--timeout-ms N`, `--osv-offline`, 각 도구의 `--gitleaks PATH`, `--osv PATH`,
  `--trivy PATH`, `--bandit PATH`, `--api-policy FILE`. 기본 external tools는
  Gitleaks, OSV-Scanner, Trivy이며 Bandit은 별도 선택·설치다.
- 비교 CLI: `compare --before FILE --after FILE --out DIR`. 같은 범위와 완료된
  검사만 비교하며 불일치·불완전·provenance 변경은 exit 2와 `unverified`로
  남긴다. 사라진 발견을 수정 완료로 단정하지 않는다.
- 종료 코드: 누락 도구, 오류, timeout, 범위 제한에 따른 누락은 안전·완료로
  해석하지 않는다. exit 0은 검사 완료 및 문턱 이상 결과 없음, 1은 문턱 이상
  결과, 2는 설정·실행·부분 검사 오류다. `--fail-on none`도 실행 오류는 2다.
- 모듈 계약: `src/contracts.ts`는 공유 계약이다. `source.ts`와 `url.ts`는 각각
  `runSource(options): Promise<CheckResult[]>`, `runUrl(options):
  Promise<CheckResult[]>`를 export한다.
- 보고서 계약: `report.ts`는 `createReport(checks, mode, startedAt, scope?):
  ScanReport`, `writeReports(report, outDir, { failOn? }?): Promise<void>`(기존 두 인자 호출은 high),
  `exitCode(report, failOn): 0|1|2`를 export한다. CLI는 이 interface를 사용한다.
  4파일은 파일별 atomic write이며 agent의 `scanGate`는 단일 scan 판정이다. delivery 실패는 CLI exit 2이고 최종 CI 성공 receipt와 구분한다. [agent 계약](agent-report.md)
- Native tool 설치: 고정 버전과 검증된 checksum을 사용한다. OSV 기본은 패키지
  식별자의 공개 DB 질의이며 네트워크 동작을 문서화한다. offline 모드는 준비된
  DB가 없으면 오류다. Trivy 규칙·DB 다운로드와 provenance도 결과에 남긴다.
- GitHub Action: 무료 CLI 실행용 composite Action이다. 입력은 환경변수로 받은
  뒤 JavaScript argv 배열로 처리한다. 사용자 저장소에서 npm install, build,
  test, target script를 실행하지 않는다. public preview workflow는
  `dusen0528/wakeio-security-ci@main`과 `tools: none`을 명시하며, 운영에서는
  검토한 full commit SHA로 pin한다.
- 배포 상태: GitHub source repository는 공개되어 있고 source clone과 preview
  Action을 사용할 수 있다. npm package는 아직 publish하지 않았고 GitHub
  Marketplace listing/release도 없다. `package:release`는 local tarball,
  source archive, SHA-256 manifest만 만든다.

## 선택적 repair 경계

2026-10-04에 별도 실험적 repair CLI가 추가되었다. 기존 scan의 계약을 확대하거나
완화하지 않는다. trusted TOML·고정 verifier·준비된 로컬 Docker 이미지에서 선언된
SQL 회귀와 정상 control을 수정 전후 비교하고, 원본을 변경하지 않은 private patch와
검증 기록을 만든다. 명시적 `--agent codex|claude --allow-source-upload`는 선택된
코드 문맥을 외부 모델에 전달할 수 있으며 별도 API 인증·비용이 필요하다.

이 CLI에는 대상 코드 실행이 포함되므로 scan의 대상 미실행 계약과 구분한다.
patch에는 원문 코드가 있으므로 scan의 redacted 보고서와 동일하게 취급하지 않는다.
전체 지원 범위·검증기 신뢰·미확인 사항은 [repair 계약](repair-preview.md)을 따른다.
