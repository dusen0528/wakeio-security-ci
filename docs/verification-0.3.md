# 0.3 프리뷰 검증 기록

2026-09-16 KST · Node.js 22.22.1 · macOS arm64 · `0.3.0-dev.1`

구현은 Luna max 서브에이전트에 분담했고 부모 에이전트가 코드·계약을 검토한 뒤 통합 검사와 실제 CLI 실행을 수행했다. 기존 유료 Wakeio backend와 분리된 OSS 작업 트리다. 공개 저장소·npm 업로드, 원격 Linux CI, 실제 고객 서비스 침투 검증을 수행한 기록은 아니다.

## 구현과 실행 확인

| 대상 | 실행 및 확인 |
| --- | --- |
| 통합 | `npm test`: TypeScript 빌드 및 99/99 테스트 통과, skip 0 |
| Python 실제 엔진 | Bandit 1.9.4를 별도 venv에 설치해 public CLI로 실행. `shell=True` 합성 코드는 B404·B602, high 기준 exit 1. 고정 실행 파일+인자 배열 수정 후 B404·B603(low)만 남아 exit 0 |
| 도구 누락 | 존재하지 않는 Bandit 경로와 `--fail-on none` 조합도 exit 2 |
| 기존 native 연동 | Gitleaks 8.30.1·OSV-Scanner 2.6.0·Trivy 0.74.0 실제 실행. 합성 JS/lockfile/Dockerfile에서 적용되는 검사 5개 완료, framework 1개 적용 없음, 발견 10개(high 5·medium 4·low 1) |
| API | 실제 로컬 HTTP 서버와 별도 CLI 프로세스. 소유자 정상 읽기, 다른 계정/익명 거절 및 보호된 JSON 표식 노출, 수정 전후 비교, 토큰·본문 제거 확인 |
| 오류 경계 | 소유자 대조 실패, 같은 인증정보, malformed 정책/JSON, 비JSON, 예상 외 상태, 429/5xx, redirect, 응답 크기 초과, 사설 주소, 요청 예산은 정상 완료로 처리하지 않음 |
| 프레임워크 정상 사례 | 일반 role 문자열·Supabase 공개키·제한 정책·동일 파일의 RLS 재활성화·SQL 주석은 고위험 노출/해제로 오인하지 않음 |
| URL 정상 사례 | 일반 Next 런타임 표식은 메모. component/version은 info. JSON의 공개 anon key와 인접 실제 secret 후보를 구분. map/CDN 추가 다운로드 없음 |
| 비교 | 범위·버전·검사 집합/상태 불일치, 과거 scope 미기록, 부분 검사에서는 unverified와 exit 2. 입력 JSON 및 출력 링크 경계 확인 |

실제 Bandit 수정 예제에 low 경고가 남는 것은 정상이다. exit 0은 high 문턱 이상의 발견이 없다는 뜻이며 아무 후보도 없다는 뜻이 아니다. 실제 scanner 출력의 임의 메시지·코드·credential 원문은 결과에 담지 않는다.

## 기존 합성 벤치마크

`node scripts/benchmark.mjs --strict --engine-label 0.3.0-dev.1` 실행 결과: 위험 15개·수정 15개, 선언한 지원 기대 13개 검출, 알려진 미지원 2개 미탐지 유지, 수정 사례 오경고 0, strict regression 0. 전체 corpus의 기대 발견은 15개 중 13개다. 이 corpus는 JS/TS의 제한된 흐름 분석 회귀 검사용이며 Python·API·실제 서비스 전체의 탐지율을 나타내지 않는다.

## 배포물 검사

`npm run package:release`로 npm tarball, source tar.gz, 두 파일의 SHA-256 manifest를 만들었다. 별도 임시 consumer 프로젝트에 tarball을 `npm install --ignore-scripts --offline`으로 설치해 아래 경로를 실행했다. 설치된 runtime 파일은 검토한 `build/src`와 바이트 단위로 대조했다.

| 배포물 사용 경로 | 결과 |
| --- | --- |
| 설치된 CLI help 및 실제 Bandit Python 검사 | exit 0; 수정 fixture의 low 후보는 유지 |
| source archive의 문서화된 API demo 취약 모드 | 설치된 CLI가 high 발견, exit 1 |
| 동일 demo의 수정 모드 | 소유자 성공·다른 계정/익명 거부, exit 0 |
| 두 API 보고서 비교 | comparable=true, not_observed=1, exit 0 |
| source archive의 Action 진입 스크립트 | 별도 checkout의 자체 npm ci/build, Bandit+API combined 실행 및 GITHUB_OUTPUT report-dir 기록 성공, exit 0 |
| 설치된 CLI의 URL 검사 | 합성 HTML/CORS에서 후보 관찰, --fail-on none에서 exit 0; 실제 요청 1회, Authorization 전달 없음 |
| 산출물 경계 | archive의 symlink/hardlink·.git·.intent-review·venv·node_modules·.env·실행 결과 디렉터리 제외 확인. API 토큰·응답 본문이 보고서에 없는지 확인 |

CI 검증은 macOS에서 composite Action의 실제 진입 스크립트를 실행한 것이다. GitHub-hosted Ubuntu job의 실행 증거는 아니다. `package:release`는 공개 게시를 수행하지 않는다. 최종 문서 보완 후 archive를 다시 만들고 checksum 및 설치 검증했던 runtime과의 일치를 재확인했다.

## 검토에서 수정한 문제

- Next 런타임 표식·`service_role` 글자만으로 고위험 노출을 만들던 판정을 제거했다.
- 공개용 변수 이름이 인접한 실제 provider token을 숨기지 않도록 값과 자기 assignment를 묶었다.
- API의 불명확한 deny 응답이 completed로 남던 경로를 partial로 바꿨다.
- 서로 다른 actor/case의 발견이 같은 JSON 식별자로 합쳐지지 않도록 identity를 반영했다.
- oversized API 응답 뒤의 요청을 중단해 반복 수신으로 예산을 우회하지 않게 했다.
- Python 환경·scanner 제어파일·보고서가 소스 파일 수 한도를 먼저 소모하지 않도록 조정하고 별도 전체 탐색 한도는 유지했다.

## 남아 있는 범위

OpenAPI/GraphQL 자동 생성 테스트, ZAP/Schemathesis active scan, 전체 Git secret 이력, image CVE, live cloud/IAM/RLS, 결제·관리자 상태 변경, 함수/파일 간 전체 추적, 광범위한 프레임워크 해석은 미구현이다. 첫 설치 `init`·엔진별 진행 안내·외부 엔진/rule bundle/DB의 완전한 provenance 고정 역시 후속 과제다. 안정적인 식별자와 비교 기능은 수정 확인을 돕지만 취약점 수정이나 보안 인증을 증명하지 않는다.

[실행 안내](preview-0.3.md) · [현재 체크리스트](checklist.md) · [과거 제약 대조](session-requirements.md)
