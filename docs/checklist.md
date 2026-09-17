# 무료 검사 체크리스트

v0.4.0-dev.1의 실행 범위다. 모든 행은 같은 무료 CLI에서 제공하며, 유료 전환으로 결과를 숨기지 않는다. 실행마다 적용 여부·완료 여부·발견 결과를 별도로 기록한다. [고도화 설계](oss-product-design.md) 전체의 완료를 뜻하지 않으며 실행 예제는 [0.4 안내](preview-0.4.md)에 있다.

## 소스가 있을 때

| 항목 | 검사 방식 | 결과·한계 |
| --- | --- | --- |
| 동적 코드 실행 | JS/TS AST의 eval·Function 등 호출 | 위험 호출 후보. 공격자 입력의 도달 여부를 확정하지 않음 |
| HTML/SQL/프로세스 호출의 입력 | 직접 입력·같은 함수의 변수·구조 분해·재대입·loop binding, 지원 JSX HTML sink·raw-query API | XSS·SQLi·명령 실행 후보. 함수·파일 간 전체 추적, 임의 property mutation·프레임워크 전체 의미 분석은 지원 범위 밖 |
| 외부 요청·리디렉션 입력 | 같은 함수에서 요청 입력이 fetch·redirect 등 호출에 전달되는지 확인 | SSRF·open redirect 후보. 실행 환경에서 재현하지 않음 |
| Secret | Gitleaks CLI, JS/TS 기본 토큰 모양 검사 | 값 원문 없이 종류와 파일 위치 제공. 실제 키 유효성 확인 없음 |
| 취약 의존성 | 지원 lockfile과 고정 버전의 self-contained Python requirements를 OSV-Scanner로 분석 | 공개 advisory와 패키지·버전 제공. 미해석 range/include 등은 partial. 소스 reachability 분석 없음 |
| Dockerfile | Trivy config | root 실행 등 설정 결과. 이미지 OS CVE 검사 아님 |
| Kubernetes/Terraform | Trivy config | manifest·IaC 설정 결과. 실제 클라우드 상태를 조회하지 않음 |
| 외부 참조 Terraform | module·파일 함수 참조 검사 후 제한 | 파일을 Trivy에 전달하지 않고 partial 표시. 외부 module까지 점검 완료로 표시하지 않음 |
| Python | 선택 도구 Bandit의 AST 검사 | shell 호출·eval·unsafe YAML/pickle·TLS 검증 해제 등 후보. 별도 설치 필요, 대상 실행 없음 |
| Next/React | use client, 정적 env/config 참조, 상대 import 연결에서 Supabase 서버키·공개 비밀변수 후보 | 공개 anon/publishable 키 구분. 실제 build·배포 번들, 전체 모듈 해석과 실행 없음 |
| Supabase | SQL의 RLS 해제·PUBLIC true 정책, CREATE/GRANT/ENABLE 이력의 RLS 미활성 후보 | 중첩 주석·인용 식별자 구분. 수집된 제한 구문의 이력이며 실제 DB 상태·모든 SQL·역할 상속을 검증하지 않음 |

기본 수집 제한은 1,000개 파일, 총 25 MiB, 파일당 2 MiB다. `.git`, `node_modules`, `vendor`, 빌드·캐시 경로와 scanner 제어 설정 등은 제외한다. 심볼릭 링크·하드 링크·파일 변경·크기 초과에 따른 누락은 부분 검사로 기록한다. 따라서 Git 커밋 전체의 Secret 이력 검사는 포함되지 않는다.

지원 lockfile 이름은 `src/source.ts`의 OSV 목록을 따른다. 지원 lockfile이 필요한 프로젝트에서 파일이 없거나 도구가 해석하지 못하면 의존성 검사가 완료된 것으로 처리하지 않는다. JS/TS 외 언어도 수집·Secret·지원 의존성·설정 검사는 가능하지만 내장 AST 규칙은 JS/TS에 한정되며 Python AST 검사는 Bandit을 선택해야 한다.

입력 흐름은 `req`, `request`, `params`, `location` 등 지원되는 이름과 구문에서 시작하는 보수적 후보 분석이다. 모든 사용자 입력을 식별하지 않으며, 자체 검증/정화 함수의 안전성도 증명하지 않는다. 입력에 관계된 불명확한 변환은 낮은 confidence 후보로 남긴다. 정상적인 쿼리 매개변수 전달, 고정값 재대입, 변수 shadowing은 위험 코드와 구분해서 회귀 검증한다. 실제 프레임워크나 데이터베이스에서 취약점을 재현한 결과가 아니다.

## URL만 있을 때

| 항목 | 확인 내용 | 결과·한계 |
| --- | --- | --- |
| 전송 | HTTP 사용, HTTPS 페이지의 HTTP 리소스 참조 | 수집한 응답과 참조에서 관찰 |
| CSP | directive/fallback, nonce/hash/strict-dynamic, 복수 정책을 고려한 unsafe-inline·unsafe-eval | 제한된 정책 해석. CSP 전체 문법·우회 가능성·실제 브라우저 실행 분석 아님 |
| 브라우저 정책 | HSTS, framing policy, X-Content-Type-Options, Referrer-Policy | 헤더·값 관찰 |
| 쿠키 | Secure, HttpOnly, SameSite 및 None/Secure 조합 | 익명 응답의 쿠키 속성만 확인. 쿠키 용도에 따라 추가 검토 필요 |
| 공개 Secret 후보 | HTML·수집된 JS의 키·토큰·비밀값 모양 | 원문 값 생략. Supabase 공개 키 형태를 구분하지만 실제 키 유효성을 확정하지 않음 |
| DOM 후보 | HTML 삽입·document.write·eval·문자열 timer·srcdoc 등 | 정적 패턴 후보. 브라우저 실행과 실제 XSS 재현 없음 |

시작 URL과 명시한 추가 페이지의 HTML, 같은 origin의 연결된 JavaScript 및 정적 import/export 연결을 제한된 GET으로 수집한다. 기본은 첫 페이지이며 추가 페이지도 공통 페이지·요청·바이트·시간 예산을 공유한다. 다른 origin의 JS/CDN, dynamic import 실행, 링크를 따라가는 전체 사이트 크롤링, API 요청 변형, 로그인·결제·관리자 권한 검증은 포함하지 않는다. `--allow-private`은 사용자가 지정한 로컬/사설 대상 검사에 사용하며 메타데이터 주소 제한은 유지한다.

URL에서는 추가로 응답의 CORS 조합, source map 참조, 명시적인 debug·민감 필드 후보, 노출된 component/version 단서를 관찰한다. 정상 Next.js 런타임 데이터만으로 노출을 판정하지 않으며 component/version 정보만으로 CVE를 확정하지 않는다. Source map 본문이나 외부 CDN을 새로 내려받지 않는다.

## API 정책이 있을 때

v2 정책에 계정별 identity GET과 기대 principal, 소유자·다른 계정·익명 사용자, 리소스 식별 표식과 별도의 보호 canary, 거부 상태를 사용자가 정의한다. 인증된 계정의 identity와 소유자의 정상 읽기를 전후로 확인한다. 만료 토큰·검사 도중 만료·같은 principal 재사용은 정상 완료가 아니다. v1은 읽을 수 있지만 검증 근거가 부족해 partial로 남는다.

유효한 다른 계정이 보호 canary를 받으면 200 또는 403이어도 노출 발견을 기록한다. 정상 오류의 공개 ID만으로 high를 만들지 않는다. 명시한 빈 본문 거부는 identity 확인 후 허용하며 429·5xx·응답 오류는 partial/error로 남긴다. 토큰·canary 값·응답 본문은 보고서에서 제외한다. 최대 20개 사례·64개 요청·120초이며 identity 대조도 요청 예산에 포함한다. redirect·쓰기 요청·자동 로그인·전체 API 탐색은 없다. [v2 정책과 로컬 데모](preview-0.4-api.md)

## 결과 이용

- `candidate`: 추가 검토가 필요한 코드·노출 후보.
- `observation`: 실제 수집한 응답·설정에서 확인한 내용.
- `advisory`: scanner 또는 공개 취약점 데이터가 제공한 권고.
- exit 0: 적용되는 요청 검사가 완료되었고 설정한 기준 이상의 발견이 없음.
- exit 1: 설정한 심각도 기준 이상의 발견이 있음.
- exit 2: 설정·실행 오류, 부분 검사 또는 적용 가능한 보안 검사가 없음.

전체 서비스의 안전 판정이나 전문 침투 테스트 결과로 해석하지 않는다. 수정 전후 보고서 비교에서는 불완전하거나 범위가 다른 검사, 모호한 중복 매칭을 unverified로 남긴다. 지원하는 source anchor는 줄 위치와 별도로 비교하며, anchor를 만들지 못한 항목에는 위치 기반 한계가 남는다. 상세 실행 근거는 [0.4 검증 기록](verification-0.4.md)에 있다.
