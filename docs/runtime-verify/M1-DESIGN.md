# M1 설계: Spring 실행 검증 경로

이 문서는 PLAN 4·6·7·10·11·12장의 M1 CP1 설계다. 기준은 M0 PR #82 병합 커밋
`a49da4ceebc2c7dd24020ecbce420f46d0ca7625`이며 브랜치는 `codex/rv-m1-spring-sql`이다.

## 진행 절차에 대한 최신 사용자 지시

- 사용자는 “목표끝까지 멈추지말고 계속해서 개발 진행하도록 해”라고 지시했다.
- 이어 PR #82에 대해 “너가 직접 병합해도돼 승인함”이라고 승인했다. 오케스트레이터가
  CI와 승인 HEAD를 확인하고 merge 방식으로 병합해 보호 파일 변경 이력을 보존했다.
- 마일스톤 PR 병합 지시를 기다리며 개발을 중단하던 절차는 이 최신 지시로 대체한다.
  CP1·CP2·필수 CPx·GATE, 종료 코드 처리, 보호 파일 불변, 테스트·KPI 기준은 유지한다.
- HANDOFF·PLAN·보호 프롬프트는 이 운영 지시를 반영한다는 이유로 수정하지 않는다.

## M1 완료 범위

1. `init-target`은 소스를 읽어 Spring/compose 감지 근거와 `wakeio.target.yml` 초안을 생성한다.
   빌드·컨테이너·대상 스크립트·네트워크 실행은 하지 않는다.
2. `verify --target FILE --execute-target-consent`는 compose 빌드·기동, JVM JaCoCo 계측,
   actuator/OpenAPI 발견, 마커가 결속된 공격, Postgres 관측, 순수 SQL Oracle, 보고를 연결한다.
3. Spring Pack v1은 검증 가능한 데이터이며 해시와 버전을 결과에 결속한다.
4. R8이 독립 작성한 취약/수정 쌍과 안전 대조 라우트로 SQLi confirmed/수정본 0건을 증명한다.
5. 요청한 핸들러의 실제 covered 줄과 미요청 핸들러 uncovered를 대조하고 라우트별로 보고한다.
6. 같은 시드·예산을 두 번 실행해 Verdict 집합과 마커 매핑의 재현성을 확인한다.
7. 빌드/기동/격리/관측/정리 실패는 미완료로 남긴다. confirmed 발견과 미완료가 함께면
   verify는 1, 발견 없이 도구 실패면 2, 계획된 검사가 완료되고 기준 이상 판정이 없으면 0이다.
8. 로컬 Docker 증거와 같은 저장소 CI 검증을 모두 남기고 compat-0.5·기존 KPI를 보존한다.

## 변경하지 않는 경계

- 기존 scan/init/init-dast, 실행 계획 v1, CodeCoverage v1, RunStore 공개 시그니처를 보존한다.
- M0의 attack/analyzer 정적 registry 분리와 계획 파서의 실행 모듈 독립성을 유지한다.
- verify만 소유 소스 컨테이너를 실행하며 외부 URL을 검사 대상으로 받지 않는다.
- 동의 거부는 파일 생성·대상 로딩·빌드·컨테이너/네트워크 요청 전에 결정한다.
- Oracle은 I/O·시계·네트워크·LLM에 접근하지 않는다. 단순 마커 포함만으로 confirmed를 내지 않는다.
- 구현 역할은 R8 예제·기대 판정을 수정하지 않고, 독립 증거는 R9만 작성한다.
- PLAN 14장은 M0/M1 범위를 바꾸지 않는다. M2의 권한 판정은 소유자 성공 대조군·identity와
  접근 규칙 없는 라우트 unknown을 필수로 설계한다. M3/M4 workflow도 각 CP1에서 별도 검토한다.

## CP1 설계 패킷

| 패킷 | 역할 | 쓰기 경로 | 완료 조건 |
| --- | --- | --- | --- |
| M1-01 | R1 계약·레지스트리 | design/M1-r1-contracts.md | 구체 포트·파일 artifact 해시 결속·Inventory v2·실패/정리/보고 경계 |
| M1-02 | R3 빌드·런타임 | design/M1-r3-build-jvm.md | compose/rootless/네트워크 정책·JaCoCo 수집·빌드 재현·CI 방법 |
| M1-03 | R8 독립 예제 | design/M1-r8-fixtures.md | 취약/수정/안전·바인딩/문법·관측 누락·커버리지 기대 매트릭스 |

위 신규 내부 설계 문서의 한정 쓰기는 오케스트레이터가 패킷으로 승인했다. 모든 제품 구현은
CP1 승인 뒤 경로 소유자에게 별도 패킷으로 발행한다. R4·R5·R9·R10 후속 설계와 구현 패킷,
구체 파일 목록 및 검증 명령은 각 설계 검토 뒤 여기에 추가한다.

## 검토가 필요한 선택지

- PLAN 13장의 설정 파일 위치: 자체 target YAML과 compose x-wakeio의 장단점을 비교한다.
- SQL 파서: Postgres 문법 파서와 토큰 위치, 바인딩 로그, 구문 오류를 함께 다룰 수 있는지
  검토한다. 버전·라이선스·배포 경로를 고정하고 미지원/파싱 실패는 unknown으로 남긴다.
- SQL 관측 artifact는 마커 없는 사건·대상 값·자격 증명을 저장하지 않으면서 판정에 필요한
  문법 역할과 무해 대조군을 보존해야 한다. 필터링으로 바인딩을 구문 승격으로 오인하면 안 된다.
- M1은 compose 직접 제공부터 시작한다. 자동 빌더 선택은 M3 결정이며 이번에 미리 확정하지 않는다.
- 실제 daemon의 rootless 여부를 확인한다. Docker Desktop VM이나 컨테이너 non-root만으로
  rootless daemon이라고 표기하지 않는다. 실행 환경이 정책을 충족하지 못하면 거부하고 원인을 보고한다.
- JaCoCo 제어 포트는 인증이 없으므로 호스트/외부에 공개하지 않고 소유 격리망에서만 사용한다.

## 독립 검증 계획

- R9는 CP1에서 기준 build·compat·KPI와 실행 도구 환경을 기록한다.
- R8은 이미지·의존 버전·입력·시드·라우트 ground truth·판정 기대값을 고정한다.
- R9는 취약/수정/음성 경로, 바인딩 대조, 관측 실패 unknown, 동의 없는 zero execution,
  예산·취소·후손 프로세스 종료, 컨테이너/네트워크/볼륨 정리를 실제 실행으로 검증한다.
- 보고서 4종의 raw 해시 결속과 요약 순서, 기존 consumer/0.5 호환, 새 verify 0/1/2 우선순위를 확인한다.
- 빌드·격리·외부 요청·비밀값·contracts/report 변경은 통합 전에 필수 CPx 대상으로 취급한다.
- CI는 fork와 pull_request_target에서 대상 실행을 거부하고 contents: read를 유지한다.

## 설계 시 참고한 1차 자료

- PostgreSQL 로그의 문장·바인딩 파라미터·오류 필드:
  https://www.postgresql.org/docs/16/runtime-config-logging.html
- SQL 파서와 토큰 위치를 제공하는 libpg_query 기반 Node/WASM 후보:
  https://github.com/constructive-io/libpg-query-node
  https://github.com/pganalyze/libpg_query
- JaCoCo agent 및 소유 격리망 dump/라인 보고:
  https://www.jacoco.org/jacoco/trunk/doc/agent.html
  https://www.jacoco.org/jacoco/trunk/doc/cli.html

상세 결정과 한계는 역할별 설계 및 CP1 응답을 반영해 확정한다. 미결정을 구현 편의로 확정하거나
M1 범위를 축소해 게이트를 통과한 것으로 주장하지 않는다.
