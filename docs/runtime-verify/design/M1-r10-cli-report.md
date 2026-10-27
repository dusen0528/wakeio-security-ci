# M1 R10: CLI·보고서 CP1 설계

기준 `a49da4ceebc2c7dd24020ecbce420f46d0ca7625`, PLAN 3·4·6·7·10·11·12·13·14.4와 R1 계약 제안.
이 문서는 설계이며 제품 구현·검증 증거가 아니다. 기존 scan/init/init-dast의 동작과 종료 코드를 유지한다.

## 1. CLI 진입과 권한

| 명령 제안 | 수행 범위 |
| --- | --- |
| `init-target --source DIR --out NEW_FILE` | 소스만 읽어 감지 근거와 target YAML 초안을 새 파일에 생성; Docker/프로젝트 스크립트/네트워크 없음 |
| `verify --target FILE --execute-target-consent --out NEW_DIR` | 명시 동의 뒤 R1~R5의 검증된 데이터·capability로 빌드부터 정리·보고까지 실행 |
| `verify --help`, `init-target --help` | 단독 help만 메모리의 고정 텍스트 출력, target 읽기·출력 생성·프로세스·DNS/HTTP 없음 |

`src/cli.ts:699`의 서브커맨드 분기에만 추가한다. 기존 `parseCliArgs`와 scan의 전역 옵션 의미는 바꾸지 않는다.
새 CLI의 순수 argv 단계는 먼저 인자를 검증한다. verify 동의가 없으면 고정 reason/exit 2만 출력한다.
이 경로에서는 target/source lstat·read, 출력 생성, Docker 호출, 대상 요청, 모델 호출을 모두 0회로 한다.
동의·정적 argv 검증 뒤에만 실행 모듈을 정적 지정 import로 연결한다. JSON이 모듈/함수 경로를 공급하지 않는다.
알 수 없는/중복 플래그, 값 누락, 제어 문자, 상반된 값, help와 실행 옵션 혼합은 거부한다.
`--profile pr|full`, `--max-minutes`, seed·예산·`--fail-on-grade`는 R1의 닫힌 범위/상한으로 검증한다.
M1에서 검사 결과 캐시·LLM·외부 target URL은 지원하지 않는다. profile 이름만으로 미검사 범위를 검사했다고 쓰지 않는다.
init-target의 `--out`은 필수 새 파일이다. source는 출력 부모 아래의 안전한 상대 PathRef로 표현할 수 있어야 한다.
verify 출력은 source 밖·존재하는 부모 아래의 새 디렉터리(0700), 파일은0600이다. 조상/대상 링크·기존 출력은 거부한다.
init-target도 명시된 새 출력만 만들며 기존 소스 파일·설정은 수정하지 않는다. YAML 직렬화는 임의 태그/보간을 만들지 않는다.
init-target의 저장 link 후 확인·정리 실패는 output이 남을 수 있는 `init_target_output_unconfirmed`/exit 2다.
교체된 경로/inode를 지울 위험 때문에 output rollback은 하지 않는다. 기존 파일 거부와 link 전 실패 의미는 유지한다.
임시 파일 삭제도 열린 FD의 dev/ino와 부모 chain·현재 이름의 정체성을 재확인한 경우에만 한다. 교체·불명은 보존한다.
Node의 경로 재확인과 unlink 사이에는 TOCTOU 창이 남는다. dirfd/openat 기반 원자적 경로 고정을 제공한다는 주장은 하지 않는다.
`doctor --runtime`은 M3다. M1 verify의 동의 후 최소 격리 preflight와 구별하며 doctor에 실행 권한을 추가하지 않는다.

## 2. 실행·종료·출판

R10 pipeline은 단계 순서와 결과 전달만 조립한다. Docker lifecycle·bounded stdio relay는 R3 capability에 둔다.
target의 host 포트 publish나 loopback HTTP relay를 기본으로 두지 않고, 요청·응답은 제한된 stdio transport를 쓴다.
R3가 자원 할당·abort·bounded drain/cleanup의 단일 책임을 갖고 R10은 그 확인 결과 없이 완료를 출판하지 않는다.
SIGINT/SIGTERM은 공통 AbortController로 전달하고 finally에서 후손 프로세스·컨테이너·네트워크·볼륨 부재를 확인한다.
정리는 별도 유한 유예를 가지며 소유 label/ID만 회수한다. 불명·drain 실패는 해당 범위 unknown/error다.

| verify 판정 순서 | CLI·4종 보고서의 공통 의미 |
| --- | --- |
| 유효한 기준 이상 finding 있음 | exit 1; 관측/coverage/cleanup 실패가 함께 있어도 finding과 미완료를 함께 유지 |
| finding 없음, 도구·관측·정리·출판 미완료 | exit 2; 빈 결과/전부 unknown/관측 누락을 clean으로 바꾸지 않음 |
| 계획된 검사·관측·정리 완료, 기준 이상 finding 없음 | exit 0; 미도달 비율의 별도 게이트는 명시 옵션일 때만 적용 |

출판 실패도 이미 검증된 finding을 지우지 않는다. exit 1과 `delivery=failed`를 구별해 stderr/가능한 receipt에 남긴다.
최종 프로세스 exit는 호출자가 관측한다. 파일 receipt를 실제 최종 종료나 네 파일 동시 트랜잭션의 증거로 부르지 않는다.

## 3. 현재 계약과 실제 충돌

| 현재 코드 | 그대로 runtime 데이터를 통과시키면 생기는 문제 |
| --- | --- |
| `contracts.ts:5`, `compare.ts:37` | Mode는 source/url/both/api/combined로 닫혀 있고 기존 reader는 runtime을 해석하지 못함 |
| `contracts.ts:79`, `report.ts:1162,1224` | Finding.evidence는 api-execution-ledger 전용; API ledger가 없으면 evidence proof가 제거됨 |
| `report.ts:781` | sanitiseReport는 알려진 ScanReport 필드만 재구성하므로 새 runtime 섹션을 보존하지 않음 |
| `report.ts:169,236` | scan gate는 미완료 우선; agent.scanGate도 같은 규칙. verify의 finding 우선 규칙과 다름 |
| `report.ts:314`, `contracts.ts:551` | agent evidence는 scanner_report이며 verification은 not_run/false 고정; runtime confirmed와 재해석하면 오독 발생 |

PLAN 10·11을 따르는 A안으로 정렬한다. 공통 보고서에 discriminated/additive runtime union을 추가한다.
공통 schemaVersion=1.0.0에서 `mode:runtime`과 최상위 `runtime.revision:verify-m1-v1`을 함께 검사한다(R1 §6).
기존 reader/writer/sanitiser/Markdown/SARIF/agent 진입점이 R1 §6의 판별자를 먼저 검사하고 runtime 분기로 dispatch한다.
runtime 분기는 공통 envelope의 `checks`와 `runtime`을 함께 검증·보존하며, 기존 scan 분기의 직렬화와 API proof 의미는 유지한다.
runtime 필드/판별자 불일치·필수 check 누락·중복·손상은 legacy fallback 없이 거부한다. scan 모드의 runtime 혼합도 거부한다.
runtime을 모르는 예전 바이너리의 지원을 주장하지 않는다. 갱신된 공통 reader는 runtime을 누락한 깨끗한 scan으로 축소하지 않는다.
runtime 보고서는 갱신된 공통 reader가 필요하며 0.5 소비자는 미지원으로 거부한다. 기존 0.5 scan 입력·출력 호환과 구별한다.
init-target은 실행 권한 없는 draft 생성으로 연결했다. verify 실행·공통 runtime reader는 후속이며 [USAGE.md](../USAGE.md)를 따른다.
`parseScanReport`와 compare의 소비 경로도 분기하며 runtime 비교는 R1의 계약·정책·digest가 맞을 때만 수행한다.
runtime gate는 `runtime.verifyGate`가 권위다. 기존 `evaluateGate`/agent.scanGate의 미완료 우선 의미를 verify에 적용하지 않는다.
별도 versioned envelope를 주포맷으로 삼는 B안은 미채택이다. N5의 B안 사람 승인이나 PLAN 기준 재정의를 기다리지 않는다.
`Finding.kind`의 observation/candidate/advisory는 유지한다. 새 runtime finding의 evidence는 구 API evidence와 별도 판별 분기다.
`evidence.grade/reach`, marker hash, controlPairId, 단계/관측 artifact refs와 Oracle revision을 R1 타입·스키마로 결속한다.
unknown은 빈 finding이 아닌 case/gap 상태다. coverage unknown의 분모를 0/100%로 채우지 않고 SQL 판정과 분리한다.
공통 runtime 확장은 M1 draft이며 최종 1.0 스키마 고정은 M5다. 기존 0.5 입력·출력의 raw/의미 해시를 바꾸지 않는다.

## 4. 네 보고서와 원문 해시

공통 strict runtime union을 한 번 검증·sanitize한 결과에서 기존 4개 파일 JSON/Markdown/SARIF/agent를 만든다.
check별 상태 enum·정확한 필드명·null/partial/unknown 조건은 R1 §6의 권위표를 그대로 따른다. 독자 schema를 두지 않는다.
JSON의 공통 `checks[].id/status/findings/notes`와 check별 `checks[].runtime` payload를 R1 §6대로 보존한다.

| check ID | 네 보고서에서 유지할 의미·필드 |
| --- | --- |
| `runtime.build` | builder, imageDigest, cacheKey, 실제 isolation, 소요 시간 |
| `runtime.start` | 기동·health·관측 준비 결과, 실행/이미지 refs와 실패 이유 |
| `runtime.surface` | 라우트별 actuator/openapi/source/crawler/agent 출처와 실제 공격 여부 |
| `runtime.coverage` | 라우트별 도달 파일·줄 수, 전체 대비 비율과 수집 방식; 미확인 분모/값은 null |
| `runtime.oracle.sql` | case별 결과·grade/reach·control 결속·관측 refs·unknown 이유; 실패를 빈 안전 결과로 바꾸지 않음 |

미실행 command/ssrf/path/xss check의 생략/not_applicable 정책도 R1 §6을 따르며 SQL 성공을 해당 Oracle 지원으로 표기하지 않는다.
JSON의 check payload, Markdown의 check ID별 표, SARIF run properties.runtime, agent의 runtime에 같은 check 필드를 투영한다.
각 표현에 null·partial·gaps를 보존하고, finding은 JSON evidence/SARIF result properties/agent evidence에 grade·reach·refs를 유지한다.
최상위 runtime은 verifyGate·scope(미지원 유형 포함)·입력/단계 artifact refs·cleanup이며 check 상세를 중복 저장하지 않는다.
입력·이미지·Pack·도구·Oracle·정책 hashes와 실제 isolation·gaps의 정확한 위치도 R1 §6을 따른다.
Markdown/agent/SARIF 요약은 확정 취약점 → verify 게이트 → 미도달 라우트 → 한계 순서다. severity와 grade를 혼동하지 않는다.
JSON finding.evidence와 SARIF properties/agent runtime evidence는 같은 검증된 refs를 쓴다. 원문 SQL·payload·마커·계정·응답은 저장하지 않는다.
기존 agent의 독립 exploit/fix verification=false를 runtime confirmed로 덮어쓰지 않는다. 새 runtime 증거 의미를 별도로 설명한다.
report.json의 정확한 UTF-8 bytes를 먼저 확정하고 SHA256을 agent-report의 reportArtifact에 넣는다. agent-report는 마지막에 쓴다.
manifest가 4종 raw SHA와 단계/cleanup refs를 결속하고 publication receipt는 manifest hash를 결속한다. 자기 참조 hash 순환은 만들지 않는다.
per-file 임시 파일→rename을 쓰며 네 파일을 한 트랜잭션이라고 부르지 않는다. 소비자는 manifest/receipt·raw SHA 불일치에서 미완료로 거부한다.
old/new 포맷 혼합·오래된 산출물·중도 출판 실패를 새 verify 성공으로 인정하지 않는 테스트를 둔다.

## 5. 후속 파일·검증·공유 요청

신규/변경 파일·테스트·역할 소유와 PLAN 11/R8 case 매핑은 R1 §7만 유일한 권위 목록으로 삼는다. 독자 파일 명부를 두지 않는다.
현재 CLI/parser/pipeline·공통 report dispatch·init-target·보고서 전달의 모든 경로 요청을 R1 canonical 목록 작성자에게 송부했다.
내부 runtime projection 모듈은 A 공통 모델의 구현 분리일 뿐 별도 envelope/주포맷이 아니다. 실제 쓰기 권한은 후속 패킷에서 받는다.
R1에 공통 runtime union·evidence 분기·판별자·verifyGate·artifact refs를 요청하고, transport/lifecycle는 R3 capability만 소비한다.
R8만 reports/CLI의 고정 입력·기대 0/1/2·unknown·손상/혼합 사례를 작성한다. R10은 그 입력·기대값을 읽기만 한다.
갱신된 공통 reader→sanitiser→4종 writer 왕복에서 필수 check/field/null/partial/grade/reach가 보존되는지 확인한다.
runtime 판별자/필드 혼합·누락·손상은 거부하고, runtime 발견+오류를 구 scanGate에 보내 2로 오독하지 않는 분기를 검증한다.
동의 없는 target read/output/Docker/request 0, help/init-target에서 lifecycle 0, 중복 인자·경로 탈출·취소·정리 실패를 확인한다.
finding+실패→1/실패만→2/완료→0, metadata 손상·표현별 불일치·secret canary·stale manifest·출판 중단을 검증한다.
R9가 실제 Spring 취약/수정/안전 쌍·route/line coverage와 4종 raw hashes를 로컬/CI에서 독립 확인한다.
기존 cli/report/agent-report/compare/compat-0.5/runtime-m0 hash 테스트와 KPI compare를 기준 변경 없이 유지한다.
contracts/report/보안·비밀값 경계의 실제 구현은 필수 CPx에서 검토받는다. 이 문서 작성으로 검증이 끝났다고 주장하지 않는다.
PLAN13의 target 위치는 독립 wakeio.target.yml 추천, compose x-wakeio 대안은 미확정이다. 기존 scan exit 변경도 M1에서는 하지 않는다.
PLAN14.4에 따라 M1 authz/workflow 범위는 늘리지 않는다. M2 owner 성공 대조·규칙 없는 unknown은 그 CP1에서 설계한다.
