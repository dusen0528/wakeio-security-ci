# F6-2 초안: OpenAPI GET contract preset

상태: 사용자 검토 수정 반영, 구현 기준. 실행 시 provenance 검증은 F6-4에서 설계한다.

## 1. 기준과 범위

- 2026-10-26: CI 5종 성공을 확인하고 사용자 승인으로 #79를 머지했다. origin/main은 `b26fd797d6464bca9f050234615f29946df17dcc`이며 #81의 base는 main이다.
- inventory 계약과 기존 v1 플랜/inputs 검증기는 위 main 기준이다. 이번 수정에서 run-plan 및 v1 검증기는 변경하지 않는다.
- 첫 프리셋은 `openapi-get-contract` 하나다. 인증 정책 생성, 다른 엔진, 소스 route, 자동 실행, LLM, 새 취약점 규칙, POST는 포함하지 않는다. 코드포인트 순 정렬 후 GET을 태스크당 16개씩, 최대 16태스크로 분할한다.
- 생성은 DNS/HTTP·프로바이더·대상 스크립트·Python worker 없이 끝난다. 실행 예시는 계약 설명일 뿐 이번 작업에서 실행하지 않는다.
- 기존 v1 plan/inputs 스키마를 넓히지 않는다. 기존 CLI 모드·플래그·종료 코드 의미를 보존한다.

## 2. 현재 코드가 정하는 제약

| 근거 | 현재 동작 | 설계 영향 |
| --- | --- | --- |
| `src/agent-dast/plan.ts:33` | 플랜 최상위는 version/kind/origin/tasks만 허용 | preset/digest 필드를 플랜에 붙이지 않음 |
| `src/agent-dast/plan.ts:45` | Schemathesis task: schema alias, operation 경로 1..16개, seed 1..2147483647, maxRequests 1..64 | 태스크당 operation 최대 16개, 플랜당 최대 16태스크/256개 |
| `src/agent-dast/plan.ts:65` | inputs 최상위 version/inputs, 항목 id/path/sha256, 최대 32개 | 기존 모양의 alias 4개로 파일 바인딩 |
| `src/agent-dast/runner.ts:87` | 태스크가 참조하는 schema/policy alias만 파일을 읽고 해시 확인 | 사용하지 않는 preset/inventory alias의 해시는 현재 검증되지 않음 |
| `src/agent-dast/runner.ts:104` | 인증 없는 Schemathesis는 HTTPS를 거부 | 첫 프리셋은 HTTP origin만 지원; HTTPS를 준비 완료로 생성하지 않음 |
| `src/openapi.ts:336` | 실행 selector는 문서 전체 참조 규칙과 선택 GET의 파라미터·requestBody 등을 검증 | inventory 열거 성공만으로 실행 플랜 생성 성공을 보장하지 않음 |
| `src/plan.ts:8` | 기존 plan 명령은 정책별 오프라인 preflight | `--preset` 모드만 추가하며 기존 모드의 출력/종료 의미 유지 |

`inventory.json`에는 OpenAPI 응답 스키마/파라미터 본문이 없다. 두 JSON(inventory, preset)만으로는 현재 runner가 실행할 schema 입력을 만들 수 없으므로 **원본 로컬 OpenAPI JSON**도 필수다. 원본을 내려받거나 inventory에서 복원하지 않는다.

이 프리셋은 **loopback HTTP 앱용**이다. 정규화한 hostname이 127.0.0.1, [::1], localhost일 때만 허용하며 다른 원격 HTTP 및 192.168.x 등 사설망 IP는 preset_remote_unsupported로 거부한다. HTTPS·인증 생성은 이번 범위 밖이며 네트워크 요청이나 실행을 자동으로 시작하지 않는다.

## 3. 생성 입력 계약

제안하는 신규 모드:

```text
wakeio-security-ci plan --preset presets/openapi-get-contract.json \
  --inventory inventory.json --openapi openapi.json --out NEW_DIR \
  [--url ORIGIN] [--max-requests N]
```

| 입력 | 계약 |
| --- | --- |
| inventory | `wakeio.surface-inventory/v1`, P1a 실제 필드만 허용. 원본 바이트 상한 1MiB, no-follow 안정 읽기. 필드/상태/카운트의 일관성도 검증 |
| preset | 아래 `wakeio.plan-preset/v1` JSON. 원본 최대 64KiB, 추가 키/중복 surface 거부, 코드/명령/파일 경로/인증 입력 금지 |
| openapi | P1a에 사용한 원본 로컬 JSON, 최대 1MiB. 읽은 원본 SHA256이 inventory.openapiDigest와 같아야 함 |
| origin | inventory.origin이 있으면 사용. `--url`도 있으면 정규화 후 같아야 함. inventory.origin=null이면 `--url` 필수. 스펙 servers에서 가져오지 않음 |
| owner request budget B | `--max-requests` 1..20000, 기본 64. 생성 시 모든 task.maxRequests 합 ≤ B 확인. 플랜이 owner 예산을 올리지 않음 |
| out | 기존 부모 아래의 새 private 디렉터리. caller symlink 거부 및 기존 파일/폴더 덮어쓰기 금지. 출력 경로는 6개 번들 파일 본문에 넣지 않음(stdout 예시 명령에는 포함) |

origin은 기존 `executionOrigin` 문법을 사용하고, 이 프리셋은 추가로 HTTP만 허용한다. loopback 밖 hostname은 preset_remote_unsupported로 먼저 거부하고, loopback HTTPS는 `preset_https_unsupported`로 거부한다. 인증된 HTTPS는 기존에 별도 경로가 있지만 첫 프리셋에 인증 정책/자격증명을 추가하지 않는다. HTTP 지원은 능동 검사의 허가나 대상 도달성을 뜻하지 않는다.

원본 OpenAPI에서 기존 열거기를 다시 호출하고 inventory의 전체 GET 집합·상태·카운트·gap과 비교한다. digest만 맞고 surface 목록이 변조된 inventory도 거부한다. source_routes=unverified는 이 GET 프리셋의 정상 범위이며 차단하지 않는다.

스키마: [프리셋](plan-preset.v1.schema.json), [provenance](plan-provenance.v1.schema.json).

## 4. 프리셋 계약

배포할 첫 파일 `presets/openapi-get-contract.json`의 초안:

```json
{
  "schema": "wakeio.plan-preset/v1",
  "id": "openapi-get-contract",
  "operations": "all",
  "seed": 1,
  "maxRequests": 64
}
```

이 5개 필드만 정의한다. id는 현재 이 값만 허용하고 엔진은 이 id에서 Schemathesis로 고정한다. 플러그인/실행파일/모델/코드/인증 필드는 없다.

- operations: `"all"` 또는 비어 있지 않은 `{ "method": "GET", "pathTemplate": "/items/{id}" }` 배열. 배포 파일은 all이며 명시 선택도 같은 프리셋 계약으로 검증한다.
- seed: 정수 1..2147483647.
- maxRequests: 정수 1..64. 각 분할 태스크의 operation 수 이상이어야 하며, 태스크별 상한 합이 owner 예산 B 이하여야 한다. 예산 오류는 `insufficient_budget required=<태스크 상한 합>` 한 줄과 exit2로 반환한다. required에는 내부에서 계산한 정수만 출력하며 입력 문자열은 포함하지 않는다. 실제 완료나 요청 수를 보장하는 값이 아니라 실행 상한이다.
- surface identity는 대소문자/후행 slash/alias를 보존한 정확한 `(GET, pathTemplate)`이다. operationId는 사용하지 않는다.
- 명시 선택의 모든 항목이 inventory에 있어야 한다. 하나라도 없으면 `surface_not_in_inventory`; 교집합만 취하거나 조용히 건너뛰지 않는다. POST/잘못된 형식/중복도 거부한다.
- 선택 결과는 코드포인트 순으로 정렬한다. 입력 배열 순서는 execution-plan.json 내용에 영향을 주지 않는다. 단, preset의 원본 바이트가 달라지면 preset 해시는 달라진다.
- 선택 GET 1..256개를 정렬 후 16개씩 나눈다. 태스크 ID는 t-openapi-get-contract-01부터 16까지다. 256개 초과만 operation_limit로 거부한다. 모든 태스크 상한 합이 B보다 크면 insufficient_budget으로 거부하며 자동 예산 증액/절단은 하지 않는다. 예: 기본 preset의 17 GET은 2태스크, 합계128이므로 B=64는 거부하고 B=128은 허용한다.
- GET 0개는 `no_operations`로 거부한다. 현재 검증기는 빈 tasks/operations를 허용하지 않는다.
- OpenAPI scope=partial인 inventory는 최초 범위에서 `inventory_partial`로 거부한다. 성공 출력을 통해 미해결 부분을 숨기지 않는다. 특히 현재 실행 selector는 선택하지 않은 영역의 원격 참조도 거부할 수 있다.
- 선택된 GET와 원본 문서를 `selectOpenApiLiveOperations`에 넣어 기존 실행 준비 검증도 통과해야 한다. 문서를 잘라서 기존 전체 참조 제한을 우회하지 않는다.

## 5. 출력 계약

생성 성공 시만 다음 6개 파일을 내보낸다. 원본 3개는 정확한 바이트를 복사하고 private 권한(dir0700/file0600)을 사용한다. 이 3개는 소유자의 입력 사본이므로 정제된 보고서로 취급하거나 에이전트에 전달하지 않는다. 보고서·로그·DB에는 원문 대신 해시만 남긴다.

| 파일 | 내용 |
| --- | --- |
| execution-plan.json | 기존 v1 플랜. 고정 직렬화/키 순서, LF와 마지막 newline |
| inputs.json | 기존 v1 alias 4개. id 순 정렬, 고정 상대 경로와 원본 바이트 해시 |
| openapi.json | 검증한 원본 OpenAPI 바이트 |
| inventory.json | 검증한 inventory 원본 바이트 |
| preset.json | 검증한 프리셋 원본 바이트 |
| plan-provenance.json | 아래의 신규 sidecar 계약 |

플랜 예시(두 surface인 경우):

```json
{
  "version": 1,
  "kind": "wakeio.execution-plan",
  "origin": "http://owner-selected.invalid",
  "tasks": [
    {
      "id": "t-openapi-get-contract-01",
      "engine": "schemathesis",
      "schema": "openapi",
      "operations": ["/items/{id}", "/search"],
      "seed": 1,
      "maxRequests": 64
    }
  ]
}
```

공개 전에 반드시 `parseExecutionPlan`과 `parseExecutionInputs`를 호출한다. 실패한 결과를 성공 출력하지 않는다. 오류 문구를 입력 내용으로 만들지 않는다.

stdout 첫 줄 제안:

```text
Plan status=generated preset=openapi-get-contract tasks=1 operations=2 maxRequests=64
Provenance is recorded only and is not yet verified at execution time.
provenance는 기록만 되고 아직 실행 시 검증되지 않음
```

이 상태는 생성 성공만 뜻한다. 스캔 결과·전체 API 커버리지·엔진 설치 완료를 뜻하지 않는다.

Exit0=검증한 bundle 생성 성공. Exit2=입력·호환성·예산·출력 오류, stderr는 고정 코드 한 줄. 기존 plan의 다른 모드는 변경하지 않는다. --preset과 기존 --api-policy/--openapi-input/--dast-policy 모드를 섞으면 invalid_arguments로 거부한다.

성공 stdout 마지막 줄에 현재 Node/CLI 경로를 사용하는 run-plan 예시를 출력한다. 원래 생성에 쓴 B와 정규화 origin을 그대로 쓰고 --active-consent, --allow-private, plan/inputs 파일, 새 run 하위 폴더를 포함한다. 동적 경로는 POSIX shell 단일 인용으로 보호한다. 명령을 출력할 뿐 실행하지 않는다.

### 임시 폴더 + rename 공개는 F6-3으로 유예

Node 기본 rename은 기존 빈 디렉터리를 교체할 수 있다. 사용자 지정 출력 경로에 대한 기존 no-clobber 계약을 유지하는 exclusive 공개 절차까지 이번 수정에 포함하면 범위가 커진다. 따라서 현재 새 디렉터리 claim/순차 쓰기와 빈 폴더만 정리하는 정책을 유지한다. 실패 시 비어 있지 않은 부분 출력이 남을 수 있고 원자적 bundle 공개를 보장하지 않는다. F6-3에서 전용 임시 폴더 및 배타적 공개/실패 정리 계약을 함께 정한다.

## 6. 해시 결합: v1을 유지하는 sidecar 권고안

플랜에 추가 메타데이터를 넣는 방식은 기존 검증기가 거부한다. inputs에 미참조 alias만 넣으면 현재 runner가 실제 파일을 읽지 않는다. 따라서 **기존 inputs 형식 + sidecar 기록**까지만 구현한다. provenance는 기록만 되고 아직 실행 시 검증되지 않음. 실행 시 검증은 F6-4에서 정한다.

모든 해시는 원본 바이트의 소문자 64자리 SHA256 hex다.

- H_O = SHA256(openapi.json) = inventory.openapiDigest.
- H_I = SHA256(inventory.json).
- H_P = SHA256(preset.json).
- H_E = SHA256(execution-plan.json).
- H_M = SHA256(plan-provenance.json).

신규 sidecar의 형태(기호는 설명용이며 출력에는 실제 해시를 넣는다):

```json
{
  "schema": "wakeio.plan-provenance/v1",
  "planSha256": "H_E",
  "preset": { "id": "openapi-get-contract", "sha256": "H_P" },
  "inventory": { "sha256": "H_I", "openapiDigest": "H_O" },
  "maxRequests": 64
}
```

sidecar.maxRequests는 소유자의 전역 예산 B다. preset.maxRequests와 task.maxRequests는 해당 태스크 상한이므로 같은 이름이어도 범위가 다르다.

inputs는 현재 검증기가 허용하는 형태를 유지한다:

```json
{
  "version": 1,
  "inputs": [
    { "id": "inventory", "path": "inventory.json", "sha256": "H_I" },
    { "id": "openapi", "path": "openapi.json", "sha256": "H_O" },
    { "id": "preset", "path": "preset.json", "sha256": "H_P" },
    { "id": "provenance", "path": "plan-provenance.json", "sha256": "H_M" }
  ]
}
```

해시 의존 관계는 원본 3개 → plan → sidecar → inputs로, 자기 참조 해시를 만들지 않는다. sidecar에는 inputs 자체의 해시를 넣지 않는다. 생성 시 검증한 inventory/preset/OpenAPI로 플랜을 만든다. 실행 시 재검증 기능은 추가하지 않는다.

### 실행 시 검증은 이번 범위 밖

`--verify-provenance`를 추가하지 않는다. run-plan, v1 플랜/inputs 검증기, runner, 보고서, scopeHash, DB를 변경하지 않는다. 생성 시 원본 해시와 입력 계약을 검증해 6개 파일에 기록할 뿐, 기존 runner가 미참조 preset/inventory/provenance 파일을 실행 전에 검증하는 것은 아니다.

**provenance는 기록만 되고 아직 실행 시 검증되지 않음.** 이 문구를 생성 stdout에도 출력한다. 실행 시 검증 계약은 F6-4에서 설계하며 이번 PR의 완료 조건·테스트에 넣지 않는다. SHA256은 서명이나 능동 검사 허가가 아니다.

### 고정 오류 코드

입출력 공통 코드에는 invalid_arguments/path_not_found/unsafe_path/input_changed/input_limit/output_exists/output_error/invalid_origin을 사용한다. 생성 계약은 invalid_inventory/invalid_preset/openapi_digest_mismatch/inventory_mismatch/origin_required/origin_mismatch/preset_https_unsupported/preset_remote_unsupported/surface_not_in_inventory/no_operations/operation_limit/inventory_partial/insufficient_budget을 구분한다. OpenAPI 구조·지원 범위 오류는 기존 타입을 invalid_openapi/unsupported_openapi/input_limit에 매핑한다. 모두 고정 한 줄이며 입력 경로나 예외 메시지를 포함하지 않는다.

검증 순서는 CLI/안전 읽기 → 각 JSON 구조 → OpenAPI digest/inventory 재검증 → origin/프리셋 선택/예산 → 기존 selector/plan/inputs 검증 → 출력이다. 여러 입력이 동시에 잘못되면 이 순서의 첫 오류를 반환한다. 미지원 HTTPS는 구조적으로 유효한 HTTP(S) origin을 확인한 뒤 해당 프리셋의 지원 범위 오류로 구분한다.

## 7. 다음 구현 PR에 함께 넣을 P1a 보완 3건

1. **input_changed**: 읽기 전후 size/mtime/ctime 또는 실제 읽은 길이가 달라지면 구조화한 고정 코드를 반환한다. JSON 오류·digest 불일치와 구분하며 예외 원문과 입력 내용은 출력하지 않는다.
2. **없음과 위험 경로 구분**: ENOENT는 `path_not_found`(입력 파일/필수 디렉터리 없음), symlink·비정규 파일·위험한 출력 포함 관계는 `unsafe_path`로 구분한다. invalid_arguments와도 구분하며 기존 exit0/2 의미는 유지한다.
3. **빈 디렉터리 정리**: 이번 호출이 mkdir에 성공한 뒤 쓰기에 실패했을 때만 빈 디렉터리를 best-effort rmdir한다. 재귀 삭제하지 않는다. 기존 디렉터리·부모 디렉터리·부분 생성 파일이나 다른 파일이 있는 디렉터리는 지우지 않는다. 정리 실패가 최초 오류 코드를 덮지 않게 한다.

이 3건을 F6-2 구현 PR에 함께 포함한다.

프로세스 감시의 간헐 실패는 별도 [이슈 #80](https://github.com/dusen0528/wakeio-security-ci/issues/80)으로 추적한다. 프리셋 구현에 섞거나, 실패를 성공으로 바꾸거나 감시를 일괄 완화하지 않는다.

## 8. 완료 조건과 테스트

| 관점 | 완료 조건 / 테스트 |
| --- | --- |
| 기존 계약 | 성공 생성 plan/inputs는 기존 검증기 100% 통과. 플랜에 메타데이터 추가 시 기존처럼 거부. 기존 CLI 모든 모드/종료 코드/fixture 유지 |
| inventory fixture 8개 | HTTP origin에서 기존 3개+inline-unselected+local-path-item-alias 5개는 정확한 GET 집합의 플랜 생성. no-get/empty-paths는 no_operations, unresolved-path-item은 inventory_partial로 거부 |
| 집합/참조 | 없는 surface, 개수가 같아도 다른 surface, POST, 중복, 대소문자/후행 slash 차이 거부. alias는 별개 surface. all의 조용한 절단 0건 |
| 상한 | 선택 수0/1/16/17/256/257, 16개씩 분할/연속 ID/중복·누락0, 태스크 예산 합이 B와 같을 때 허용/초과 시 거부, seed0/1/상한/상한+1, maxRequests0/1/64/65, operation 수보다 적은 예산, 소유자 B보다 큰 예산은 required=태스크 상한 합을 출력하고 거부, 잘못된 정수 거부 |
| 실행 준비 경계 | 기존 selector가 거부하는 requestBody/callbacks/remote/cycle/ref siblings 등을 우회하지 않고 거부. 실행 준비를 통과시키려고 원본을 고쳐 쓰지 않음 |
| inventory 정합 | 원본 digest 불일치, digest만 맞는 surface 변조, counts/scope/gap 변조, 알 수 없는 스키마/추가 키 거부 |
| origin | inventory origin 사용, null일 때 명시 URL 필수, origin 충돌 거부, servers 무시, 자격증명/query/fragment/path 거부, loopback 3종 허용, 원격/192.168.x/10.x/172.16.x 거부, loopback HTTPS 고정 거부. DNS 0건 |
| 해시 | OpenAPI/preset/inventory 원본의 1바이트 변경, plan/sidecar/inputs의 alias/hash/path 교체를 각각 탐지. 상대 경로 bundle 이동 허용. 자기 참조 해시 없음 |
| 실행 예시 | stdout 명령을 실행하지 않고 shell 인자만 추출해 기존 run-plan 인자 parser로 검증. B/origin/plan/inputs 경로 일치 및 quote/공백/명령 치환 문자가 있는 경로를 그대로 유지 |
| 재현성 | 같은 바이트+origin+B로 3회 생성 시 6파일 모두 바이트 동일. 생성기가 timestamp/run ID/실행 환경의 절대 경로/출력 위치를 6개 번들 파일 본문에 추가하지 않음(stdout 예시 명령에는 포함)(원본 입력 사본의 기존 내용은 그대로 유지) |
| 오프라인 | Docker --network none에서 모든 생성 fixture·origin 문자열·remote ref·없는 surface 거부 검사. worker/provider/자식 프로세스 시작 canary 0건. 의존성 준비와 본 테스트 분리 |
| P1a 보완 | 읽기 중 변경→input_changed, 없음→path_not_found, symlink 등→unsafe_path. 쓰기 실패 시 빈 폴더 정리, 기존/비어 있지 않은 폴더 보존. 정리 실패에도 최초 stderr 한 줄 유지 |
| 회귀 | inventory recall10/10·예상 밖 GET0·기존 init 스냅샷 불변. 기존 전체 테스트·0.5 호환·KPI 차이를 main과 같은 조건에서 측정. 미측정 KPI를 성공으로 취급하지 않음 |

이 문서는 구현 전 수정한 계약이다. 검증 결과는 구현 PR에 별도로 기록한다. 대상 HTTP·대상 스크립트·LLM·배포 및 #81 머지는 수행하지 않는다. #79 머지는 명시적 사용자 승인으로 완료했다.
