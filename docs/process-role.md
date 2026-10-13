# Node process API 인자 역할 (`2026-10-13.2`)

이 문서는 소스 0.5.0 preview의 의미 계약이다. 검증 영수증과 npm 배포 상태는 별도다. 대상 소스는 데이터로만 읽으며 이 모델은 대상 프로그램·명령·의존성을 실행하지 않는다. [독립 수용 계약](research/process-role-spec-2026-10-13.md)과 [공식 API 및 외부 소스 조사](research/process-role-references-2026-10-13.md)에 범위와 고정 근거를 기록했다.

## API와 인자 역할

`child_process`와 `node:child_process`의 `exec`, `execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync`를 대상으로 한다. `fork`의 modulePath는 [별도 기존 역할](fork-role.md)이다. 정확한 lexical ESM named alias/namespace/default import, const CommonJS namespace/destructuring/member extraction, shadow되지 않은 inline require를 구별한다. 일반 동적 load·재export·임의 alias graph 또는 런타임 native identity를 증명하지 않는다.

| 정적 입력 역할 | 후보 | severity / confidence |
| --- | --- | --- |
| `exec/execSync`의 command arg0, 또는 shell이 켜진 나머지 API의 arg0 | `ast:shell-input-sink` | critical / tainted medium, input-related unknown low |
| 기본 direct 실행의 executable arg0 | `ast:process-executable` | high / tainted medium, input-related unknown low |
| 고정 executable + 입력 argv + 확인된 shell true/비어 있지 않은 문자열 | `ast:shell-input-sink` | critical / tainted medium, input-related unknown low |
| 닫힌 options의 입력 shell 필드 | `ast:process-executable` | high / tainted medium, input-related unknown low |
| identity, options 또는 overload가 불명확한 입력 | 역할 미해결 후보 또는 partial | 후보는 low와 truncated trace; partial은 exit 2 |

`execFile/execFileSync/spawn/spawnSync`는 argv를 생략하면 options가 arg1, 배열 argv가 있으면 arg2다. argv의 실제 입력 기여자와 options shell 필드의 위치를 각각 보존한다. 다른 인자나 앞선 무관한 입력의 trace를 대신 사용하지 않는다. 후보의 sink는 실제 호출 위치다. 여러 호출 context가 합류해도 위험·미해결 context를 정상 context의 제외 근거로 덮지 않는다.

## shell 값과 제외의 의미

- `exec/execSync`는 기본 shell command API다. `shell:false/null/숫자/object` 등 문자열이 아닌 값은 Node의 정규화에서 true가 된다.
- 뒤 네 API는 기본값·false·null에서 Node 옵션에 의한 shell 해석을 하지 않는다. true와 비어 있지 않은 문자열은 shell 해석을 켠다. 숫자·object 같은 미지원 값은 런타임 오류 가능성이 있으므로 정적으로 안전 제외하지 않는다.
- 비어 있는 문자열 `shell:''`은 여섯 API의 Node 22 정규화 뒤 falsey라 direct 실행으로 구별한다. 이때 입력 arg0는 executable 선택 후보다. 잘못된 명령 문자열의 실제 실행 성공이나 실패를 판정하지 않는다.
- 입력 `shell:req.query.shell`은 문자열이면 실행할 shell을 선택할 수 있다는 별도 executable 후보다. 정적 입력 certainty와 런타임 타입·실행 가능성을 구분하며 문자열 또는 실행이 확인되었다고 쓰지 않는다.

닫힌 plain options와 argv의 입력을 제한적으로 분석한다. 선언된 scope에서 const 별칭을 사용할 수 있어도 heap 불변성을 자동 보장하지 않는다. mutation/escape, getter/computed field, 미해결 spread, opaque options/argv, 모호한 overload, namespace/member 변경 및 불완전 index는 제외 proof를 얻지 않는다. 중복 shell key는 마지막 data field를 따른다. 실제 accessor를 읽거나 실행하지 않는다.

기본/false에서 입력 argv를 shell 후보로 제외하는 것은 이 Node 옵션의 셸 해석만 제외한다. 프로그램 옵션 주입, 명시적 `sh -c`/`node -e`, executable 선택, PATH·cwd·env·argv0, 권한 및 입력 검증의 안전을 판정하지 않는다. argv/options 계산 안의 eval·SQL·HTTP·HTML sink는 별도로 검토한다. 고정 argv는 전체 process 호출의 보안 인증이 아니다.

## 보고서와 검사 완료 상태

기존 Finding/StaticFlow/AgentReport schema와 finding ID 알고리즘을 사용한다. 결과는 `report.json`, `report.md`, `report.sarif`, `agent-report.json`에 동일한 candidate 의미·severity·근거로 전달된다. 소스·명령 문자열이나 입력값을 보고서에 추가하지 않는다. Agent verification은 `not_run`, vulnerabilityConfirmed와 remediationVerified는 false다.

수집·index·flow cap이나 parse 실패는 기존 partial/exit 2를 유지한다. `--fail-on none`도 미완료 검사를 통과시키지 않는다. 알려진 입력을 보존한 low 후보는 실행 증거가 아니며, 미완료 검사에서 후보가 보이지 않는 결과는 fixed/clean 인증이 아니다. API 지원 밖 문법 자체를 새로운 실제 취약점 또는 coverage 수치로 세지 않는다.

Ruleset `2026-10-13.2`는 process 역할의 후보 집합과 의미 변경을 scope fingerprint에서 구별한다. 이전 `.1` 보고서와 비교할 때 동일 분석 의미나 검증된 수정으로 취급하지 않는다. 보고서 schema·제품 버전·npm 게시 상태를 바꾸는 값은 아니다.

실제 외부 소스에는 DVNA의 고정 HTTP `exec` 경로와 별도 역사적 `execFile` 수정 패턴, glob의 CLI/filesystem argv + shell 공개 기록이 있다. 이들은 신규 detector의 효능·정밀도·회수율 영수증이 아니다. 기존 Juice Shop/NodeGoat **5/7·partial·exit 2**는 이전 측정으로 보존하며 현재 process 모델 결과로 다시 표시하지 않는다.
