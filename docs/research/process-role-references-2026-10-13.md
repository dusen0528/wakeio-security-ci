# Node child_process 인자 역할 근거 (2026-10-13)

상태: 읽기 전용 조사와 설계 근거다. 제품 기준선은 `b1ad87670bca7664e2a06dfef38e0eaab86b96d3`이며 이 조사에서 제품 코드·모델·벤치마크 oracle을 수정하거나 빌드·검사·대상 앱 실행을 하지 않았다. 아래의 채택 의미는 증분 설계의 의미 계약이며 구현 완료를 뜻하지 않는다.

## 기준선과 기존 OSS 증거

`docs/fork-role.md`와 `src/source/fork-role.ts`의 native 역할은 `fork`의 modulePath인 arg0에 한정되어 있다. `src/source/ast.ts`의 기존 `SHELL_SINK`는 bare `exec/execSync/spawn/spawnSync/fork` 및 일부 `child_process.*` spelling에 대해 arg0 흐름만 사용한다. 새 증분에서 검토할 구조적 차이는 API identity, 실행 파일과 argv의 역할, options overload다. 이는 현재 실제 OSS에서 해당 미검출을 측정했다는 뜻이 아니다.

기존 `benchmarks/oss-corpus.json`, `docs/research/oss-source-efficacy-2026-10-13.md`, `artifacts/oss-efficacy-2026-10-13/conditional-final-efficacy-review.md`를 읽었다. 고정 Juice Shop/NodeGoat의 사전 지정 일곱 HTTP 흐름은 SQL/NoSQL/eval/redirect이며 이 여섯 child_process API 흐름을 포함하지 않는다. 이전 공식 결과는 **5/7, partial, exit 2**다. 이번 조사로 분모·결과를 다시 쓰거나 현재 증분의 회수율로 가져오지 않는다. 두 checkout의 요청 처리 소스 검색에서 신규 process-role의 HTTP 양성 기준은 확인하지 못했다. 이는 전체 프로그램에서 process 실행 위험이 없다는 판정이 아니다.

## 공식 Node 22 의미

버전을 고정한 [Node v22.22.0 child_process 문서](https://nodejs.org/download/release/v22.22.0/docs/api/child_process.html)를 확인했다. `shell`의 기본 셸은 Unix `/bin/sh`, Windows `ComSpec`이다.

| API | arg0 | 선택 인자 | 기본 셸 |
| --- | --- | --- | --- |
| `exec` | shell command 문자열 | options, callback | 사용 |
| `execSync` | shell command 문자열 | options | 사용 |
| `execFile` | executable file | argv, options, callback | 없음 |
| `execFileSync` | executable file | argv, options | 없음 |
| `spawn` | executable command | argv, options | 없음 |
| `spawnSync` | executable command | argv, options | 없음 |

뒤 네 API에서 `args`를 생략하면 options는 arg1이고 배열 args가 있으면 arg2다. `shell: true` 또는 비어 있지 않은 셸 경로 문자열은 셸을 사용한다. Node는 셸 사용 시 입력을 검증하라고 명시한다. `argv0`는 자식의 argv[0] 값이며 실행 파일 선택과 별도다. `execFile`/`spawn`의 args + shell true는 v22.15.0부터 deprecated지만 제거되거나 안전해진 것이 아니다. [공식 API](https://nodejs.org/download/release/v22.22.0/docs/api/child_process.html#child_processexecfilefile-args-options-callback)

[고정 Node 구현](https://github.com/nodejs/node/blob/v22.22.0/lib/child_process.js#L177-L223)의 `normalizeExecArgs`는 문자열이 아닌 shell을 true로 바꾼다. 따라서 `exec/execSync(..., {shell:false})`를 no-shell로 제외하면 안 된다. `execSync`도 같은 정규화를 쓴다. [동일 구현의 `normalizeSpawnArguments`](https://github.com/nodejs/node/blob/v22.22.0/lib/child_process.js#L529-L630)는 shell의 truthiness로 분기하고 file과 args를 공백으로 합친다. 비어 있는 문자열 `shell: ''`는 이 분기를 타지 않는다. 이 구현상 edge를 비어 있지 않은 경로 문자열과 같게 취급하지 않으며, 문서상 통상적인 shell 설정의 안전 인증으로 확대하지 않는다. 실제 실행은 하지 않았다.

Node의 [보안 권고](https://nodejs.org/en/learn/getting-started/security-best-practices#malicious-third-party-modules-cwe-1357)는 프로세스에서 실행되는 코드와 의존성의 권한을 설명한다. 외부 clone은 여기서 SOURCE DATA ONLY다. install/import/build/test/server/DB/DAST, 대상 소스의 실행, maintainer 연락 및 disclosure는 이 조사에서 하지 않았다.

## 채택할 정적 의미와 제한

1. 정적으로 identity가 확인된 API만 command/executable/argv 역할로 분리한다. fork의 modulePath 계약은 유지한다. 동적 load, shadowed require, mutation/escape 및 불완전 scope/index의 native identity는 별도 미해결 상태다.
2. `exec/execSync`의 입력 관련 arg0는 shell-command 후보다. 뒤 네 API의 입력 관련 arg0는 executable 선택 후보이고 argv는 별도 근거다. argv와 options의 입력을 arg0 근거로 복사하지 않는다.
3. 뒤 네 API의 argv가 입력 관련이고 `shell:true`/비어 있지 않은 shell 문자열이 확인되면 shell-argument injection 후보다. 동적 options, spread, mutation, 불명확한 overload를 false/default 증명으로 쓰지 않는다. literal/object 해석 범위와 자원 한도는 구현 계약에서 선언해야 한다.
4. false/default로 제외하는 것은 이 Node 옵션으로 인한 **셸 해석 경로**뿐이다. 프로그램 옵션, 명시적 interpreter 호출, executable 선택, 환경·PATH·cwd·argv0, 입력 검증 및 권한의 안전을 뜻하지 않는다. [OWASP의 Argument Injection 설명](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md#argument-injection)도 argv 분리와 입력 검증을 함께 다룬다.
5. 모든 결과는 source→정확한 인자→sink의 정적 후보다. 실행·악용·수정 완료 또는 실제 native runtime identity를 확정하지 않는다. 아래의 외부 소스 대조가 detector 성공이나 incremental real-source gain을 대신하지 않는다.

## 독립 HTTP 소스 양성과 역사적 수정 패턴

[Appsecco DVNA](https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/README.md)는 작성자가 의도한 취약 Node 학습 앱이며 [MIT](https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/LICENSE)다. 공식 URL `https://github.com/appsecco/dvna.git`만 작게 clone했다. 무시되는 `artifacts/process-role-2026-10-13/reference-clones/dvna`의 HEAD는 `9ba473add536f66ac9007966acb2a775dd31277a`, tree는 `fb11a01b9c97ec7b979386ddeb5c396783fef1a8`이며 작업 파일 변경은 없다. Clone/fetch는 hooksPath `/dev/null`, submodule.recurse false로 수행했고 대상 스크립트는 실행하지 않았다.

- **실제 HTTP 양성 소스**: [고정 `server.js:38`](https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/server.js#L38)은 `/app` 라우터를 mount한다. [`routes/app.js:52`](https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/routes/app.js#L52)는 인증 middleware 뒤 `POST /ping`을 `appHandler.ping`으로 등록한다. [`core/appHandler.js:38-44`](https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/core/appHandler.js#L38-L44)의 `req.body.address`가 검증 guard 없이 `exec` arg0 문자열에 이어 붙는다. 작성자 [가이드](https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a1-injection.md#L53-L94)도 이 경로를 command injection으로 설명한다. known-vulnerable source reference이며 새 발견이나 로컬 악용 확인이 아니다.
- **역사적 fixed-pattern 소스**: 작성자 가이드가 가리키는 [수정 commit `4fe36fcfbd615fc9ea340e1238be33dd0d140ef8`](https://github.com/appsecco/dvna/commit/4fe36fcfbd615fc9ea340e1238be33dd0d140ef8), tree `6a41d99fa4c02503c2ac0e35a87b0e27a9ac36ef`의 [`core/appHandler.js:41-53`](https://github.com/appsecco/dvna/blob/4fe36fcfbd615fc9ea340e1238be33dd0d140ef8/core/appHandler.js#L41-L53)는 `execFile`의 고정 executable과 argv를 사용하고 shell 옵션이 없다. `vh.vIP` guard도 있다. 이를 같은 요청값을 셸 문자열에 넣는 패턴이 제거된 음성 대조로 쓸 수 있지만 프로그램·검증 라이브러리·권한의 안전을 인증하지 않는다.
- **직접 before/after 효능 쌍 아님**: 해당 수정의 부모 `dc1f9c54685eb04f55e444370d6d622834e4cc00`, tree `c20f8b7f2ab9a2c7e4fbfde35c5f08e386cd797c`는 이미 `vh.vIP`를 적용한다. [`validationHandler.js:19-22`](https://github.com/appsecco/dvna/blob/4fe36fcfbd615fc9ea340e1238be33dd0d140ef8/core/validationHandler.js#L19-L22)가 `validator.isIP(...,4)`를 사용하므로, guard 우회 근거 없이 그 부모를 독립 취약 양성으로 세지 않는다. 현재 master와 역사적 fix는 서로 다른 고정 소스의 패턴 대조다. 이름이 fixes-2017인 다른 ref `56c5e82c1a000e26ae19afb67b6696d634ceab2e`에도 exec가 남아 있어 branch 이름을 수정 완료 근거로 쓰지 않았다.

이 소스는 `const exec = require('child_process').exec` / `const execFile = require('child_process').execFile`라는 **member extraction**을 사용한다. 기존 bare exec heuristic의 후보 대상일 수 있지만 fork lexical 계약의 신규 지원 범위는 아니다. 새로운 process-role이 해당 extraction을 지원하지 않는다면 native identity 성공 증거로 사용하지 않는다. 양성 검출 자체도 이 조사에서 실행하지 않았다. 실제 파일을 그대로 읽는 독립 결과가 없으면 신규 역할의 real-source 효능은 미측정이다.

### 전체 파일 SHA-256

| pin | file | SHA-256 |
| --- | --- | --- |
| `9ba473a` | `LICENSE` | `c4bde472e45bb9bedfe4c767de1485450d3886d0bfd37412c8f8c402f48a4e8a` |
| `9ba473a` | `README.md` | `13f721c2dfe2123a72c3b2150481cfef66d52fec7f6b747ad4c6c76e23158ec8` |
| `9ba473a` | `core/appHandler.js` | `0fc237589d5a9e73450d089f97124fb943d68222f70df0e973a8b9acfe2ebb6b` |
| `9ba473a` | `routes/app.js` | `339023b38a30dc1d79136b964092c8e35c1702a133521e0a56ce5683d6a0e9bc` |
| `9ba473a` | `server.js` | `46fea6b48ee71281ee4448224879e7b2633e2acbf8acb496298a33cef1598524` |
| `4fe36fc` | `LICENSE` | `3918b81077d08aa4e30a81f813bbd101391fcc22395ff64c3812cf0afdc40084` |
| `4fe36fc` | `core/appHandler.js` | `01d683767591ba9793d98b821d32d07e840f1c247c63f5eec2266811d4ade2cc` |
| `4fe36fc` | `core/validationHandler.js` | `78c49dc0f27c2cd47f01e72364e708fc3dd18caea25021fcd9e4e780d7ca497e` |
| `4fe36fc` | `routes/app.js` | `94dd5267bcd13f3002c4c5f3f5aa4b89396133138ac422a3b618400197a9e8f8` |
| `4fe36fc` | `server.js` | `b3c5eee507929a76cb3694562b00cfa46f23a2c6d50dd23c942235a707b7a4dd` |
| `dc1f9c5` | `core/appHandler.js` | `96f9887a4570ac9e22972ad30af40485b2b0c1b7611deb5398380760ddce9ac2` |

Historical file bytes were read with `git show <full pin>:<path>`; HEAD and FETCH_HEAD must not be interchanged. Source lines and hashes above are independent of scanner output. No external source was copied into product modules or tests; preserve MIT notice if later redistributing source portions.

## 공개 argv + shell 보안 기록

Maintainer가 공개한 [glob GHSA-5j98-mcp5-4vw2 / CVE-2025-64756](https://github.com/isaacs/node-glob/security/advisories/GHSA-5j98-mcp5-4vw2)는 CLI `-c/--cmd`에서 matched filename argv가 `shell:true`로 전달되는 command injection을 설명한다. 구조화된 patched versions는 `10.5.0, 11.1.0, 12.0.0`이다. API 라이브러리 전체의 취약점으로 확대하지 않는다.

[공개 수정 `1e4e297342a09f2aa0ced87fcd4a70ddc325d75f`](https://github.com/isaacs/node-glob/commit/1e4e297342a09f2aa0ced87fcd4a70ddc325d75f)는 `foregroundChild(cmd, matches, {shell:true})`를 바꾸고 셸 positional arguments를 구분한다. 프로젝트는 [ISC](https://github.com/isaacs/node-glob/blob/1e4e297342a09f2aa0ced87fcd4a70ddc325d75f/LICENSE)다. 공개 diff를 읽었으며 clone/install/실행은 하지 않았다. 이는 shell argv 위험의 실제 공개 사례지만 source는 filesystem/CLI이고 호출은 `foregroundChild` wrapper다. 이번 HTTP source/native child_process 모델의 직접 양성 분모나 지원 성공으로 세지 않는다. Wrapper/CLI/filesystem source를 지원하지 않는 모델의 무후보를 안전 판정으로도 쓰지 않는다.

## 우선순위

우선 공식 overload·shell 의미와 인자별 trace 계약을 합의하고, identity/overload가 불명확할 때 제외하지 않는 설계를 검토한다. 그다음 승인된 구현과 독립 결과가 마련되면 위 소스 pin의 정확한 HTTP 경로를 파일 그대로 대조한다. 기존 일곱 흐름은 이전 partial 측정으로 보존한다. 현재 증거는 의미 계약과 실제 외부 소스의 제한된 패턴 대조까지이며 신규 detector의 검출·정밀도·회수율은 미측정이다.
