# 선택적 native SAST preview

기본 source 검사는 그대로다. 직접 준비한 Opengrep core를 선택하는 실험 경로는 다음과 같다.

```sh
wakeio-security-ci scan --source ./app --tools none --opengrep-core /absolute/path/opengrep-core --out ./reports
```

SDK는 `runSource({ root, tools: [], nativePreview: { executable: absolutePath }, signal })`을 사용한다. `signal`은 단계 사이와 scanner child의 협력적 취소이며 동기 AST 분석을 선점하지 않는다. source 없는 flag, 누락값·상대 경로는 CLI usage error다. 기본 tools, installer, Action 입력은 native를 자동 선택하지 않는다.

현재 선택 profile `native-preview-v1`은 Darwin arm64의 Opengrep core 1.30.0 하나만 지원 대상으로 둔다. binary 173348760 bytes/SHA256 `9d101457981b1dea39013cf61cabbf896cefbb7e664c19efdb21ee8be4a598de`를 대조하고 원본 자체 Apache rule pack SHA256 `596df423168083551b64ccc74806353b04f031889bd3d06ec8bbd6afe48b32c1`만 사용한다. Linux/Windows 선택은 error/exit2이며 Linux CI 운영 지원으로 해석하지 않는다. 프로그램은 engine을 다운로드하거나 번들에 포함하지 않는다. engine의 LGPL-2.1 및 해당 배포 의무와 자체 규칙의 Apache-2.0은 별도다. [notice](../THIRD_PARTY_NOTICES.md)를 확인한다.

JS/TS의 이름이 req/request인 query/body/params와 Python request args/form `.get`·subscript/json subscript를 source 형태로 선택한다. SQL 첫 인자와 Node exec/execSync, Python subprocess literal shell=True 및 os.system/popen을 선택한다. binding/shadowing, guard, 실행 시 string 타입, execFile/spawn shell=True, 완전한 framework semantics와 exploitability는 검증하지 않는다. 후보는 severity high와 confidence low를 분리해 표시한다.

native에는 collector가 받아들인 JS/TS/Python code만 별도 private stage로 전달한다. target config·ignore·secret·dependency 파일은 전달하지 않는다. stage는 원문을 가진 로컬 temporary source이며 전체 masked source라는 보장은 없다. HOME/TMPDIR는 별도 private 디렉터리이고 최소 OS PATH만 전달한다. proxy·credentials·provider auth를 상속하지 않는다. 고정 Darwin network-deny wrapper, local config, controlled project root, autofix/버전 검사/원격 설정 비활성화 경로를 사용하며 unrestricted fallback은 없다. target hooks/build/import/실행은 하지 않는다.

native 실행 deadline은 `min(timeoutMs, 10000)`이다. output cap 8MiB, jobs1, native max-memory256MiB와 규칙 timeout2초, owned group sampled RSS512MiB/100ms를 적용한다. 정리 유예는 별도 최대2초이며 OS 관측·스케줄링은 hard realtime 보증이 아니다. sampled RSS는 kernel hard RAM isolation이 아니다. close와 owned PGID 정리를 따로 확인하고 관측 실패/평가 불가/cleanup unknown은 완료가 아니다. EPERM은 unknown이며 ps로 성공을 추정하지 않는다. setsid escape·parent SIGKILL recovery·hostile-code sandbox 보장은 없다.

raw exit0은 Wakeio 성공 판정이 아니다. selected file inventory와 `paths.scanned`, native version/ID/range, errors/skips, ignored 상태, 후보/exit 관계를 함께 검증한다. 유효한 후보에 `is_ignored:true`가 붙거나 후보가 있는데 native exit0이면 후보를 보존하고 partial/CI2로 표시한다. parse/error/skip/coverage 불일치, 취소/timeout/출력/자원/cleanup 미확인도 incomplete다. `--fail-on none`은 incomplete를 무시하지 않는다. invalid protocol·identity·실행 불가는 error다. 미지원 finding ID/path/range는 근거로 전이하지 않는다.

공개 JSON/SARIF/Markdown/agent에는 고정 안내와 상대 위치만 넣는다. native message/lines/metavars/content/stderr/private path는 복사하지 않는다. byte offset·UTF8 column을 대조한 뒤 public column은 기존 TS와 같은 UTF16 code unit으로 변환한다. 실제 native 한글/astral 및 CRLF 관측은 좁은 calibration 근거이며 범용 Unicode 지원을 보증하지 않는다. source/sink/intermediate는 engine이 제공한 위치만 사용하고 call/return edge를 합성하지 않는다. native staticFlow는 항상 truncated이고 trace가 없으면 not_provided다. 잘못된 trace는 유효 후보를 지우지 않고 incomplete로 표시한다.

verification not_run/false와 remediation not_verified를 유지한다. static candidate는 실제 취약점·수정 확인이 아니다. 4 reports는 기존 sanitization과 단일 scanGate를 공유한다. report delivery는 파일별 atomic이며 scanGate와 별도다. delivery 실패는 CLI2이고 이전 artifact는 final 성공 receipt가 아니다.

binary와 stage의 전후 hash는 관측 사이 변경을 찾는 제한적인 identity 확인이다. hostile한 동시 mutation 또는 모든 TOCTOU 공격을 완전히 방어한다고 주장하지 않는다. 이 preview의 실제 지원 수용은 별도 실행·출력·정리 검증 근거가 필요하며 기본 엔진 채택·상용 parity·전체 CI 목표 완료를 뜻하지 않는다.
