# Schemathesis authenticated GET controls — 2026-10-13

Baseline은 `dd1d512`이다. 공식 source를 읽고 채택한 설계를 구분한 기록이며, 실행 결과는 receipt가 도착한 뒤 추가한다. 이 연구자는 build/test/scan, 대상 설치·import·실행, Git 변경이나 live provider 호출을 하지 않았다. 독립 acceptance는 [별도 동결 계약](../schemathesis-auth-acceptance.md)이 소유한다. 소스 preview는 0.5.0이고 npm 발행본은 0.4.0이다.

## Primary sources와 실제 경계

| 확인 범위 | 공식 source와 확인한 사실 |
| --- | --- |
| Schemathesis 4.2.0 `Case.call` | [Case](https://github.com/schemathesis/schemathesis/blob/v4.2.0/src/schemathesis/generation/case.py), [prepare_headers](https://github.com/schemathesis/schemathesis/blob/v4.2.0/src/schemathesis/transport/prepare.py), [Requests transport](https://github.com/schemathesis/schemathesis/blob/v4.2.0/src/schemathesis/transport/requests.py): case headers 다음 explicit call headers를 case-insensitive하게 합친다. 이후 coverage의 missing-header 제외가 헤더를 제거할 수 있다 |
| 생성되는 인증 입력 | [generation config](https://github.com/schemathesis/schemathesis/blob/v4.2.0/src/schemathesis/config/_generation.py)는 security generation 기본 true. [security adapter](https://github.com/schemathesis/schemathesis/blob/v4.2.0/src/schemathesis/specs/openapi/adapter/security.py), [schema](https://github.com/schemathesis/schemathesis/blob/v4.2.0/src/schemathesis/specs/openapi/schemas.py)는 http Authorization과 apiKey header/query/cookie를 parameter로 구성한다. false 설정만으로 명시적인 ordinary parameter를 제거하지 않는다 |
| Requests 2.34.2 | [sessions](https://github.com/psf/requests/blob/v2.34.2/src/requests/sessions.py)는 요청 준비 때 cookie jar와 request cookies를 합치고 response cookie를 redirect 여부와 별개로 보존한다. [authentication docs](https://requests.readthedocs.io/en/latest/user/authentication/#netrc-authentication)는 netrc가 raw Authorization을 덮어쓸 수 있고 `trust_env=False`로 비활성화한다고 명시한다. [models](https://github.com/psf/requests/blob/v2.34.2/src/requests/models.py)의 auth handler는 prepared header를 바꿀 수 있다. [adapters](https://github.com/psf/requests/blob/v2.34.2/src/requests/adapters.py)의 기본 retries는 0이다 |
| TLS 전송 | [Node 22.22.1 HTTPS](https://nodejs.org/download/release/v22.22.1/docs/api/https.html)와 [TLS](https://nodejs.org/download/release/v22.22.1/docs/api/tls.html)는 CA/hostname 검증과 servername/SNI, certificate authorization 경계를 제공한다. 고정 IP 연결에서도 원 hostname으로 TLS 검증해야 한다 |
| 인증/권한 대조 | [OWASP WSTG v4.2 authentication bypass](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema/)는 보호된 기능에 실제 인증이 적용되는지 확인한다. [authorization bypass](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/)는 정상 권한/다른 identity·role의 응답과 접근을 비교한다. 아래의 exact scalar·횟수·gate는 Wakeio의 채택한 설계 추론이며 OWASP가 지정한 exact algorithm은 아니다 |

확인 날짜는 2026-10-13이다. repo lock은 Schemathesis 4.2.0과 Requests 2.34.2를 지정하고 준비한 환경의 metadata도 같은 버전이었다. source tag와 배포 artifact의 runtime fingerprint는 다른 근거다. [Schemathesis 4.2.0은 MIT](https://github.com/schemathesis/schemathesis/blob/v4.2.0/LICENSE), [Requests 2.34.2는 Apache-2.0](https://github.com/psf/requests/blob/v2.34.2/LICENSE)이다. upstream code나 payload를 이 문서에 복사하지 않았으며, 새 독립 구현에 MIT라는 표지를 강제로 적용하지 않는다.

## 채택한 규칙 5개

1. **한 Authorization snapshot:** Node가 정책의 한 환경변수에서 전체 헤더 값을 한 번 읽는다. 생성 Authorization/Cookie와 응답 Set-Cookie는 제거하고 credential은 Node 전송 config에만 둔다. cookie/session auth·자동 로그인·refresh·netrc auth를 이번 계약으로 확대하지 않는다. 응답이 token을 반영하면 worker가 transient body로 볼 수 있으므로 credential secrecy를 worker의 관측 불가능성이라고 주장하지 않는다.
2. **TLS-aware Node gate:** 기존 CONNECT는 tunnel 수/byte를 셀 뿐 암호화된 HTTP method/request count를 볼 수 없다(`src/dast-egress.ts`). 최초 연구의 HTTP-only 제안은 채택하지 않았다. 대신 worker는 고정 HTTP facade만 호출하고 Node가 승인한 HTTP/HTTPS origin의 pinned peer에 실제 GET을 전송한다. HTTPS는 정상 CA·원 hostname/SNI·peer 검증을 유지한다. plain HTTP credential은 literal loopback + allowPrivate로 제한한다. 임의 Python/engine 코드에 대한 OS sandbox는 아니다.
3. **정상과 익명 대조:** identity-before → operation별 anonymous-normal 401/403 + protected marker absent와 authenticated normal-before → generated → normal-after → identity-after. anonymous 부재 확인도 유효한 UTF-8 JSON이 전제이며 empty/malformed/non-UTF-8은 partial 2다. identity/normal은 정확한 2xx status와 nonempty string·finite number·boolean JSON scalar를 확인한다. 대조 요청은 `2+3N`, 최소 전체 request budget은 `2+4N`이다. 전 단계가 wire request/response byte/time 예산을 공유하며 redirect/retry를 추가하지 않는다.
4. **관찰과 완료 분리:** 생성 5xx는 medium 관찰이며 fail-on medium에서 1. 대조 실패·생성 401/403·ignored credential·drift·미완료는 2이고 기존 positive를 지우지 않는다. 전부 거부된 실행을 0으로 만들지 않는다. 완료된 bounded 검사 0도 BOLA·SQL exploit·일반 인증 안전·전체 API coverage·검증한 수정이 아니다.
5. **보고서·agent 경계:** policy/schema/worker digests와 실제 runtime, typed control outcome/count를 네 형식에 보존한다. 원 authenticated scope 증거 누락을 credential-free 완료로 재해석하지 않는다. raw token/env name/oracle/normal query/body, exception·cURL은 출력하지 않는다. fingerprint는 정확한 replay 권한이 아니다. advice는 enum/count 중심 진단이며 별도 report upload opt-in이다. 이번 slice는 live Codex 호출·자동 수정·새 OSS 취약점 발견을 주장하지 않는다.

## 채택한 입력과 validation 상태

정책은 `version:1`, `kind:schemathesis-get-auth`, `baseUrl`, `authorizationEnv`, `identity`, `operations[].path/normal`의 고정 shape다. CLI는 `--schemathesis-auth-policy FILE`을 기존 OpenAPI·api-base·operation·active-consent와 함께 쓰고 SDK는 `authPolicy/env`를 받는다. 정상 path/query는 선택한 OpenAPI template의 concrete 요청이다. [합성 예제](../../examples/schemathesis-auth-policy.json)는 실제 target이나 credential이 아니다. [사용 안내](../schemathesis-auth-controls.md)는 검사·gate·네 보고서·선택적 agent 단계를 연결한다.

이 절은 실행 전 채택한 계약이다. 아래 후속 로컬 검증과 distribution·hosted 결과는 각각의 실제 receipt로 구분한다. receipt 없는 단계는 성공으로 간주하지 않는다.

### 구현 전 baseline 실측 — 2026-10-13

Root가 동결한 `dd1d512`에서 같은 소유 protected V/F를 검사했을 때 둘 다 completed·exit 0이었다. 각각 요청 두 건은 모두 401이고 protected handler 도달 수는 0이었다. 기존 credential-free live 회귀는 6/6 통과했다. 이는 기존 credential-free 응답 검사의 결과이며 보호된 handler에 도달한 증거나 V/F 구분의 성공이 아니다. 이 slice의 공백은 이 authentication reachability와 완료 근거를 추가하는 것이다. private local-only receipt: `artifacts/schemathesis-auth-2026-10-13/baseline-gap.json`. 새로운 취약점 발견이나 실제 외부 서비스 효과로 재해석하지 않는다.

## 후속 구현·로컬 검증 — 2026-10-13

첫 focused 실행은 19/21이었다. 실제 dropped-reply 대조에서 Requests의 retry 0과 별개로 Hypothesis가 실패 예제를 다시 호출해 생성 요청이 한 번 더 전송됐다. Worker의 종료 latch와 Node gate의 terminal-stop latch로 후속 전송을 차단했다. 따라서 generator의 설정만으로 no-retry를 증명하지 않고 실제 wire count를 확인한다. 다른 실패는 비교 fixture가 ledger hash만 바꾸고 자기 scope binding을 그대로 둔 모순이었다. strict rejection을 유지하는 assertion을 추가하고, 일치하는 변경 scope/ledger는 원 fingerprint가 같아도 unverified로 비교하도록 fixture를 고쳤다. 첫 전체 suite의 1122/1123은 기존 fake-CLI 테스트의 현재 projection 기대값 10이 남은 결과였다. 두 현재 기대값을 11로 동기화했고 인증 모드·secret 제외·replay 제한 assertions와 historical live receipts는 유지했다.

최종 root 실행은 focused 21/21, support 18/18, 전체 required suite 1123/1123이다. failed/skipped/cancelled/todo는 모두 0이고 독립 acceptance source와 fixture hash는 사전 동결 그대로다. Required receipt의 세 단계 모두 exit 0·cleanupConfirmed true이며 sourceBefore/After는 동일한 `349855abbaeb3771736809e8b7c4e7b708fe9108e13b983db4a5b3771686a5bc`(264 files, 3489331 bytes)다. Private local-only receipt: `artifacts/schemathesis-auth-2026-10-13/required-final/required-engine-RkjI5w/receipt.json`.

실제 public CLI는 같은 소유 합성 API의 아래 결과를 기록했다. V/F의 정상·무인증·전후 identity controls는 matched이고, all-deny는 normal-before, drift는 identity-after에서 실패했다. 네 report 형식의 byte count와 digest도 각 row에 보존했다.

| 소유 대조 | CLI gate | 실제 HTTP attempts | 생성 id=2 도달 수 | 상태 |
| --- | ---: | ---: | ---: | --- |
| V: 보호된 generated 5xx | 1 | 7 | 1 | completed |
| F: 같은 generated 입력의 정상 대조 | 0 | 7 | 1 | completed |
| all-deny | 2 | 3 | 0 | partial: normal_control_mismatch |
| trailing principal drift | 2 | 7 | 1 | partial: identity_mismatch |

Private local-only public CLI receipt: `artifacts/schemathesis-auth-2026-10-13/local-cli/receipt.json`. 이 V/F는 실제 Schemathesis·Node 전송 경로와 소유 handler의 구분을 검증한 범위이며 외부 staging·OSS 취약점·상용 탐지율·확인한 exploit 또는 수정의 증거가 아니다. 이 문서 동결 시점에 fresh source/npm archive consumer와 GitHub hosted 실행은 아직 완료 근거가 없고, 이후 별도 receipt와 최종 PR/CI 기록으로 확인한다. npm 발행이나 live Codex 호출은 이번 slice에서 주장하지 않는다.
