# MIT DAST 구현 조사와 Wakeio의 첫 SQL 차등 검사

기준일: 2026-10-13. 조사 시점 checkout: `wakeio-security-ci` `2a3d380`, package `0.5.0`. 공식 저장소 코드·라이선스와 Wakeio의 현재 경계를 확인한 구현 참고 문서다. 외부 서비스를 스캔하지 않았고, 이 문서 자체는 탐지 구현·실측 정확도 증거가 아니다.

## 채택할 좁은 범위

**명시적으로 allowlist에 올린 GET URL의 기존 고유 쿼리 파라미터 하나에 대해, SQL true/false 입력의 응답 차이를 두 번 재현하는 검사**를 첫 범위로 삼는다. ProjectDiscovery의 실제 [Nuclei SQLi template `CVE-2021-36748`](https://github.com/projectdiscovery/nuclei-templates/blob/3d818a6e398abd5867c50b35218ba25224d12b99/http/cves/2021/CVE-2021-36748.yaml)은 true/false 조건을 넣은 두 GET 요청의 status/body/header를 함께 대조한다. 이는 특정 PrestaShop 플러그인·경로에 맞는 탐지기다. Wakeio의 일반용 8요청 대조군, 설정된 JSON scalar oracle, 두 번 반복 판정은 **이 사례에서 착안한 Wakeio 설계**이지 해당 Nuclei template의 기능이나 검증 성능을 그대로 가져온 것이 아니다. 외부 template 또는 payload 파일을 복사·동봉하지 않는다.

기존 Wakeio [Nuclei 어댑터](../../src/nuclei.ts)는 MIT 엔진 `3.11.1`을 이미 지원하므로 같은 엔진의 중복 래퍼를 만들지 않는다. 새 검사는 Wakeio Node 네트워크 경로로 직접 수행한다. 현재 [egress gate](../../src/dast-egress.ts)의 HTTPS `CONNECT`는 TLS 안의 HTTP 요청 수를 관측하지 못하므로, [Nuclei 어댑터](../../src/nuclei.ts)는 HTTPS를 시작 전에 거절한다. Node의 [URL 네트워크 코드](../../src/url-network.ts)는 실제 GET마다 budget을 세고 DNS peer/TLS를 검증하므로 이 작은 검사에는 HTTP·HTTPS 모두 적용할 수 있다. Nuclei의 HTTPS 거절 규칙을 삭제하거나 우회할 근거는 없다.

## 실제 오픈소스 확인과 사용 판단

| 프로젝트 | 공식 구현 근거 | 라이선스와 적용 |
| --- | --- | --- |
| Nuclei engine | 선택된 template의 HTTP 요청과 matcher를 실행하는 [공식 엔진](https://github.com/projectdiscovery/nuclei/blob/dev/README.md) | [엔진 LICENSE](https://github.com/projectdiscovery/nuclei/blob/dev/LICENSE.md)는 MIT. Wakeio에 선택형 어댑터가 이미 있음. |
| Nuclei templates | [CVE-2021-36748의 두 GET 조건과 AND matcher](https://github.com/projectdiscovery/nuclei-templates/blob/3d818a6e398abd5867c50b35218ba25224d12b99/http/cves/2021/CVE-2021-36748.yaml); 프로젝트의 [template 기여 지침](https://github.com/projectdiscovery/nuclei-templates/blob/main/CONTRIBUTING.md)은 약한 matcher와 오탐을 경고 | 엔진과 **별도** [template LICENSE](https://github.com/projectdiscovery/nuclei-templates/blob/3d818a6e398abd5867c50b35218ba25224d12b99/LICENSE.md)는 MIT. 해당 CVE template은 일반 입력 검사의 oracle이 아니므로 실행·동봉하지 않음. |
| Dalfox v3, `e3573eb91ffdf268790f5e52eee08dd40bf447bf` | [쿼리 파라미터 발견](https://github.com/hahwul/dalfox/blob/e3573eb91ffdf268790f5e52eee08dd40bf447bf/src/parameter_analysis/discovery/query.rs), [반사 확인](https://github.com/hahwul/dalfox/blob/e3573eb91ffdf268790f5e52eee08dd40bf447bf/src/scanning/check_reflection.rs), [DOM 구조 검증](https://github.com/hahwul/dalfox/blob/e3573eb91ffdf268790f5e52eee08dd40bf447bf/src/scanning/check_dom_verification.rs)을 가진 실제 XSS DAST | [LICENSE.txt](https://github.com/hahwul/dalfox/blob/e3573eb91ffdf268790f5e52eee08dd40bf447bf/LICENSE.txt)는 MIT. SQL 검사 구현을 제공하지 않으므로 이번 구현의 알고리즘 출처로 표시하지 않음. 향후 XSS 범위 후보. |
| ffuf | 입력 fuzzing·응답 matcher/filter의 [공식 구현](https://github.com/ffuf/ffuf) | [LICENSE](https://github.com/ffuf/ffuf/blob/master/LICENSE)는 MIT. 탐색 도구이며 이 SQL 재현 검사에는 채택하지 않음. |
| ZAP | 활성 보안 스캐너의 [공식 프로젝트](https://github.com/zaproxy/zaproxy) | [공식 legal notice](https://github.com/zaproxy/zaproxy/blob/main/LEGALNOTICE.md)는 Apache-2.0. 이번 'MIT 구현 참고' 후보 밖이라는 분류이며 라이선스 호환성에 대한 법률 판정은 아님. |

저장소 최상위 라이선스와 외부 asset·template·의존 패키지 라이선스는 별개다. 이번 구현은 외부 엔진 코드·payload·template의 복사를 요구하지 않는다. Wakeio 자체 패키지는 [`Apache-2.0`](../../package.json)이다. 향후 MIT 원문 코드를 실질적으로 복사하면 해당 고지 보존과 외부 자료별 라이선스 검토가 필요하다. [Nuclei templates license](https://github.com/projectdiscovery/nuclei-templates/blob/3d818a6e398abd5867c50b35218ba25224d12b99/LICENSE.md), [Dalfox license](https://github.com/hahwul/dalfox/blob/e3573eb91ffdf268790f5e52eee08dd40bf447bf/LICENSE.txt)

## Wakeio 구현 계약

1. 사용자가 한 origin과 **기존 고유 쿼리 파라미터**가 있는 단일 GET URL을 명시한다. 매개변수 이름 중복, 없는 이름, URL userinfo, 경로·origin 이탈은 시작 전에 거절한다. 다른 파라미터·경로는 고정한다. 임의 URL 크롤링, 파라미터 발굴, POST, 헤더·cookie 삽입, OAST, 시간 지연 payload, database 함수 호출, 데이터 추출은 범위 밖이다. 기존 `--active-consent` 조건을 보존한다. [Wakeio CLI](../../src/cli.ts), [URL policy](../../src/url-network.ts)
2. 초기 구현은 **numeric** profile 하나만 지원한다. 원본 값이 제한된 십진 숫자일 때만 숫자 비교식 `AND 1=1` / `AND 1=2`를 붙인다. 이는 탐지 완전성을 보장하지 않는 제한된 probe다. 다른 SQL dialect·문맥에서는 부정 결과나 5xx가 날 수 있으므로 오류/미검증을 유지한다. Payload가 변경하는 query value는 보고서에 남기지 않는다. Quote profile은 이번 범위에 구현하지 않는다.
3. JSON scalar oracle의 위치는 신뢰된 설정으로 지정한다. 응답에서 해당 위치의 원시 scalar만 읽고, 문자열·배열·객체·누락·형식 오류는 구분한다. 검사 순서는 **B/T/F/B를 두 번**으로 고정해 총 8 GET이다. `B`는 원본, `T`는 true 조건, `F`는 false 조건이다. 두 라운드의 모든 B와 T가 동일한 정상 scalar이고, 두 F가 B/T와 다른 **동일한 정상 scalar**여야 후보를 낸다. 두 라운드의 상태·콘텐츠형·JSON 형식·oracle 추출도 모두 완료되어야 한다. 원본 baseline drift, 5xx, malformed JSON, oracle 누락, timeout, redirect, budget 소진은 clean 판정이 아니라 `partial`/`inconclusive`다. 구체 판정은 scan fixture와 정상 대조군으로 고정한다.
4. [Node URL 네트워크 코드](../../src/url-network.ts)의 `normalizeUrl`, `resolveAddresses`, 고정된 DNS peer/TLS 검증, `RequestBudget`, body/deadline 제한과 `rejectRedirects`를 재사용한다. 매 전송 시도에 budget이 차감돼야 하며 취소·오류 후 8요청 완료처럼 보고하지 않는다. HTTPS도 Node가 직접 각 GET을 보낼 때만 request-count 주장을 한다. 보고서는 승인된 origin/path와 파라미터 이름, profile, phase별 상태·oracle의 값 없는 동등성 분류·요청 수·중단 이유를 기록한다. 원래 query 값, probe 값, raw response, credential, 임의 response body는 저장하지 않는다.
5. 모든 대조군이 충족한 결과는 `Finding.kind = candidate`로 표시한다. 반복 가능한 응답 차이는 SQL query가 실제로 실행됐다는 독립 증명이 아니므로 '확정 취약점'이나 독립 exploit verification으로 승격하지 않는다. 안정된 finding identity는 rule/origin/path/파라미터/profile에서 만들고 원본 값이나 임의 난수는 빼야 한다. 기존 `Finding.controlVerification`은 API 권한 대조 전용이라 그대로 재사용하지 않는다. [Finding 계약](../../src/contracts.ts)

**owned fixture 수용 사례:** 실제 SQLite 문자열 결합 query의 numeric profile에서 후보가 두 번 재현된다. 매개변수 바인딩한 안전한 같은 endpoint와 query 입력을 무시하는 endpoint에서는 8요청을 완료하고 후보가 없다. 원본 값이 정상 oracle과 다르거나 출력을 단순 echo하는 endpoint, F 결과가 라운드마다 바뀌는 endpoint, baseline drift, 5xx, malformed JSON, redirect, 다른 origin, 예산·시간 초과는 후보를 만들지 않으며 완료/불완전 이유를 분리한다. Synthetic/loopback 확인 결과를 임의 서비스에서의 탐지율로 확대하지 않는다.

## 사용자 Codex agent 경계

사용자 소유 Codex 연결은 DAST 이후 triage·수정 제안을 위한 선택 경로다. [공식 비대화형 문서](https://learn.chatgpt.com/docs/non-interactive-mode)는 `codex exec`, `--json` JSONL 이벤트, `--output-schema`, 기본 read-only sandbox, `--sandbox workspace-write`, `--ephemeral`과 CI 인증 방법을 설명한다. Agent에게 oracle, target allowlist, 검증 status를 정하는 권한을 주지 않는다. 분석과 수정 권한·격리 복사본·검증 실행은 별도 정책으로 다룬다. 모델의 자연어 결론이나 exit 0은 DAST 재검증 완료를 뜻하지 않는다. 선행 [agent 조사](security-remediation-agent-landscape-2026-10-03.md)도 이 역할 분리를 제안했으며 이번 조사에서 인증 정보 조회, 모델 호출, 패치 또는 PR 생성은 하지 않았다.

## 상태

- 확인됨: MIT 공식 source/license, Nuclei의 실제 SQL true/false template, 현재 Wakeio URL/DAST 경계.
- 이 checkout에 구현됨: [numeric-only 원생 검사](../../src/dast.ts), [8단계 실행 장부와 검증기](../../src/dast-execution.ts), [실제 SQLite owned fixture](../../examples/native-dast-sqlite.mjs), [반복 가능한 CLI 예제](../../examples/native-dast-demo.mjs). 문자열 결합 query와 매개변수 바인딩 query의 positive/negative control, 예산·중단·HTTPS 로컬 CA 검증은 [native 테스트](../../tests/dast-native.test.ts)에 한정된다. 별도 Action/보고서 통합 테스트 역시 이 checkout의 합성·loopback 근거이며 실제 운영 서비스의 탐지율 근거가 아니다.
