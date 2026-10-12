# Native DAST·replay·agent 검증 기록 (2026-10-13)

이 기록은 **0.5.0 소스 프리뷰**의 검증 범위다. npm에 공개된 마지막 버전은 0.4.0이며, 아래 결과는 실제 서비스의 취약점 탐지율이나 수정 완료를 뜻하지 않는다.

| 완료 기준 | 확인한 결과와 한계 |
| --- | --- |
| Numeric SQL DAST | 소유한 SQLite 엔드포인트에서 동일 정책의 baseline/true/false/baseline을 두 번 실행했다. 문자열 결합 쿼리는 후보(exit 1, 8 GET), 매개변수 바인딩은 `not_observed`(exit 0, 8 GET)였다. 다른 SQL 구문·엔드포인트의 안전성은 미검증이다. |
| 동일 정책 replay | 원본 후보·정책·8단계 장부를 확인한 뒤 같은 엔드포인트에서 `reproduced`(1/8 GET), 바인딩 전환 후 `not_reproduced`(0/8), 서버 오류에서 `inconclusive`(2/1)를 확인했다. 잘못된 증거·동의·권한은 요청 전 `refused`(2)로 처리한다. 비재현은 실제 서비스의 수정 증명이 아니다. |
| Codex 조언 | 명시적 `cli-login`과 `api-key` 모드를 지원한다. 로그인된 Codex CLI의 소유 SQLite 보고서 조언은 실제 호출로 성공했고 `verified: false`였다. API 키 모드는 fake CLI 계약 테스트만 통과했으며 실제 키 호출은 미검증이다. 조언은 스캔 결과나 게이트를 바꾸지 않는다. |
| 보고서·마스킹 | 스캔/재검사 보고서의 정책·실행 장부와 SHA-256 결속, 32 KiB 이하의 마스킹된 agent-report 투영 및 감사 경계를 검사했다. 원문 응답·쿼리 값·자격증명·모델 출력을 공개 보고서에 넣지 않는다. 자동 마스킹만으로 모든 사적 문장을 식별한다고 보장하지 않는다. |
| 패키지 소비자 | Node 22.22.1에서 로컬 패키지 설치본의 런타임 파일 118개가 소스와 일치했고 replay SDK export/CLI 도움말 및 위 네 단계의 SQLite 데모가 동작했다. npm 발행 검증은 아니다. |
| 공개 OSS 소스 벤치마크 | 고정된 Juice Shop·NodeGoat 전체 체크아웃에서 사전 선언한 흐름 7개 중 5개가 일치했다. 나머지 2개는 알려진 미지원 NoSQL이고, 후보 17개·관찰 1개는 미심사다. Juice Shop 분석이 부분 완료라 벤치마크 종료 코드는 2이며 precision·supported recall은 산출하지 않는다. 대상 앱은 실행하지 않았다. |
| 필수 엔진 게이트 | Node 22.22.1에서 preflight·build·test가 종료 코드 0, 테스트 756/756 통과·건너뜀 0이었다. 각 단계의 정리가 확인됐고 검증 범위의 소스 SHA-256은 실행 전후 동일했다. 이 게이트의 성공은 위 OSS 벤치마크의 부분 완료를 성공으로 바꾸지 않는다. |

소유한 로컬 SQLite 예제는 Node.js 22.13+와 이 체크아웃의 빌드가 필요하다. 각 `--out`에는 **새 절대 경로**를 지정한다.

```sh
npm run build
node examples/native-dast-demo.mjs --out /absolute/path/to/new-native-demo
node examples/native-dast-replay-demo.mjs --out /absolute/path/to/new-replay-demo
```

직접 관리하는 대상의 정책 작성·동의·실행 명령은 [native DAST 가이드](native-dast.md), 별도 조언 요청은 [Codex 조언 가이드](agent-advice.md), 소스 벤치마크 재현 명령과 판정 규칙은 [OSS 벤치마크 가이드](oss-benchmark.md)를 따른다. 활성 스캔과 replay에는 매번 명시적 동의가 필요하다.
