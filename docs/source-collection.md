# 저장소 수집 한도를 명시해서 검사하기

이 기능은 **현재 GitHub 소스·Action 프리뷰** 기준이다. 새 npm 배포를 뜻하지 않으며 공개 npm 0.4.0의 기능으로 간주하지 않는다. 아래는 검토한 Wakeio checkout의 빌드된 CLI를 사용한다. 별도 검증한 로컬 `.tgz`를 설치한 CLI에서도 같은 옵션을 쓸 수 있다.

## Clone에서 보고서까지

대상 clone은 파일 데이터로 읽는다. `--tools none`은 내장 검사만 선택하며 대상 앱의 설치·스크립트·서버를 실행하지 않는다. 보고서는 clone 밖 새 디렉터리에 둔다.

```sh
node /path/to/wakeio-security-ci/build/src/cli.js doctor \
  --source /path/to/cloned-app --tools none --json \
  --source-max-files 10000 --source-max-bytes 134217728 \
  --analysis-profile extended

node /path/to/wakeio-security-ci/build/src/cli.js scan \
  --source /path/to/cloned-app --tools none \
  --source-max-files 10000 --source-max-bytes 134217728 \
  --analysis-profile extended --out /path/to/new-reports
```

Doctor는 선택한 `collectionBudget`과 다음 scan 명령을 보여 준다. `inventoryBasis: metadata_estimate_not_collector_coverage`는 메타데이터 추정치라는 뜻이다. 파일 총계에는 실제 collector allowlist 밖 파일도 포함될 수 있으며 수집·분석 완료를 미리 보장하지 않는다. 명시한 수집·AST 설정은 `nextCommand`에 유지된다. `init`에도 같은 세 옵션을 전달하면 새 CI workflow의 CLI 명령에 기록된다.

| 선택 | 생략 시 | 허용 최대 |
| --- | ---: | ---: |
| `--source-max-files` | 1,000개 | 10,000개 |
| `--source-max-bytes` | 26,214,400 bytes (25 MiB) | 134,217,728 bytes (128 MiB) |

숫자는 부호·공백·소수·지수·선행 0 없는 양의 정수로 지정한다. 중복 옵션이나 범위를 넘은 값은 검사 전에 거부한다. source가 있는 복합 scan에도 사용할 수 있지만 URL/API만 검사할 때는 사용할 수 없다. SDK는 기존 `runSource({maxFiles,maxBytes})`를 유지한다.

개별 파일의 2 MiB 한도, 민감 파일 취급과 생성물 제외 규칙, symlink 등 파일 검증은 그대로다. 파일 개수 설정에서 계산되는 traversal 한도와 고정된 디렉터리 깊이 64 한도도 별도로 적용한다. `--analysis-profile extended`는 AST 작업량 선택이며 수집 한도를 대신하지 않는다. 수집 한도를 늘려도 큰 파일·읽기 오류·파싱 실패·AST 작업량 초과는 여전히 partial이 될 수 있다. 자동 한도 확대나 재실행은 하지 않는다.

## Action에 같은 설정 전달하기

검토한 현재 프리뷰 Action checkout을 `.wakeio-action`에 준비한 경우의 실행 step이다. 대상 저장소와 Action checkout을 구분하고 원격 Action을 참조할 때는 검증한 commit을 고정한다.

```yaml
- name: Scan cloned source
  uses: ./.wakeio-action
  with:
    source: ./cloned-app
    tools: none
    analysis-profile: extended
    source-max-files: '10000'
    source-max-bytes: '134217728'
    out: ./wakeio-reports
```

두 입력을 생략하면 기존 수집 한도를 유지한다. 잘못된 값은 Node setup·도구 설치 전에 거부한다. 정상 실행에서는 argv로 전달하며 대상 파일을 실행하지 않는다.

## 보고서와 다음 판단

`report.md`의 첫 요약에서 scan gate와 미완료 원인을 읽고, `report.json`의 `source.inventory`를 확인한다. `collectionBudget`에는 `collection-v1` revision과 실제 `maxFiles`, `maxBytes`, `maxFileBytes`, `maxEntries`가 있다. `collectionEvidence`에는 전체 issue 수와 code별 집계가 있다. `file_limit`는 선택 파일 수뿐 아니라 traversal/depth 한도도 포함할 수 있으므로 파일 수만 보고 원인을 단정하지 않는다. 알려진 수집 원인과 AST 분석 gap은 별도로 읽는다.

네 보고서 `report.json`, `report.md`, `report.sarif`, `agent-report.json`을 함께 보관한다. 에이전트는 적용한 한도, 수집 원인, finding의 source→sink와 검증 상태를 함께 읽어야 한다. 한도가 다른 결과는 같은 범위의 수정 검증으로 취급하지 않는다. 새 `collection-v1` identity가 source scope fingerprint에 포함되므로 기본 수집 파일·판정·exit가 같아도 이전 fingerprint와 같다고 보장하지 않는다. legacy 보고서는 읽을 수 있지만 수집 identity가 없으면 비교 가능한 수정 근거를 새로 확립하지 않는다.

Exit `0`은 선언한 검사가 완료되고 severity 기준을 넘는 발견이 없는 경우, `1`은 기준 이상의 발견, `2`는 오류·미완료다. `--fail-on none`도 미완료를 통과시키지 않는다. 한도를 늘려 후보를 새로 발견해도 candidate이며 취약점 확인이나 전체 안전 인증이 아니다.

[AST 분석 한도](source-flow.md#explicit-ast-workload-selection), [에이전트 보고서 계약](agent-report.md), [고정 OSS benchmark](oss-benchmark.md)를 함께 참고한다. 기존 benchmark의 수집 설정과 역사적 영수증은 이 옵션 도입으로 변경하지 않는다.
