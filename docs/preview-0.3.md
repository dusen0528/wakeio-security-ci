# 0.3 개발 프리뷰 사용법

무료 OSS의 세 입력은 소스, 공개 URL, 사용자가 작성한 API 권한 정책이다. 조합 실행과 JSON·SARIF·Markdown 출력을 지원한다. Node.js 22 이상이 필요하다. 현재 배포물은 로컬 tarball이며 공개 npm·Marketplace 배포를 완료한 상태는 아니다. 기본 설치는 [배포 문서](distribution.md)를 따른다.

## Python 및 프레임워크 소스

```sh
npm ci --ignore-scripts
npm run build
python3 -m venv .venv
.venv/bin/python -m pip install 'bandit==1.9.4'
node build/src/cli.js scan --source /path/to/app \
  --tools bandit --bandit "$PWD/.venv/bin/bandit" --out results/python
```

Bandit은 별도로 설치하는 선택 도구다. `--tools`는 기본 목록을 대체한다. 기존 도구를 함께 쓰려면 `--tools gitleaks,osv,trivy,bandit`과 각 실행 파일 경로를 지정한다. 기본 목록은 여전히 `gitleaks,osv,trivy`다. `--tools none`은 내장 JS/TS·프레임워크 규칙만 실행하며 Python AST 검사를 대신하지 않는다.

Bandit은 수집 제한을 통과한 `.py` 복사본을 정적으로 분석한다. 대상 코드를 import·실행하지 않는다. 저장소의 `.bandit` 설정과 `# nosec`로 검사를 숨기지 않으며 누락·파싱·실행 실패는 부분 검사 또는 오류로 표시한다. `.venv`, `venv`, Python 캐시, `.intent-review`는 수집에서 제외한다.

내장 규칙은 `supabase/migrations/**/*.sql`의 명시적 RLS 해제·PUBLIC true 정책, `use client` 모듈의 서버 비밀키 형태, JS/TS 선언의 의심스러운 `NEXT_PUBLIC_` 이름을 살펴본다. 정상 공개용 Supabase 키와 역할 이름만으로 고위험 노출을 판정하지 않는다. PUBLIC 읽기는 의도한 기능일 수 있어 검토 후보로 표시한다. 전체 SQL 문법, 파일 간 migration 최종 상태, 실제 DB 권한, `.env`의 Next 빌드 의미, import 관계를 통한 client 경계 확장은 분석하지 않는다.

## API 권한 점검을 로컬에서 재현

첫 터미널에서 합성 서버를 시작한다.

```sh
node examples/api-authorization-demo.mjs --vulnerable
```

두 번째 터미널에서 실행한다.

```sh
export WAKEIO_OWNER_AUTH='Bearer demo-owner'
export WAKEIO_OTHER_AUTH='Bearer demo-other'
node build/src/cli.js scan \
  --api-policy examples/api-authorization-policy.json --allow-private \
  --out results/before --fail-on high
```

취약 예제에서는 다른 계정이 소유자의 문서를 읽어 high 결과와 exit 1을 기대한다. 첫 터미널의 서버를 종료하고 `--vulnerable` 없이 다시 시작한 뒤 같은 명령의 출력 경로를 `results/after`로 바꾼다. 소유자는 계속 읽을 수 있고 다른 계정·익명은 거절되는지 검사한다.

실제 정책은 [JSON 예제](../examples/api-authorization-policy.json)를 복사해서 URL, 경로, 환경변수 이름, 소유권을 확인할 JSON 필드를 지정한다. `equals`는 보고서에 쓰지 않지만 정책 파일에는 저장되므로 비밀값 대신 합성 리소스 ID를 사용한다. 토큰은 정책에 넣지 않고 환경변수로 전달한다.

각 사례에서 소유자의 성공 상태와 JSON 표식을 먼저 확인하고 다른 계정·익명의 거부 결과를 검사한 뒤 소유자 요청을 다시 확인한다. 403이어도 보호된 표식이 본문에 있으면 노출 후보다. 소유자 확인 실패, 429·5xx, 파싱·네트워크 오류, 판단 불가능한 응답은 정상 통과로 처리하지 않는다.

GET만 사용하며 서버에서 GET으로 상태를 바꾸는 경로는 정책에서 제외해야 한다. 자동 로그인·토큰 발급, 쓰기 요청, 결제·관리자 변경, 퍼징, 전체 OpenAPI 자동 탐색은 지원하지 않는다. 최대 20개 사례·64개 요청·120초이며 리디렉션을 따르지 않는다. 인증은 HTTPS가 원칙이고 `--allow-private`과 loopback HTTP 조합만 로컬 예제로 허용한다. 메타데이터 주소 제한은 유지한다.

## 두 번의 검사 비교

```sh
node build/src/cli.js compare \
  --before results/before/report.json --after results/after/report.json \
  --out results/comparison --fail-on high
```

- `new`, `changed`, `unchanged`: 새 발견·심각도/신뢰도 변화·유지.
- `not_observed`: 비교 가능한 두 검사에서 이전 발견이 이번에는 관찰되지 않음. 수정 완료나 안전 증명이 아님.
- `unverified`: 검사 누락·실패 또는 범위/규칙 버전 차이로 사라진 결과를 해석할 수 없음.

JSON에도 결과 식별자를 기록한다. 위치가 이동하면 새 결과로 나타날 수 있다. 같은 입력 경로·URL·정책·실행 옵션·도구 선택, 규칙/CLI 버전, 검사 집합과 완료 상태가 필요하다. 범위 정보가 없는 이전 보고서, 다른 checkout 절대 경로는 보수적으로 비교 불가다. 외부 scanner 버전·advisory DB까지 고정하거나 임의로 수정된 보고서의 진위를 검증하지 않는다.

`compare`는 비교 불가이면 exit 2, 새 결과 또는 변경 결과가 문턱 이상이면 1, 그 외에는 0이다. 기존 `scan`의 발견·오류 판정을 숨기는 baseline suppress 기능은 추가하지 않았다.

## CI에 선택 기능 연결

Action을 vendor한 후 Python 준비 단계에서 Bandit을 설치하고 경로를 전달한다.

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: '3.12'
- shell: bash
  run: |
    python -m venv "$RUNNER_TEMP/wakeio-bandit"
    "$RUNNER_TEMP/wakeio-bandit/bin/python" -m pip install 'bandit==1.9.4'
    echo "BANDIT_BIN=$RUNNER_TEMP/wakeio-bandit/bin/bandit" >> "$GITHUB_ENV"
- uses: ./vendor/wakeio-security-ci
  with:
    source: .
    tools: bandit
    bandit-path: ${{ env.BANDIT_BIN }}
    out: .wakeio-security-ci
```

API는 `api-policy: .security/api-policy.json`을 추가하고 정책의 환경변수 이름을 Action의 `env`에 연결한다. secret이 없는 fork PR은 인증 없는 검사와 별도 job으로 구성한다. 토큰이 있는 job에서 신뢰하지 않는 PR의 정책·Action 코드를 실행하지 않는다. 로컬 서버에만 `allow-private: 'true'`를 명시한다.

Wakeio 서버·LLM·GPT 토큰 호출 기능은 없다. OSV 패키지 식별자 질의, Trivy 규칙 다운로드, 명시적 URL/API 요청, 설치 단계의 다운로드는 별도 네트워크 동작이다. [체크리스트](checklist.md), [검증 기록](verification-0.3.md)을 함께 확인한다.
