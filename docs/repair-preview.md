# 선택적 보안 패치 — 실험적 CLI

`scan`의 무료·기본 무전송·대상 코드 미실행 계약은 유지한다. 별도 `repair`는
명시적으로 선택한 공급자 또는 로컬 수정안에서 **검토할 patch와 검증 기록만**
만든다. 원본 적용, commit, push, PR, merge, 배포는 하지 않는다.

현재 지원은 준비된 로컬 Docker 이미지와 신뢰된 Python 검증기를 사용하는
선언된 SQL injection 회귀·정상 동작 control이다. 예제는 SQLite 실제 쿼리를
검사한다. 일반적인 Node/TS 앱, IDOR, SSRF, 전체 회귀 테스트와 production
보안 패치 완료를 보장하는 기능은 아직 아니다.

## 실행 계약

1. TOML의 버전·키·타입·예산·명시 파일 목록을 엄격히 검사한다. 중복 TOML 키도
   Python 표준 `tomllib`가 거부한다. Python 3.11+는 repair에만 필요하다.
2. 최대 8개, 개별 128 KiB·합계 256 KiB의 명시 파일을 고정한다. 링크와 경로
   탈출은 거부한다. 검증기는 대상 디렉터리 밖에 두고 SHA-256을 고정한다.
3. 이미 존재하는 Docker **image ID**를 확인한다. 이미지 pull·build·의존성 설치를
   자동으로 수행하지 않는다. 실제 Python/SQLite 버전은 이미지에서 직접 조회한다.
4. 비루트·읽기 전용·무네트워크·capability 제거·자원 제한 컨테이너에서 원래
   코드를 검증한다. 설정·설치·import 오류·timeout은 취약점 재현이 아니다.
5. 고정된 보안 assertion 실패와 정상 control 통과를 확인한 뒤 수정안을 받는다.
   공급자의 성공 문장·exit 0은 검증 완료로 해석하지 않는다.
6. 허용 파일과 원래 내용 hash가 일치하는 replacement만 사본에 적용한다.
   검증기·정책·원본 작업 트리는 수정하지 않는다.
7. **같은 검증기·이미지·입력 fingerprint**로 수정 후 검사한다. 생략·타입 오류·
   fingerprint 불일치·정상 동작 실패·환경 오류는 검증 완료가 아니다.
8. 소스 불변 여부를 재확인하고 private `changes.patch`, `repair.json`을 전달한다.

검증 성공은 `declared-sql-regression-and-normal-control` 범위에만 해당한다.
필수 검사 전체가 원래부터 없거나 생략됐다면 “앱의 모든 회귀 검증 완료”라고
표현하지 않는다. 기존 `compare`의 `not_observed`도 `fixed`로 바꾸지 않는다.

## 예제 준비와 실행

예제 대상 파일은 `examples/repair-query.py`다. 이것을 별도 fixture 디렉터리의
`query.py`로 복사한다. 검증기는 대상 밖의 `examples/repair-sql-verifier.py`를
유지한다. 아래 두 경로와 output은 실제 절대 경로로 바꾼다.

`examples/repair-policy.toml`의 image placeholder는 의도적으로 실행에 실패한다.
리뷰한 로컬 이미지의 ID를 확인해, **사용자가 검토한 정책 사본**에 설정해야 한다.
이미지는 Python과 SQLite 표준 모듈을 포함해야 한다. 검증기 hash는 파일을
변경했다면 다시 리뷰·확인하고 정책 사본에 반영한다.

```sh
docker image inspect --format '{{.Id}}' YOUR_PREPARED_IMAGE

# 에이전트 없이, 예제 수정안을 독립적으로 검증한다.
node build/src/cli.js repair \
  --source /absolute/fixture \
  --policy /absolute/reviewed-policy.toml \
  --out /absolute/private-reports/new-run \
  --proposal examples/repair-proposal.json

# 선택한 공급자에만 명시된 코드 문맥을 전달해 수정안을 받는다.
node build/src/cli.js repair \
  --source /absolute/fixture \
  --policy /absolute/reviewed-policy.toml \
  --out /absolute/private-reports/new-agent-run \
  --agent codex --allow-source-upload
```

output의 부모 디렉터리는 준비돼 있어야 하며 output은 새 디렉터리여야 한다.
output이 원본 안에 있거나 이미 존재하면 거부한다. 원래 검증 파일·정책 파일을
수정안으로 바꾸는 것은 허용되지 않는다. 새로운 실행은 별도 output으로 남긴다.

Docker Desktop처럼 기본 `/var/run/docker.sock` 대신 다른 소켓을 쓰는 환경은
`--docker-host unix:///absolute/path/docker.sock`을 명시한다. 현재 옵션은 로컬
Unix socket만 허용하고 TCP/SSH daemon, 사용자 `DOCKER_HOST`·context·HOME 설정은
자동 전달하지 않는다. 기존 macOS 소켓을 쓰기 위해 비밀 환경 전체를 넘기지 않는다.

## 선택적 공급자 연결

- Codex는 `CODEX_API_KEY`, Claude는 `ANTHROPIC_API_KEY`를 요구한다. 이 값은
  TOML·보고서에 기록하지 않고 선택한 공급자 프로세스에만 전달한다.
- 앱 로그인 상태나 기존 대화를 재사용하는 기능은 아니다. 사용자 계정의 auth
  파일, 기존 HOME 설정, 저장소 hook·MCP·skill을 자동 재사용하지 않는다.
- `--agent-path`로 리뷰한 CLI를 명시할 수 있다. CLI의 도움말·버전·실행 파일
  hash를 확인하며 미지원 옵션·권한 정책은 실패 처리한다. 자동 공급자 대체는 없다.
- 최초 adapter는 data-only다. 빈 private 디렉터리에서 도구를 끄고 제한된 파일
  문맥으로 replacement를 받는다. 자율 shell 실행·대상 저장소 탐색·재귀 서브에이전트는
  지원하지 않는다. Codex tool 이벤트도 수락하지 않는다.
- `--allow-source-upload` 없이는 모델 실행을 시작하지 않는다. 코드가 외부 모델에
  전송될 수 있으며 모델 비용·데이터 정책은 사용자 책임이다. Claude에는 CLI의
  `$1` budget 옵션을 전달하지만 실제 청구 상한을 보증하지 않는다. Codex에는
  확정 금액 제한을 구현하지 않았다. 실제 모델·비용을 회수하지 못하면 `unknown`이다.
- `timeout_ms`는 repair 실행 단계의 공유 예산이다. 입력 파싱·사전 확인·정리에는
  별도 제한이 있고 전체 wall-clock은 그만큼 추가될 수 있다. 프로세스 출력도 제한한다.

## 검증기와 CI의 신뢰 경계

검증기는 모델이 만든 patch와 함께 믿어서는 안 된다. reviewed base revision에서
정책·검증기·runtime을 가져오고, untrusted PR이 이를 바꾼 상태에서 credential job을
실행하지 않는다. SHA-256은 동결한 파일이 같음을 증명할 뿐 검증 내용의 정당성을
자동으로 보장하지 않는다. 임의 검증기가 통과를 출력하면 그것은 잘못된 정책이다.

SQL 예제는 판정 process와 대상 process를 분리한다. 신뢰된 판정 process가
읽기만 허용된 SQLite DB에서 실제 SQL 실행과 반환 행을 관찰한다. 대상의 stdout은
별도의 제한된 query protocol이며, 검증 결과 JSON을 위조해 출력하면 오류가 된다.
대상이 이미 반환받은 다른 사용자 행을 감추는 것만으로도 통과하지 못한다.

`--docker`와 `--agent-path`는 **신뢰할 실행 파일**이다. 공격자가 바꾼 가짜 CLI나
악성 Docker daemon은 hash만으로 안전해지지 않는다. 실제 격리 환경의 운영 신뢰도는
별도로 필요하다. Docker socket·host secret을 대상 컨테이너에 mount하지 않는다.

patch에는 원문 코드가 포함된다. 디렉터리 `0700`, 파일 `0600`으로 저장하지만,
공개 artifact나 SARIF로 자동 업로드하지 말고 접근·보관 기간을 별도로 관리한다.
보고서도 private artifact이며 stdout에는 고정된 상태와 사유만 표시한다.

## 결과와 검증 수준

| 종료 | 의미 |
| --- | --- |
| 0 | 선언된 보안 회귀와 정상 control 통과; 전체 앱·production 수정 증거 아님 |
| 1 | patch는 만들었지만 같은 보안 assertion이 계속 실패함 |
| 2 | 미재현, 잘못된 정책/수정안, 무격리, 미인증, 미지원 정책, 오류·생략·timeout·불일치 등 |

`repair.json`은 snapshot·정책·검증기·image·patch hash, 수정 파일, 실제 runtime,
수정 전후 판정, 공급자·버전·실행 파일 hash, 미확인 모델·비용과 실패 사유를 남긴다.
patch 생성, 검증 완료, 전달 성공을 같은 상태로 합치지 않는다. 실패 뒤 존재하는
patch를 `repair.json` 확인 없이 적용해서는 안 된다.

현재 검증 기록: 기존 무료 scan 회귀와 실제 Schemathesis 엔진 검사, repair CLI의
실제 SQLite 재현/수정/control 검사, 공급자 **모의 프로토콜** 검사를 수행했다.
Docker CLI 모의 실행기는 계약 회귀용이며, 별도로 2026-10-04에 실제 Docker에서
자체 SQL fixture의 5가지 사례를 검사했다. 정상 패치 통과, 효과 없는 패치 실패,
위조 결과 거부, 실제 격리 속성, timeout 후 컨테이너 정리를 확인했다.
[환경·증거·재실행 명령](verification-repair-docker.md)을 참고한다.
Codex 0.160.0·Claude Code 2.1.195는 버전·도움말만 확인했으며 라이브
모델 실행·인증·청구·실제 공급자 정책 적용은 아직 확인하지 않았다.

실제 Docker 검증 명령은 별도 `npm run test:repair:docker`이며, 준비된 이미지 ID와
새 private output 경로가 필수다. 이미지 pull이나 모델 호출은 하지 않으며 검사
실패를 생략으로 바꾸지 않는다. 이 Docker 단계가 hosted CI에서 실행됐다는 증거는
아직 없다. CI self-test는
`npm run test:schemathesis`를 사용하여 필요한 Python/Schemathesis가 없으면 실패한다.
필수 명령은 핵심 실제 엔진 테스트 두 개가 출력에 존재하고 전체 생략 수가 0인지도
확인한다. 실행 가능한 엔진만 확인한 뒤 생략된 테스트를 성공으로 넘기지 않는다.

2026-10-04 로컬 결과: `npm run test:schemathesis` 174개 통과, 실패·생략 0개.
필수 Python 경로를 존재하지 않는 경로로 지정한 사전 검사도 exit 2로 실패했다.
