# 실제 Docker 격리 검증 — 2026-10-04

사용자가 허용한 공개 Python 이미지와 저장소의 자체 SQL fixture만 실행했다.
모델 호출·소스 업로드·원본 패치 적용·commit·push는 하지 않았다. 이 기록은
범용 앱이나 production 취약점 수정 완료, 라이브 공급자 연동의 증거가 아니다.

## 환경과 고정 값

- macOS ARM64, Docker Engine 27.3.1.
- 운영자가 공식 `python:3.12-slim` 이미지를 한 번 받았다. repair 자체는 pull하지 않는다.
- 고정한 로컬 image ID: `sha256:04e0b4721883a7b878e91662548cd04ddbc2f256cfa86f43920b92557198c1c3`.
- 받은 이미지의 RepoDigest: `python@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016`.
- 이미지에서 직접 확인한 설치 버전: Python 3.12.15, SQLite 3.46.1.
- 고정한 검증기 SHA-256: `09877493143999a626dedd1868853ae3ce9c0f58156696776bde28c951a1fc83`.
- 수정 전후 합성 입력 fingerprint: `64f45f0c3306150119ba1c341eae75327db16dea794414111a8f9fb1bcee817a`.

원래 코드는 문자열로 SQL을 조합한다. 정상 `alice` 조회는 통과하지만
`' OR 1=1 --` 입력은 다른 사용자 행까지 반환한다. 같은 검증기·runtime·입력으로
parameter binding 패치를 검사해 공격 입력의 반환 행은 비우고 정상 조회는 유지했다.
독립 판정 process가 실제 SQLite 실행 결과와 대상에게 반환된 행을 관찰한다.

## 공개 repair CLI 결과

| 사례 | 종료 코드 | 확인한 결과 |
| --- | --- | --- |
| parameter binding | 0 | 수정 전 보안 실패·정상 통과, 수정 후 둘 다 통과 |
| 효과 없는 주석 패치 | 1 | 같은 보안 검사가 계속 실패; `verified=false` |
| 대상이 성공 JSON 출력 | 2 | 위조 출력은 query protocol 오류; `verified=false` |
| 격리 속성을 직접 검사한 패치 | 0 | uid 65534, capability 0, no-new-privileges, 읽기 전용 root·mount, 외부 IPv4 경로·활성 비루프백 인터페이스 없음, Docker socket·인증 변수 미노출 |
| 대상 import에서 60초 대기 | 2 | 15초 공유 예산을 초과한 수정 후 검증은 불완료; 컨테이너 제거 |

다섯 실행 모두 원래 fixture 파일의 바이트가 유지됐고, output 디렉터리는 `0700`,
patch·JSON은 `0600`이었다. 종료 후 `wakeio-repair-*` 컨테이너가 0개임을 확인했다.
Docker VM에 비활성 터널 인터페이스가 존재할 수 있어 “인터페이스가 lo 하나뿐”은
검사 기준으로 삼지 않았다. 대신 route와 활성 상태를 검사했다.
이 검사는 Docker의 모든 탈출 가능성이나 전체 애플리케이션 회귀를 보장하지 않는다.

실행 중 macOS daemon 연결 실패도 실제 CLI에서 exit 2 / `sandbox_unavailable`로
확인했다. 명시적 로컬 `--docker-host` 옵션을 추가해 해결했고, 외부 daemon 환경을
자동 상속하지 않는 공개 CLI 회귀 테스트도 추가했다. 이 테스트는 수정 전 실패,
수정 후 통과했다.

## 증거와 재실행

로컬 private 기록은 Git에서 제외된
`artifacts/repair-docker-2026-10-04-32qivR/verification.json`과 각 사례의
`repair.json`, `changes.patch`에 보관했다. patch는 자체 fixture 원문을 포함하므로
이 패턴을 실제 소스에 적용할 때 공개 artifact로 업로드하지 않는다.

저장소 checkout에서 실행한다. 이미지 ID는 현재 리뷰한 로컬 이미지의 ID로 바꾸고,
output은 존재하지 않는 새 경로를 사용한다. 예시의 소켓 경로는 실제 로컬 소켓
주소로 바꾸거나 기본 소켓이면 옵션을 생략한다.

```sh
npm run test:repair:docker -- \
  --image sha256:04e0b4721883a7b878e91662548cd04ddbc2f256cfa86f43920b92557198c1c3 \
  --docker-host unix:///absolute/path/docker.sock \
  --out /absolute/private-reports/new-docker-run
```

명령은 자체 fixture 사본을 만들고 공개 repair CLI로 다섯 사례를 검사한다.
Docker·이미지·검증이 없거나 실패하면 명령이 실패한다. 자동 pull, 테스트 skip,
agent fallback은 없다. 이 단계의 hosted CI 실행, Codex/Claude의 라이브 인증·추론·
비용·도구 차단 정책은 아직 검증하지 않았다.
