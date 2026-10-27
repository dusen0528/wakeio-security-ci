# Runtime verify 개발 상태

Runtime verify는 M1 개발 중이다. `init-target`은 소스를 데이터로 읽어 Target YAML 초안을 만든다.
CLI의 `verify` 실행·공통 runtime 보고서 reader 연결은 후속 작업이며 `doctor --runtime`은 M3 범위다.

Spring Pack의 감지 조건을 만족하는 `services/orders`가 있을 때, 저장소 루트에서 다음처럼 초안을 만든다.
출력의 부모는 이미 존재해야 하고, 소스가 그 부모 아래의 안전한 상대 경로로 표현되어야 한다.

```sh
node build/src/cli.js init-target --source services/orders --out wakeio.target.draft.yml
node build/src/cli.js init-target --help
```

새 출력 파일은 소스 밖에 0600 권한으로 만들며 기존 파일·링크를 덮어쓰지 않는다.
경로 구성요소에 심볼릭 링크를 쓸 수 없다(macOS의 시스템 /tmp·/var 별칭만 예외).
지원하지 않는 소스·불안정/연결된 입력·안전한 상대 경로로 표현할 수 없는 배치는 고정 사유와 exit 2로 거부한다.
옵션 누락·중복·미지원 옵션·제어 문자·help 혼합은 소스 읽기나 출력 생성 전에 거부한다.
exit 0은 초안 생성 성공이다. 빌드·프로젝트 설치/스크립트·Docker·대상 요청은 실행하지 않는다.
저장 link 후 확인·정리 실패는 `init_target_output_unconfirmed`와 exit 2로 알린다. 이 경우 출력이 이미 존재할 수 있다.
출력을 자동으로 지우지 않으므로 재시도 전에 경로와 파일을 확인해야 한다. exit 0은 저장 후 확인·정리까지 성공한 경우다.
초안은 schema에 맞지만 실행 준비가 끝난 설정이 아니다. compose 파일/서비스·의존 서비스·seed·scope를 검토해야 한다.
compose 파일에는 미확정 자리표시자를 쓰고 seed는 비워 둔다. port/health는 Pack 데이터,
startup/요청/시간 예산은 PLAN의 제한된 예제값을 쓰며 환경변수·자격 증명은 복사하지 않는다.
감지 파일의 SHA-256·Pack ID/SHA·고정 사유는 초안 주석에 남긴다. 원문·응답·비밀값이나 독립 검증 증거가 아니다.
Pack의 source-routes와 binding hint는 감지 성공만으로 컴파일·실행 지원된다고 판단하지 않는다.

runtime 보고서는 갱신된 공통 reader가 필요하며 0.5 소비자는 미지원으로 거부한다.
현재 0.5 reader는 `mode: runtime`을 지원하지 않는다. 기존 0.5 scan 보고서의 입력·출력 호환 보존은
새 runtime 보고서 지원을 뜻하지 않는다. 후속 공통 reader는 `mode: runtime`과
`runtime.revision: verify-m1-v1`을 함께 확인하며, 모르는 runtime 필드를 버려 정상 scan으로 읽지 않는다.
새 reader가 연결되기 전에는 runtime 보고서 생성·소비나 4종 보고서 검증이 완료됐다고 간주하지 않는다.

Target YAML 파싱에는 yaml 2.9.1, 신뢰한 로컬 JSON Schema 검증에는 Ajv 8.20.0을 사용한다.
관련 직접 의존성 2개와 Ajv 전이 의존성 4개의 버전·라이선스는
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)에 정리되어 있다.
Action의 생성 고지에도 이 6개 패키지의 라이선스를 포함한다. init-target 경로는 파서와 정적 schema를 번들에서 사용한다.
npm 배포 파일에는 원본 `schemas/target.v1.json`과 정적 import에 필요한 `build/schemas/target.v1.json`이 포함된다.
Pack은 tool 내부 고정 경로에서만 읽는다. npm의 build/src 모듈과 Action의 dist-action 모듈은 각각 배포된 packs를 사용한다.

실행 동의·격리·정리·보고서 계약의 설계는 [M1 설계](M1-DESIGN.md)와
[CLI·보고서 설계](design/M1-r10-cli-report.md)를 참조한다. 설계 문서는 실제 대상 실행이나 배포 완료의 증거가 아니다.
