# Runtime verify 개발 상태

Runtime verify는 M1 개발 중이다. 현재 target 데이터 파서·계약·아티팩트 모듈이 추가됐으며,
CLI의 `verify`·`init-target`와 공통 runtime 보고서 reader 연결은 후속 작업이다.
현재 실행 가능한 완료 기능으로 안내할 명령 예시는 없다. 전체 사용법은 연결과 검증을 마친 뒤 추가한다.
`doctor --runtime`은 M3 범위다.

runtime 보고서는 갱신된 공통 reader가 필요하며 0.5 소비자는 미지원으로 거부한다.
현재 0.5 reader는 `mode: runtime`을 지원하지 않는다. 기존 0.5 scan 보고서의 입력·출력 호환 보존은
새 runtime 보고서 지원을 뜻하지 않는다. 후속 공통 reader는 `mode: runtime`과
`runtime.revision: verify-m1-v1`을 함께 확인하며, 모르는 runtime 필드를 버려 정상 scan으로 읽지 않는다.
새 reader가 연결되기 전에는 runtime 보고서 생성·소비나 4종 보고서 검증이 완료됐다고 간주하지 않는다.

Target YAML 파싱에는 yaml 2.9.1, 신뢰한 로컬 JSON Schema 검증에는 Ajv 8.20.0을 사용한다.
관련 직접 의존성 2개와 Ajv 전이 의존성 4개의 버전·라이선스는
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)에 정리되어 있다.
Action의 생성 고지에도 이 6개 패키지의 라이선스를 포함하지만 현재 Action 진입점은 새 파서를 참조하지 않는다.
npm 배포 파일에는 원본 `schemas/target.v1.json`과 정적 import에 필요한 `build/schemas/target.v1.json`이 포함된다.
파서를 Action에 연결할 때는 이 정적 JSON import를 번들에 포함하고 실제 연결 경로를 다시 검증해야 한다.

실행 동의·격리·정리·보고서 계약의 설계는 [M1 설계](M1-DESIGN.md)와
[CLI·보고서 설계](design/M1-r10-cli-report.md)를 참조한다. 설계 문서는 실제 대상 실행이나 배포 완료의 증거가 아니다.
