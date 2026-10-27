# M1 R3: compose Builder · JVM RuntimeProfile CP1 설계

기준: `a49da4ceebc2c7dd24020ecbce420f46d0ca7625`, PLAN 4·5·7·8·11·12·13장.
이 문서는 설계 제안이다. 대상 빌드·기동, VM 생성, 설정 변경과 설치는 실행하지 않았다.
Oracle·공개 계약·고정 예제·기대 판정은 각각 소유 역할의 경계를 따른다.

## 1. 확인한 환경과 rootless 충족 경로

읽기 전용 `docker context show`, `docker info --format ...`, `docker version --format ...` 결과:

- context `desktop-linux`, Docker Desktop, Linux/aarch64, client/server `27.3.1`.
- SecurityOptions: `name=seccomp,profile=unconfined`, `name=cgroupns`; `rootless` 항목 없음.
- CgroupDriver `cgroupfs`, CgroupVersion `2`; 기본 runtime `runc`, 등록 runtime에 `runsc` 없음.
- 이는 대상 컨테이너의 실측이 아니며, rootless 충족 증거도 아니다. 현 context로 M1 실행은 거부한다.

Docker의 rootless는 daemon과 컨테이너를 비루트 사용자 namespace에서 실행하는 모드다.
단순 `user: 1000`, Docker Desktop VM, `userns-remap`을 daemon rootless로 표기하지 않는다.
또한 rootless에서 CPU·메모리·PID cgroup 제한은 cgroup v2와 systemd·controller 위임이 필요하다.
근거: [Docker rootless](https://docs.docker.com/engine/security/rootless/),
[rootless 자원 제한](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources).

| CP1 선택지 | 충족 방법·한계 |
| --- | --- |
| A: 전용 Linux rootless daemon **추천** | Mac은 별도 Linux VM, CI는 격리된 사용자 daemon. rootless·systemd cgroup v2·cpu/memory/pids 위임을 probe로 검증하고 명시적 endpoint를 사용한다. 기존 Desktop daemon은 중지·변경하지 않는다. |
| B: rootless BuildKit 단독 | 빌드만 비루트화하며 실행 daemon 요구는 해결하지 못한다. rootlesskit 네트워크도 별도 격리가 필요해 A보다 정책 조합이 늘어난다. |
| C: 현재 Desktop의 non-root 컨테이너 | daemon rootless 요구를 충족하지 못하므로 선택하지 않는다. |

실행 preflight는 `rootless` SecurityOption·cgroup v2/systemd·실제 resource probe를 모두 요구한다.
`runsc`가 준비되고 probe가 통과하면 사용하며, 없으면 검증된 rootless Docker로만 내려간다.
`--require-isolation gvisor` 미충족, 제한 무시, 미확인 backend는 target 생성 전에 exit 2다.
`IsolationReport`는 backend·daemon/runtime 버전·rootless·seccomp·resource 실측을 분리한다.
BuildKit 공식 rootless 예제의 `--privileged`/unconfined 설정을 target 기본값으로 가져오지 않는다.
근거: [BuildKit rootless 제한](https://github.com/moby/buildkit/blob/master/docs/rootless.md).

## 2. compose 입력은 실행 명세로 정규화

원본 compose를 바로 `docker compose up`에 전달하지 않는다. R1의 strict TargetSpec 검증 뒤,
동의가 있을 때만 source snapshot과 검증된 데이터로 임시 compose manifest를 만든다.
`detect()`/`init-target`은 파일 읽기만 수행하고 Docker·Maven·Gradle·source script를 호출하지 않는다.

| 허용 데이터 | M1 처리 |
| --- | --- |
| target service의 `build.context`, `dockerfile` | snapshot 아래 상대 경로, bounded 정규 파일만. context digest에 포함한다. |
| dependency image | 허용 registry의 exact digest와 platform. M1 PG dependency를 명시한다. |
| command/entrypoint | literal argv 배열만. host shell 보간 없이 컨테이너 안에서만 실행한다. |
| ports/health/dependency | target spec의 port·health·service 관계만 읽고, trusted compiler가 생성한다. |
| environment | 제품이 허용한 합성 테스트 값·이름 참조만. host env/.env/CI secret의 자동 상속 없음. |

절대·상위 경로, symlink 탈출, remote/git/additional context, `extends`/`include`, YAML 실행 태그,
중복키·과도한 alias·`${...}` 보간, host bind·socket·devices·external volume/network를 거부한다.
`privileged`, `cap_add`, host PID/IPC/network, userns override, `use_api_socket`, build secret/SSH,
`network.host`/`security.insecure` entitlement와 임의 runtime/security_opt도 거부한다.
source가 고른 healthcheck shell·post_start·hooks는 실행하지 않는다. 허용 집합 밖은 exit 2다.
정규화 파일은 기존 source 밖 private 임시 경로에만 작성하고 source 원본은 수정하지 않는다.
API를 통한 archive 복사나 build context tar를 써서 원본 저장소를 target에 직접 mount하지 않는다.
관리 volume은 run 전용이며 tool·seed snapshot은 read-only, PG data·JaCoCo 결과만 필요한 쓰기를 준다.
Compose 자체는 이보다 넓은 권한·경로를 허용하므로 제품 parser의 거부가 별도로 필요하다.
근거: [Compose service 속성](https://docs.docker.com/reference/compose-file/services/),
[Compose build 속성](https://docs.docker.com/reference/compose-file/build/).

## 3. 빌드 네트워크·비밀값·자원

빌드도 대상 코드 실행이다. verify 동의·rootless·resource·network policy probe가 끝나기 전에는
project lifecycle, Maven plugin/extension, wrapper, Dockerfile RUN을 실행하지 않는다.
controller 프로세스는 기존 `runProcess`의 argv·출력 상한·AbortSignal·process group 감독을 재사용한다.
기존 scanner용 `minimalEnvironment`를 넓히지 않고, Docker endpoint와 전용 config/home만 별도 전달한다.
registry 로그인 파일·credential helper·SSH agent·proxy/env·CI token·cloud credential은 전달하지 않는다.

**추천:** 전용 rootless backend의 별도 build namespace에 default-deny egress를 적용하고,
검증된 registry proxy만 패키지 출구로 둔다. proxy는 HTTPS host/port·redirect·DNS/IP 대상을 검증한다.
M1 Maven 기본 allowlist는 `repo.maven.apache.org:443`; 이미지·tool 준비 registry는 별도 setup 정책이다.
프로젝트의 추가 사내 registry는 explicit 설정이 있어야 하며 인증은 M1에서 지원하지 않아 거부한다.
직접 IP 접속·외부 DNS·host gateway·metadata endpoint·proxy 우회가 가능하면 build를 시작하지 않는다.
이 네트워크 경로는 아직 구현/실측하지 않았으며 CP1에서 backend 구성과 R9 probe를 함께 검토한다.

dependency 준비 뒤 archive/manifest checksum을 결속하고 최종 compile/package RUN은 network none이다.
일반 compose `build.network`는 `default|none|host` 모드이며 top-level internal network 이름이 아니다.
따라서 `build.network: internal-net`이나 proxy env만으로 allowlist를 보장한다고 주장하지 않는다.
backend가 온라인 allowlist를 증명하지 못하면 offline build만 가능하며 cache miss는 명시적 build error다.
이는 임의 프로젝트 지원 완료가 아니며, 필요한 dependency 준비 실패를 성공/clean으로 바꾸지 않는다.
근거: [Compose build network](https://docs.docker.com/reference/compose-file/build/#network).

초기 제안 상한은 전체 target 집합 CPU 2, 메모리 2 GiB, PID 256, build 600초, startup 180초다.
개별 timeout은 항상 전체 verify 잔여 예산 이하이며, 설정은 제품 hard cap을 늘릴 수 없다.
`docker inspect`와 실제 cgroup 파일/제한 probe로 적용을 검증한다. argv 기재만으로 성공으로 세지 않는다.
build stdout/stderr는 private bounded buffer에서 마스킹 후 고정 reason·허용 hash만 보고서에 전달한다.
자원·네트워크·비밀 canary 검증은 R9의 소유 fixture로 수행하며 대상 데이터를 원문 보존하지 않는다.

## 4. 기동·PG 의존성·정리

target/PG/controller를 run별 고유 network에 연결하고 runtime network는 `internal: true`다.
source의 외부 URL·host port·aliases는 신뢰하지 않는다. origin은 생성한 소유 container identity에 결속한다.
추천 transport는 trusted controller의 bounded stdio relay다. target을 외부/host에 publish하지 않는다.
R1/R5가 host HTTP engine 재사용을 위해 loopback relay를 둘 경우에도 relay만 host에 존재하며,
container identity·port·method·path allowlist와 공통 request budget을 거쳐 내부 target으로만 전달한다.
PG·JaCoCo 관리 포트는 publish하지 않으며 controller/observer 전용 접근만 허용한다.

target은 numeric non-root UID, cap-drop ALL, no-new-privileges, default seccomp, read-only rootfs다.
전용 tmpfs·managed 결과 volume만 쓰기 가능하며 Docker socket·host 경로·SYS_PTRACE는 없다.
PG도 non-root로 실행하고 초기 data volume의 소유권은 trusted 준비 단계에서 제한적으로 설정한다.
PG에는 합성 계정·seed만 주고, 로그/DB data와 source·controller credential을 분리한다.
실행 중 인터넷·호스트·임의 다른 container 통신은 실패해야 한다. 실패/미확인 시 Oracle coverage는 unknown이다.
health는 고정 HTTP path와 deadline으로 controller가 검사한다. health 실패에서 공격을 진행하지 않는다.
의존 서비스/seed 준비·스냅샷 복원은 R1/R5와 합의한 artifact 계약으로 연결하며 임의 SQL 원문은 보고하지 않는다.

allocation마다 generated project/run label과 실제 container/network/volume ID를 private lease에 기록한다.
마지막 단계는 ID별 stop/rm, network/volume 제거, inspect/list의 부재 확인이다. 전역 prune은 하지 않는다.
timeout·SIGINT·SIGTERM·중간 생성 실패 모두 동일 finally 경로를 거친다. owned process group도 종료 확인한다.
CLI crash/lease 회수 실패는 완성 보고서로 인정하지 않는다. 다음 실행은 소유 lease만 점검·회수한다.
cleanup 미확인은 `error`이며 유효한 발견이 없으면 exit 2다. clean 완료로 바꾸지 않는다.
발견과 미완료가 함께 있으면 PLAN10장에 따라 exit 1이고 cleanup 오류는 별도 명시한다(R1/R10 계약).
기존 repair의 generated 이름·force rm·부재 확인을 참고하되 process 종료를 container 정리의 대용으로 쓰지 않는다.

## 5. JVM 계측·라인 매핑

추천 toolchain 후보는 Java 21 LTS, Maven 3.10.0, JaCoCo 0.8.16이다. 현재 공식 release를 확인한
제안이며 확정 버전/이미지 digest는 R8 fixture와 CP1 검토에서 결속한다. snapshot·floating tag는 실행 거부한다.
[Maven 다운로드](https://maven.apache.org/download.cgi),
[JaCoCo release history](https://www.jacoco.org/jacoco/trunk/doc/changes.html).

JDK build/JRE run/PG/tool images마다 repository, exact version, OS/arch, OCI index와 platform digest를 고정한다.
JaCoCo agent/CLI jar는 같은 exact version·SHA256, Maven 배포본은 공식 SHA512·서명 확인 후 로컬 SHA256도 고정한다.
pin 파일은 도구 버전·라이선스·다운로드 출처·원문 hash를 기록하고, 아직 측정하지 않은 digest를 만들지 않는다.
agent는 제품 소유 read-only volume, exec/XML 출력은 run 전용 managed volume에 둔다.
검증된 image entrypoint argv에 `-javaagent:`를 삽입하며 source JAVA_TOOL_OPTIONS를 상속하지 않는다.
`sessionid`는 run/coverage artifact에 결속하고 append=false, target application class include 범위를 정한다.
JaCoCo tcpserver는 internal network에서만 사용한다. 인증이 없는 포트를 host/외부에 노출하지 않는다.
trusted CLI helper가 startup/health 후 baseline dump+reset, 각 route control/attack 후 dump+reset을 한다.
동시 요청이 섞이지 않도록 coverage 수집 구간은 직렬화하며 startup/health probe coverage는 분리한다.
각 exec에 built image·class tree·source snapshot·route/task·request 구간·agent 버전을 해시로 묶는다.
같은 build의 classfiles/source로 CLI report XML을 만들고 class ID·라인 디버그 정보·경로 경계를 대조한다.
Jacoco dump/report 실패, class 불일치, debug line 없음, source 탈출은 줄 수 0 대신 unknown이다.
covered는 요청 후 handler의 라인 instruction count가 증가한 경우이며 미요청 대조 handler는 증가하지 않아야 한다.
공통 프레임워크 코드의 covered만으로 특정 route handler나 sink가 reached라고 주장하지 않는다.
근거: [JaCoCo agent](https://www.jacoco.org/jacoco/trunk/doc/agent.html),
[JaCoCo CLI dump/report](https://www.jacoco.org/jacoco/trunk/doc/cli.html).

## 6. 재현·의존 캐시와 실패 기록

source snapshot·build 설정·Dockerfile·lock/POM/plugin graph·Pack·builder/toolchain·platform을 image cache key에 넣는다.
Maven repository cache는 repo identity와 main/PR trust namespace별로 분리하고 artifact checksum을 재확인한다.
PR이 쓴 cache를 main이 읽지 않는다. checksum 불일치는 miss/error이며 자동 교정·안전 verdict 재사용은 없다.
두 clean build의 image/config digest·JAR bytes·class tree를 비교한다. Maven outputTimestamp·plugin 버전을 고정한다.
동일 digest가 안 나오면 원인 필드/차이를 남기며 같다고 보고하지 않는다. R9가 clean/warm 두 조건을 구분한다.
JaCoCo session/time/소요 시간은 원본에 남기고, 비교용 semantic projection의 제외 필드를 미리 고정한다.
근거: [Maven reproducible builds](https://maven.apache.org/guides/mini/guide-reproducible-builds.html).

## 7. 구현 파일·독립 검증 계획

- R3 신규 후보: `src/runtime/builders/{compose,compose-input,build-policy}.ts`,
  `src/runtime/runtimes/{jvm,jacoco,container-lifecycle}.ts`; actual shared 계약·registry 변경은 R1 요청만 한다.
- R3 자체 회귀 후보: `tests/runtime-compose.test.ts`, `runtime-jvm.test.ts`, `runtime-cleanup.test.ts`.
  R8의 예제·기대 판정은 읽기 전용이며 제품 실패에 맞춰 수정하지 않는다.
- R9 CI 후보: `.github/workflows/runtime-m1.yml`; `contents: read`, SHA-pinned Actions,
  same-repository PR·main/dev push 조건만 허용하고 fork·pull_request_target은 실행 전 거부한다.
- rootless backend 준비는 신뢰 도구 setup이다. 실제 source build/run은 반드시 제품 verify consent 경로를 사용한다.
- 아래 명령은 승인 뒤 구현될 재현 계획이며 이 패킷에서 실행하지 않았다.

```sh
node --test build/tests/runtime-compose.test.js build/tests/runtime-jvm.test.js build/tests/runtime-cleanup.test.js
node build/src/cli.js verify --target examples/runtime/spring-sqli/vulnerable/wakeio.target.yml --execute-target-consent --out /NEW/vuln
node build/src/cli.js verify --target examples/runtime/spring-sqli/fixed/wakeio.target.yml --execute-target-consent --out /NEW/fixed
```

R9는 두 번의 V/F/safe 실행에서 confirmed 기대값·route coverage·marker 재현·전체 시간과 정리를 검증한다.
builder forbidden destination/secret canary/소스 불변, runtime 외부 차단·UID/cap/seccomp/read-only·자원 적용,
agent off·dump 실패·PG 실패·health timeout·signal·cleanup 실패·잔여 object 0을 독립 검증한다.
동의 없는 실행은 파일 생성·Docker 접촉·target request 0이어야 한다. 미충족은 exit 2와 해당 범위 unknown이다.
이 설계는 로컬 Desktop rootless·allowlist 실측·고정 이미지 digest가 확보됐다는 증거가 아니다.
