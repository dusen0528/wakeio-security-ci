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
온라인 allowlist를 증명하지 못하면 build error다. 고정 cache만으로 온라인 지원을 대체하지 않는다.
M1 통과에는 빈 의존 cache의 허용 registry fetch 성공과 금지 목적지 차단을 모두 실측해야 한다.
근거: [Compose build network](https://docs.docker.com/reference/compose-file/build/#network).

초기 제안 상한은 전체 target 집합 CPU 2, 메모리 2 GiB, PID 256, build 600초, startup 180초다.
개별 timeout은 항상 전체 verify 잔여 예산 이하이며, 설정은 제품 hard cap을 늘릴 수 없다.
`docker inspect`와 실제 cgroup 파일/제한 probe로 적용을 검증한다. argv 기재만으로 성공으로 세지 않는다.
build stdout/stderr는 private bounded buffer에서 마스킹 후 고정 reason·허용 hash만 보고서에 전달한다.
자원·네트워크·비밀 canary 검증은 R9의 소유 fixture로 수행하며 대상 데이터를 원문 보존하지 않는다.

## 4. 기동·PG 의존성·정리

target/PG/controller를 run별 고유 network에 연결하고 runtime network는 `internal: true`다.
source의 외부 URL·host port·aliases는 신뢰하지 않는다. origin은 생성한 소유 container identity에 결속한다.
transport는 trusted controller의 bounded stdio relay 단일안으로 확정한다. host port는 publish하지 않는다.
R1 §5 `RunContext.request: RuntimeRequestPort` capability를 R4/R5/R10에 주입하고 host HTTP listener는 만들지 않는다.
소유 container identity·port·method·path allowlist, 요청/응답 크기·deadline과 공통 admission budget을 강제한다.
PG·JaCoCo 관리 포트는 publish하지 않으며 controller/observer 전용 접근만 허용한다.

target은 numeric non-root UID, cap-drop ALL, no-new-privileges, default seccomp, read-only rootfs다.
전용 tmpfs·managed 결과 volume만 쓰기 가능하며 Docker socket·host 경로·SYS_PTRACE는 없다.
PG도 non-root로 실행하고 초기 data volume의 소유권은 trusted 준비 단계에서 제한적으로 설정한다.
PG 서비스는 제품이 고정한 신뢰 image/config digest·DB/container/log-volume lease에 결속한다.
source가 제공한 PG image·entrypoint·로그 경로/설정을 신뢰하거나 raw init script를 관리자 권한으로 실행하지 않는다.
앱 접속 role은 `LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS`로 생성한다.
`pg_read_server_files`·`pg_write_server_files`·`pg_execute_server_program` 등 `pg_*` role의 직접/간접 멤버십은 0이다.
일반 verify도 R8과 같은 SELECT-only 기본값이다: DB CONNECT·대상 schema USAGE·허용 테이블 SELECT만 준다.
앱은 DB/schema 소유자가 아니며 PUBLIC·상속·SET ROLE 경로까지 포함해 불필요 CREATE/TEMP·관리 권한을 제거한다.
admin seed/snapshot·Observer 로그/설정 확인 자격은 앱 합성 계정과 분리하고 앱에 credential·복원 handle을 주지 않는다.
이미지의 초기 `POSTGRES_USER` 관리자와 앱 접속 role을 동일하게 쓰지 않는다.
source seed SQL은 격리된 schema 전용 non-superuser seed role로만 실행한다. 서버 파일/프로그램·관리 role 권한은 없다.
source의 superuser/extension/프로그램 권한 요구는 거부하며 trusted 관리자 준비와 source seed 실행을 섞지 않는다.
`log_statement=all`·`log_min_error_statement=ERROR`는 서버 레벨 SUSET으로 고정하고 앱의 SUSET parameter SET/ALTER SYSTEM 권한은 0이다.
`log_parameter_max_length` 등 parameter 설정·한도는 R5 핀에 결속하며 server/DB/role override와 startup option도 검사한다.
`log_parameter_max_length_on_error`는 USERSET이므로 SUSET 보호로 주장하지 않는다. 관련 관측이 불명하면 unknown이다.
Observer는 독립 관리 연결로 실제 `pg_settings`·role 속성/멤버십/유효 ACL을 초기·복원 후·수집 시작/종료 장벽에서 확인한다.
신뢰 lease/설정/role 불일치·누락·드리프트는 관련 구간 unknown/error다. 앱 응답·stdout·source 로그를 증거로 대체하지 않는다.
근거: [PG 권한](https://www.postgresql.org/docs/18/ddl-priv.html), [서버 역할](https://www.postgresql.org/docs/18/predefined-roles.html),
[로그 설정](https://www.postgresql.org/docs/18/runtime-config-logging.html), [GUC 권한 구분](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/utils/misc/guc_tables.c).
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
trusted CLI helper가 startup/health baseline을 분리하고 각 control/probe 요청별 before/after exec·XML·reset ack를 묶는다.
동시 요청이 섞이지 않도록 coverage 수집 구간은 직렬화하며 startup/health probe coverage는 분리한다.
각 exec에 built image·class tree·source snapshot·route/task·단일 request ordinal·구간·agent 버전을 해시로 묶는다.
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

- 제품·schema·예제·테스트·CI의 경로·소유자·PLAN11/R8 case 매핑은 [R1 설계](M1-r1-contracts.md) §7의 유일 명부를 따른다.
- R3는 독자 파일/테스트 목록을 두지 않는다. 명부 밖 추가는 오케스트레이터의 R1 변경 패킷으로 승인받는다.
- R8의 예제·기대 판정은 읽기 전용이며 제품 실패에 맞춰 수정하지 않는다.
- R9 CI는 `contents: read`, SHA-pinned Actions, same-repository PR·main/dev push만 허용한다.
  fork·pull_request_target은 실행 전 거부한다. 실제 파일/테스트 명령은 R1 §7에서만 정한다.
- rootless backend 준비는 신뢰 도구 setup이다. 실제 source build/run은 반드시 제품 verify consent 경로를 사용한다.
- 아래 명령은 승인 뒤 구현될 재현 계획이며 이 패킷에서 실행하지 않았다.

```sh
# 단위/실패 회귀 명령은 R1 §7의 canonical 테스트 목록으로 조립한다.
node build/src/cli.js verify --target examples/runtime/spring-sqli/vulnerable/wakeio.target.yml --execute-target-consent --out /NEW/vuln
node build/src/cli.js verify --target examples/runtime/spring-sqli/fixed/wakeio.target.yml --execute-target-consent --out /NEW/fixed
```

R9는 두 번의 V/F/safe 실행에서 confirmed 기대값·route coverage·marker 재현·전체 시간과 정리를 검증한다.
builder forbidden destination/secret canary/소스 불변, runtime 외부 차단·UID/cap/seccomp/read-only·자원 적용,
agent off·dump 실패·PG 실패·health timeout·signal·cleanup 실패·잔여 object 0을 독립 검증한다.
동의 없는 실행은 파일 생성·Docker 접촉·target request 0이어야 한다. 미충족은 exit 2와 해당 범위 unknown이다.
이 설계는 로컬 Desktop rootless·allowlist 실측·고정 이미지 digest가 확보됐다는 증거가 아니다.

## 8. M1-08: Mac·CI 준비 절차와 enforced datapath

읽기 전용 확인: `limactl version 1.0.3`, `colima version 0.8.1`. 기존 instance나 daemon은 변경하지 않았다.
설치된 공식 Lima rootless template 이름은 `docker.yaml`/`template://docker`다(`docker-rootful`과 구별).
[v1.0.3 원문](https://github.com/lima-vm/lima/blob/v1.0.3/templates/docker.yaml)은 기본 host mount와 unpinned install/fallback이 있어 그대로 기동하지 않는다.
후속 준비기는 이 template의 해시·VM OS image digest·Docker extras 패키지/서명·RootlessKit·nft 버전을 고정한 파생 YAML을 만든다.
파생 값은 `mounts: []`, agent forwarding off, host resolver/host alias off, 자동 TCP forwarding off; Docker Unix socket forwarding만 둔다.
명령 후보(이름 충돌 시 거부): `limactl create --name=wk-m1-cp1 --cpus=2 --memory=4 --disk=20 /ABS/pinned-wakeio-docker.yaml` 후 `limactl start wk-m1-cp1`.
이는 로컬 `create/start --help`로 문법만 확인한 계획이다. host source는 tar/API로 복사하며 guest mountinfo에서도 host share 0을 확인한다.
endpoint는 `limactl list wk-m1-cp1 --format 'unix://{{.Dir}}/sock/docker.sock'`의 소유 socket으로 고정하고 매 호출 `docker --host`에 전달한다.
Mac Desktop context를 바꾸지 않는다. run lease의 VM UUID/이름을 확인한 경우에만 해당 instance의 stop/delete·socket/disk 부재를 검증한다.
CI 준비는 전용 `wakeio-m1` UID10001과 충돌 없는 subuid/subgid 65,536개를 만들고 핀된 uidmap/dbus/rootless extras/nft를 설치한다.
`user@10001.service.d`에 `Delegate=cpu cpuset io memory pids`를 두고 `systemctl daemon-reload`, `loginctl enable-linger wakeio-m1`을 수행한다.
전용 user session에서 `dockerd-rootless-setuptool.sh install`, `systemctl --user start docker`; socket은 `/run/user/10001/docker.sock`이다.
Mac도 rootless W=10001을 sudo 없는 전용 user로 만들고 template 관리자와 분리한다. 원본 template의 user provision은 이 계정으로 교체한다.
관리자 전용 Unix relay만 W socket을 Lima host socket으로 연결하며 target에는 relay·관리 key·host share가 없다.
rootless option·seccomp 실제 적용·cgroup limit/CPU controller probe 실패 시 source 실행을 거부한다.
위 root 작업은 신뢰 VM/runner 준비뿐이다. target은 non-root·cap0이며 setup tool·sudo·Docker socket·credential을 받지 않는다.

VM root 준비기가 전용 `inet` nft table의 OUTPUT에서 rootless socket UID W를 먼저 분기하고, IPv4/IPv6 모두 proxy tuple만 허용한다.
VM 전체도 default-deny이며 고정 관리 SSH reply와 proxy UID의 허용 upstream만 예외다. UID0/SUID helper의 포괄 허용은 없다.
핵심 규칙은 `meta skuid W`에서 `ip/ip6 daddr P tcp dport PORT accept`, 나머지 counter/drop이다. 일반 established 허용보다 먼저 적용한다.
rootlesskit/slirp의 실제 socket UID와 flow counter를 probe로 대조하고, 준비 때 열린 연결을 닫은 뒤 정책을 atomic 설치한다.
P는 별도 UID의 canonical Maven reverse proxy다. trusted mirror 설정을 만들고 GET/HEAD artifact 경로만 허용하며 CONNECT·upload·임의 Host를 거부한다.
GET/HEAD도 Maven 좌표의 정규 repository 경로·허용 확장자만 받으며 query·비정규 인코딩/경로를 거부한다.
허용 좌표/GET 경로에는 잔여 정보 채널이 있다. CPx1 N2에 따라 소스 등 build 입력·env에 비밀이 없다는 전제로 수용하며 완전한 정보 유출 차단으로 주장하지 않는다.
proxy만 제한된 DNS를 사용하고 upstream host/TLS 검증·public IP pin·모든 redirect 재검증을 한다. 사설/link-local/metadata·주소 변경은 거부한다.
proxy UID도 허용 registry DNS/IP/443만 접근한다. target의 직접 IP·DNS/DoH·host gateway·CONNECT/SNI 우회는 W drop 또는 proxy 거부로 끝나야 한다.
단일 run VM lease에서 phase 전환을 직렬화한다. setup은 핀된 tool 준비, build는 proxy tuple만, runtime은 W 외부 output 전부 drop·내부 app/PG만 허용한다.
R9는 소유 canary로 위 우회와 IPv6를 시도해 금지 수신 0·허용 fetch 성공·counter 일치를 확인한다. 정책 이름/환경변수만으로 통과하지 않는다.
빈 cache fetch→checksum 결속→Maven offline compile→동일 image/JAR digest 비교를 검증한다. 임의 project 준비 실패는 error이며 지원 완료로 바꾸지 않는다.

R5 parser helper는 핀된 image/WASM으로 job마다 새로 만들고 network none·UID65534·cap0·read-only·CPU1·PID16·256MiB로 제한한다.
stdin은 인코딩 후 64KiB 이하(SQL32KiB 포함), projection stdout은 1MiB 이하·전체8MiB/4,096사건 이하; stderr/원문 로그는 저장하지 않는다.
controller의 helper job deadline은 1초다. trap·재초기화·timeout·출력 초과는 unknown으로 닫고 process group 종료와 container rm을 확인한다.
R3 capability는 `{leaseId, assetDigests, stdinBytes, deadlineMs, memoryBytes}`→`{projectionBytes, hashes, stopReason, cleanupConfirmed}`만 제공한다.
PG lease는 DB/container/log volume ID·runNonce·seed 뒤 시작 cursor·session/line·rotation generation을 묶고 marker 없는 줄은 즉시 버린다.
요청 종료 뒤 writer 정지→최종 cursor까지 drain→parser 종료→raw PG volume 삭제·부재 확인 순서다. gap/미완료 drain/삭제 실패는 unknown/error다.
후속 R3 패킷은 핀된 VM/CI setup과 nft/proxy, helper/lifecycle을 구현하고 보안 CPx를 받는다. R9가 같은 consent CLI 경로로 독립 probe한다.
현재는 준비·정책·helper 모두 미실행이다. 실제 가용성·성능과 우회 차단이 입증되기 전 M1 격리/빌드 게이트를 PASS로 세지 않는다.
M1-21은 기존 최소 env/argv/group 감독을 재사용한 trusted tool 실행기와 probe 데이터 정합성 검사만 구현한다.
실제 `preflightIsolation`은 backend/collector 미구현으로 항상 unavailable·verified=false다. 합성 테스트의 matches=true는 실측/실행 권한이 아니다.
M1-29의 `normaliseCompose`는 snapshot own-data만 검사한다. YAML 문법의 중복 키·tag·anchor/alias/merge 거부는 호출자 strict parser 책임이다.
M1 입력은 app build/literal argv와 PG image 선언·관계만 받는다. 환경 값은 `wakeio:postgres.{url,username,password}` 참조만 허용하고 실제 합성 값은 trusted builder가 만든다.
정규화 결과는 항상 executable=false이며 source snapshot·독립 PG pin/config·실측 isolation이 필요하다. source의 image digest 선언도 신뢰 pin의 대용이 아니다.
Maven 정책은 canonical 좌표의 jar/pom/module/xml/zip/tar.gz·metadata·서명/체크섬 경로만 다룬다. HTTP 서버·DNS/redirect 검증·nft 강제는 아직 없다.
좌표 경로 근거: [Maven 공식 repository layout](https://maven.apache.org/repositories/layout.html). 알 수 없는 확장자를 임의 URL 통로로 허용하지 않는다.
CPU quota 비교는 `Math.round(cpu * period)`로 정수화한다(CPx2 N1). 0.3 CPU/100000 period의 실제 요구 quota는 30000이다.
후속 bootstrap/proxy는 우선 canonical `runtimes/controller.ts`·`builders/build-policy.ts` 안에서 최소 조립하며 명부 밖 bootstrap/proxy 파일은 추가하지 않는다.
M1-37: context/Dockerfile의 각 선두 `-` segment를 거부하고 service는 Target과 같은 점 허용·64자 상한으로 정렬한다.
후속 실행 argv는 snapshot의 절대 경로와 명시 flag로만 만든다. 상대 소스 경로를 그대로 tool option 위치에 넣지 않는다.
controller의 consent guard 뒤에서만 새 private HOME·고유 profile을 만들며 기존 Lima/Desktop 설정을 읽거나 변경하지 않는다.
프로필 준비는 create/list와 실제 profile directory dev/ino 결속까지다. backend는 계속 unavailable이며 VM 시작·Docker/대상 실행은 연결하지 않는다.
고정 rootfs URL/SHA와 Docker extras 버전/URL/SHA는 trusted 입력이다. 모양 검증은 다운로드/서명/실제 byte 검증의 증거가 아니다.
제품 소유 boot script는 alias 제거·UID10001/non-sudo·비중첩 subuid/gid·cgroup 위임의 첫 설정 뒤 missing-prerequisite로 종료한다.
daemon/관리 Unix relay·nft/proxy·VM 실제 ID·resource/egress probe가 없어 VM 시작 승인을 내지 않는다. 관리 SSH22만 TCP 예외로 명시한다.
cleanup은 private HOME/store/profile의 결속·Stopped/PID0를 재확인한 profile만 delete하고 부재를 확인한다. Running VM은 실제 VM ID 미결속으로 stop/delete를 거부한다.
abort/deadline 뒤 process group 확인과 별도 10초 cleanup budget을 사용한다. 실패/교체/부재 불명은 cleanup unconfirmed로 보존한다.
M1-52: 한 tool의 process group 확인이 false면 이후 성공으로 복구하지 않는다. 삭제 감독 불명도 HOME/완료 확인 전에 거부한다.
executor 주입은 trusted internal 조립/고장 재현 경계뿐이며 raw options/TargetSpec에는 함수 권한이 없다. 기본 감독은 기존 실행기를 그대로 사용한다.
Lima Unix socket 경로는 100바이트 이내다. trusted caller는 canonical /tmp 아래 짧고 소유권이 확인된 base를 주며 긴 경로를 제한 완화로 우회하지 않는다.
근거: [Lima Docker](https://lima-vm.io/docs/examples/containers/docker/), [rootless cgroup](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources), [nft socket UID](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation#Matching_by_socket_UID_.2F_GID).

### M1-60 / CPx6 제안: 신뢰 OS 준비와 source 실행의 단계 분리

기존 Stopped-only `prepareLimaProfile`과 target/source 실행 전 모든 barrier는 유지한다.
신규 내부 `prepareLimaOsProfile`은 소유 로컬 image bytes를 검증하고 source-free OS profile만 만든다. CLI/Provider/preflight에는 연결하지 않는다.
이 단계 분리는 CPx6 검토 제안이며 실제 VM 준비/boot 실행은 해당 승인과 후속 R9 패킷 전까지 금지한다.
consent own-descriptor 검사 전 파일/경로/프로세스/네트워크 I/O는 0이다. raw options/TargetSpec에는 executor/스크립트 권한이 없다.
rootfs pin은 Noble24.04/date/arch에 결속된 공식 URL과 trusted SHA다. URL/hash 모양만으로 bytes 검증을 대신하지 않는다.
입력 FD는 nofollow/nonblock·regular·소유 UID·hardlink0·조상 링크 거부이며 2GiB/64KiB chunk·10분 이하/외부 deadline/abort로 private copy한다.
원본의 dev/ino/size/mtime/ctime·이름을 전후 대조하고 private 0600 copy를 fsync·재독 SHA 검증한다. boot 전에도 재독 SHA를 대조한다.
private HOME/config/rootfs와 Lima가 만든 lima.yaml/vz-identifier의 dev/ino/size/mtime/ctime을 결속한다. 링크/교체/불명은 HOME을 남기고 unconfirmed다.
Lima1.0.3의 VZ identity는 `vz-identifier`의 opaque GenericMachineIdentifier bytes다. list JSON에 없는 UUID를 만들지 않고 실제 bytes SHA만 기록한다.
`lease.boot()`는 source 없는 OS의 Running 관측→소유 foreground 그룹 종료→Stopped/PID0 확인만 하는 유한 cycle이다. 상주 backend/target 실행 API가 아니다.
공식1.0.3 `start --foreground`는 같은 PID에서 hostagent로 exec한다. 기존 최소 env/argv/bytecap/AbortSignal/PGID 감독을 그대로 사용한다.
list의 PID를 kill/stop 권한으로 쓰지 않는다. 별도 10초 관측/cleanup에서 Running·재사용 PID·VM identity 불명은 stop/delete를 거부한다.
VM의 OS 준비 부팅은 rootless daemon/nft를 설치할 신뢰 환경을 얻기 위한 단계다. source/host credential은 복사·mount하지 않으며 Docker 설치도 없다.
이 OS-only 단계의 guest user-mode egress는 아직 차단되지 않는다. 소스·host 비밀·target·Docker 실행 0이 전제이며 egress 격리 PASS가 아니다(CPx6 N4).
source-free config만 기존 setup script의 최종 무조건 missing-prerequisite 종료를 제외한다. alias/cgroup/UID/subuid/위임 실패 guard는 유지한다.
CPx6 N2: script는 공통 BOOT_GUARDS와 명시 MISSING_PREREQUISITE_TRAILER로 조합한다. M1-117 이후 OS-only 끝은 guard complete 기록과 trap 해제다.
Stopped-only는 그 뒤 미구현 backend 거부125를 추가한다. OS guard 완료와 backend 준비를 같은 상태로 해석하지 않는다.
기존 Stopped-only script는 같은 guard 뒤 trailer를 붙인다. guard 안의 실패 exit125는 두 경로 모두 그대로다. 줄 위치에 따른 split/slice 제거는 없다.
mount0·agent/pubkey/proxyenv/hostResolver off·alias 제거·서비스 TCP forwarding off(관리 SSH22 예외)·VM2CPU/4GiB/20GiB는 그대로다.
Docker extras/guest helper의 실제 bytes pin·daemon/relay·nft/proxy·resource/egress/PG/target 검증은 미완료다. backend는 계속 unavailable·verified=false다.
관측 phase 이름은 guest 준비/격리 PASS를 뜻하지 않는다. 테스트는 고정 가짜 bytes/소유 Node mock만 사용했고 실제 image 다운로드·VM 부팅은 하지 않았다.
후속 R9가 공식 image bytes·Lima helper 자산·host 지원을 독립 검증해야 한다. 현재 API는 로컬 파일만 받으며 downloader/지속 VM 운영은 후속이다.
[공식 SHA metadata](https://cloud-images.ubuntu.com/releases/noble/release-20261017/SHA256SUMS)의 arm64 후보는 `50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e`다. metadata 조회만 했으며 이 image bytes 실측은 없다.
1.0.3 근거: [VZ identity](https://github.com/lima-vm/lima/blob/v1.0.3/pkg/vz/vm_darwin.go#L652-L665), [foreground exec](https://github.com/lima-vm/lima/blob/v1.0.3/pkg/instance/start.go#L175-L218), [실제 list 필드](https://github.com/lima-vm/lima/blob/v1.0.3/pkg/store/instance.go#L37-L62).
CPx6 N1 고정1.0.3 생성 호출 체인: [createAction364~373](https://github.com/lima-vm/lima/blob/v1.0.3/cmd/limactl/start.go#L364-L373)의 instance.Prepare → [Prepare84](https://github.com/lima-vm/lima/blob/v1.0.3/pkg/instance/start.go#L74-L95)의 driver.Initialize → [VZ Initialize145~147](https://github.com/lima-vm/lima/blob/v1.0.3/pkg/vz/vz_driver_darwin.go#L145-L147)의 getMachineIdentifier다.
root와 R3가 고정 원문을 확인한 정적 근거이며 실제 create 실측은 아니다. 후속 R9가 create 직후 vz-identifier 존재·bytes·소유 identity를 확인한다.
없는 identity를 임의 UUID로 채우지 않는다. identity 부재/불명에서는 회수를 거부하고 unconfirmed를 보존하는 기존 기준을 유지한다.

M1-71: R9의 actual create는 exit1·cleanup confirmed·lease 없음이었고 별도 validate에서 unused param.rootlessSocket 오류를 확인했다.
원래 create stderr 본문은 보존되지 않아 두 오류 문구의 동일성/실패 원인 확정은 하지 않는다. 실제 create 재측정은 후속 R9 담당이다.
Stopped-only/OS-only가 공유하는 generated config에서 미사용 param 전체를 제거한다. Docker extras·socket의 가짜 template/echo 참조는 넣지 않는다.
기존 공통 param을 복원한 Stopped 진단 config도 validate exit1/unused dockerExtrasVersion이었다. 이는 재구성 config의 검증이며 create stderr 동일성 근거는 아니다.
Docker URL/version/SHA는 기존 trusted LimaPins/controller 입력에만 보존하고 닫힌 키·공식 host/arch/version URL 결속·SHA 모양 검증을 유지한다.
config의 metadata 저장 기대 2개를 pin 음성 검사와 두 preparer의 사전 I/O/실행 0 검사로 대체했다. Docker 자산은 여전히 미사용·미검증이다.
자체 확인은 R9가 검증한 private1.0.3 binary/원래 rootfs로 새 private HOME의 두 실제 generated config에 validate만 실행해 각각 exit0/OK였다.
OS 경로의 create는 trusted seam에서 validate로 대체한 뒤 종료했다. 실제 create/start/stop/delete는 0이며 config/HOME·원본 자산/캐시는 그대로였다.
이는 config validation 자체 점검이며 실제 VM 준비/격리 증거나 R9 증거가 아니다. digest·guard·소유 정리·unavailable/verified=false는 유지한다.

M1-76: R9 M1-75에서 actual create exit0·70-byte vz-identifier와 lease SHA 일치를 기록했지만 list의 `limaVersion: v1.0.3`가 기존 literal 검사에서 거부됐다.
고정1.0.3 list protocol에서 정확한 `1.0.3`/`v1.0.3` 두 표현만 허용한다. controller는 trim·semver range·latest·suffix를 받아들이지 않는다.
[공식1.0.3 CLI](https://github.com/lima-vm/lima/blob/v1.0.3/cmd/limactl/main.go)는 Version의 선두 v를 표시에서 제외하고, [store](https://github.com/lima-vm/lima/blob/v1.0.3/pkg/store/instance.go#L162-L170)는 instance version file 값을 읽는다. CLI version 검사는 기존 정확한 1.0.3 그대로다.
[Instance struct](https://github.com/lima-vm/lima/blob/v1.0.3/pkg/store/instance.go#L54-L60)의 hostAgentPID/driverPID는 omitempty여서 0이면 JSON에서 생략될 수 있다.
Stopped+생략/0은 해당 Lima instance의 관측이며 OS 전역 프로세스 부재 실측이 아니다. 소유 tool의 PGID 종료 확인도 별도 조건이고 임의 PID kill 권한은 없다.
버전 외 name/dir/protected/status/arch/VZ/asset·identity·PID·sticky 정리 기준은 그대로다. mock 태그형 lease의 준비/boot/정리와 다른 버전·접미사·개행 거부를 검증한다.
실제 잔존 profile/캐시는 접근·수정·실행하지 않는다. R9가 별도 원본 proof 확인 뒤 정상 SDK로 정리하며 범용 adopt/force 복구 API는 추가하지 않는다.

M1-80: R9 M1-79는 create/prepare·N1 identity 결속을 통과했으나 시작 직후 host-agent PID만 있는 Broken/errors frame에서 즉시 취소했고 cleanup은 성공했다.
driver PID가 없던 실제 원인은 미확정이다. 아래 작성 순서는 과도 관찰이 가능한 정적 근거이며 이번 실제 실패가 과도 상태 때문이었다고 확정하지 않는다.
공식1.0.3 [hostagentAction](https://github.com/lima-vm/lima/blob/v1.0.3/cmd/limactl/hostagent.go#L33-L46)은 먼저 ha.pid를 쓰고 Run으로 진입한다. [VZ state callback](https://github.com/lima-vm/lima/blob/v1.0.3/pkg/vz/vm_darwin.go#L87-L98)은 VM Running 뒤 같은 process PID를 vz.pid에 쓴다.
[Inspect](https://github.com/lima-vm/lima/blob/v1.0.3/pkg/store/instance.go#L174-L193)는 host-agent만 있으면 Broken으로 분류하며 API 연결 실패도 errors/Broken을 만들 수 있다.
boot 중 소유 foreground가 살아 있을 때만 identity/asset/name/dir/pinned version/arch/VZ/protected를 먼저 검증한 frame을 분리한다.
Stopped/Installing/Broken은 미준비로만 재관찰한다. 유효하지 않은 PID·driver-only/서로 다른 PID·알 수 없는 status·transport/identity 손실은 즉시 실패다.
Running은 같은 양수 PID 쌍·errors 없음이 모두 맞아야 한다. frame 오류 배열은 readiness로 바꾸거나 원문 로그로 저장하지 않는다.
시작/관찰은 기존 30초와 caller deadline 중 짧은 한도·abort·16KiB cap을 공유한다. foreground가 먼저 끝나면 Running 관측을 성공으로 채택하지 않는다.
일반 prepare/cleanup의 strict 관찰은 그대로다. finally 소유 PGID 종료와 strict Stopped/PID0 없이 관측 성공을 보고하지 않는다. 소유 삭제 뒤 부재 확인 전에는 cleanup confirmed가 아니다.
고정 Node mock 상태열과 지속 Broken·조기 종료·취소·PID 모순·asset/identity 변경·cleanup 불명을 검사한다. 실제 SDK 재측정은 후속 R9 담당이며 VM/캐시에는 접근하지 않는다.

### M1-99 / CPx8 검토용 bounded source-free OS session

`withLimaOsSession(options, trustedAsyncUse)`는 새 소유 profile만 준비한다. callback은 raw JSON/TargetSpec/options의 필드가 아니며 consent own-descriptor 검사 전 I/O/호출은 0이다.
기존 lease.boot()/Stopped-only 경로는 그대로다. 새 session은 caller deadline과 30초 중 짧은 상한이며 기존 실행기600000ms·16KiB·abort/PGID 감독을 늘리지 않는다.
private HOME/rootfs/config/VZ identity와 정확한 고정 version/양수 PID 쌍을 묶고, binary는 안정 FD/byte SHA와 파일 identity를 전후 결속한다. PID 변경·asset/transport 손실은 폐쇄한다.
Running 동안에만 frozen `{probe()}`를 비차단 trusted async callback에 준다. 고정 argv/script만 실행하며 명령/경로/설치/네트워크 옵션·원문 key/config/OS 로그는 제공하지 않는다.
probe는 UID10001·non-sudo·cgroupv2·cpu/memory/pids delegation의 가용성과 worker 쓰기 권한만 읽는다. guard125/SSH255의 관측 부재와 정확한 성공 token을 구분하고 안전한 boolean metadata만 돌려준다.
[Lima1.0.3 shell](https://github.com/lima-vm/lima/blob/v1.0.3/cmd/limactl/shell.go#L75-L132)의 workdir/shell 옵션과 argv quoting을 사용한다. env는 고정 guest env -i이며 관리 SSH는 같은 소유 VM만 향한다.
callback 종료/throw/미완료·deadline/abort·foreground 조기 종료 시 capability를 닫고 동시 probe를 취소/drain한다. 소유 foreground PGID 종료→strict Stopped→기존 delete/부재 확인 순서다.
cleanup 불명은 sticky로 남기며 Running/PID/asset 불명을 삭제 권한으로 쓰지 않는다. 반환 뒤 보관한 capability의 재사용은 I/O 없이 거부한다.
신뢰 callback의 미해결 Promise는 fence로 유한하게 반환한다. 같은 Node event loop를 막는 동기 무한 루프는 선점하지 못하므로 hostile/blocking callback 지원은 이 작은 session 범위 밖이다.
probe 통과는 daemon·quota/seccomp·egress/PG/target 검증이 아니다. source/host 비밀/mount/agent 전달·Docker/설치 권한·CLI/preflight 연결은 없고 항상 unavailable/verified=false다.
테스트는 소유 Node mock뿐이며 실제 VM 실행은 0이다. CPx8 승인 뒤 R9가 고정 자산으로 guest 준비 probe를 실측해야 하며 현재 OS user-mode egress 차단도 미검증이다.
M1-99는 120자 검사 2회 실패로 미커밋 중단했고 build/테스트도 미실행이었다. M1-103에서 해당 124자 표현식만 줄바꿈했으며 WIP controller AST 동일성을 확인했다.
기존 테스트 diff의 삭제 6행은 import2·mock 명령 이름 선택1·기존 stuck-cleanup 분기1·종료 timer 추출2행이다. 새 shell/session mock 지원이며 기존 assertion/기대값 삭제는 없다.
기준의 기존 test AST 38개가 모두 같고 strict Stopped/version/identity 거부도 보존됐다. 요청된 serial cleanup/compat 1회는 51 pass·0 fail/skip였으며 실제 OS/격리 증거가 아니다.

### M1-110 / CPx8 N3 독립 host parser 자산 로더

`createPgParserAssetLoader(trustedInstallationRoot)`는 내부 host composition용이며 Target/options/cwd/PATH/env locator가 아니다. raw 입력은 own data consent 한 필드만 받으며 그 검사 전 파일/프로세스/네트워크 I/O는 0이다.
승인9b70e09의 worker/manifest/WASM/고지 raw SHA·정확한 길이·파일 allowlist와 protocol/전체 lock pin을 controller 상수로 둔다. manifest/요청의 기대 hash는 채택하지 않는다. 갱신은 R1 M1-107 전체 review bundle 순서를 따른다.
허용된 여섯 배포 파일만 O_NOFOLLOW/O_NONBLOCK로 연다. owner/regular/nlink1/비그룹쓰기·정확한 크기/2MiB 상한·안정 FD와 이름 dev/ino/size/mtime/ctime을 전후 대조하고 root/디렉터리 교체와 추가 파일도 거부한다.
manifest의 raw pin 검증 뒤 explicit protocol/package version/전체 lock SHA/배포 path·고지 pin을 대조한다. 설치 TS나 lock 원문을 읽지 않으며 source provenance는 실행 identity나 권한이 아니다.
신뢰 설치 root는 외부 쓰기가 불가능한 readonly 제공을 전제로 한다. 로더는 OS readonly mount를 만들거나 악의적인 같은 UID host를 격리하지 않으며 실측 claim도 하지 않는다.
모든 read FD를 닫은 뒤 private WeakMap에 검증된 byte 사본만 보관한다. `copyPgParserAssetFiles(handle)`은 다시 defensive copy만 주며 원본 변경·공개 copy 수정과 분리한다. JSON 복제/위조/Proxy handle은 거부한다.
이 handle의 권한은 공개 자산 bytes 조회뿐이다. executionAuthorized=false, status=unavailable/verified=false이며 worker spawn/WASM/SQL 실행 capability·CLI/preflight 배선은 없다. 미래 invoker는 verified backend 뒤 별도 승인 범위다.
자산 결속은 1초/256MiB/network-none·daemon/resource/egress·Oracle 완료를 증명하지 않는다. 계약 테스트는 공개 자산 copy·실제 owned FD 교체만 사용하며 기존 OS session/boot/Stopped 조건과 assertion은 그대로다.
자체 build와 serial cleanup/pg-log/compat 1회는 66 pass·0 fail/skip다. 고정 배포 자산/bundle은 불변이고 실제 worker/WASM/SQL/VM/target 실행은 0이며 R9의 독립 증거를 대신하지 않는다.

### M1-117 / CPx9 N1·N2 및 OS 진단

parser manifest의 독립 raw SHA는 본문 전체를 이미 고정한다. 중복 package/version/길이 literal 비교를 없애고 host protocol/전체 lock header 일관성만 남긴다. 승인 pin/자산 원문은 그대로다.
root 및 workers/pg-parser의0777 거부를 추가하며 sudo/chown 없이 소유 사본만 쓴다. 디렉터리 쓰기 검사 제거 mutation은 일회 검증 뒤 폐기하고 제품에는 남기지 않는다.
Lima의 지원 proxy 소문자/대문자8키를 empty로 명시한다. SDK setupEnv가 system proxy를 먼저 읽은 뒤 이 값으로 덮고 제거한다. SDK 조회 자체 차단이나 실제 host 값/유출 확인을 주장하지 않는다.
공통 BOOT_GUARDS는 root0700 /run/wakeio-m1-boot 안에0600·nlink1 boot-status를 mktemp+rename으로 교체한다. kernel boot_id와 pending/failed/complete·닫힌 step만 저장하며 실패 trap은 실패 사유를 보존한다.
고정 probe는 root 소유/권한/링크/크기192B·FD/이름 dev/ino/시간·현재 boot identity·정확한 단일 행을 검증한다. 낡은 boot/잘린 상태/metadata 이상은 boot_metadata_invalid·unknown이며 성공으로 바꾸지 않는다.
BOOT complete 이후에도 UID10001·non-sudo·cgroupv2·위임·worker 쓰기 권한·정확 subid·비중첩·host alias 제거를 다시 확인한다. 고정 성공 token과 observed boolean은 유지한다.
OsPrerequisites에 bootPhase/reason을 추가해 안전한 닫힌 진단만 제공한다. SSH255는 ssh_unavailable, 이전125/빈 stdout은 guard_unknown이다. 알려지지 않은 token/phase/사유 조합은 session 실패다. 원문 로그/계정/설정은 반환하지 않는다.
신규 useradd에만 -K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0을 넣는다. 정확231072:65536 검사·비중첩 검사·없을 때 append는 유지하며 기존 매핑이나 전역 login.defs는 덮어쓰지 않는다.
M1-116의 manpage 재조회2회 timeout으로 남은 대조는 기존 public cache만 사용했다. Ubuntu noble branch useradd와 upstream4.13 cache bytes가 같으며 -K 처리1374–1387→COUNT2504–2511→할당2666–2685 순서를 확인했다.
이는 자동 allocator에 의존하던 잠재 setup 문제를 제거하는 정적 근거다. 고정 image의 실제 계정/subid 상태나 마지막125의 원인은 확인하지 않았다. cloud-init/Lima 준비 순서는 M1-114 source 감사 범위다.
기존 assertion 변경은 BOOT 끝의 atomic complete/trap 해제와 추가 probe metadata에 맞춘 것이다. UID/guard·Stopped/신원/cleanup 거부·원 성공 token·30초/5초·16KiB 상한은 유지한다.
자체 테스트는 소유 Node mock의 닫힌 protocol과 script 계약·구문만 확인한다. guest root metadata/guard 실제 동작과 SDK proxy 제거 실측은 CPx10 승인 뒤 R9가 담당하며 VM/daemon/parser/target 실행은 없다. backend는 unavailable/verified=false다.
추가 assertion은 host.docker.internal 제거 패턴을 Docker 명령으로 오인하던 단어 검사 대신 명령 경계를 검사한다. Docker 실행·설치·eval 금지는 유지하며 alias 제거 자체도 확인한다. 최초 검증의 이 오탐2건과 진단 사유 cgroup_v2_missing의 숫자2 누락1건은 각각 수정 후 재검증한다.
수정 후 build·serial cleanup/pg-log/compat는70 pass·0 fail/skip다. root/worker-directory0777은 원본이 거부하고 격리된 검사 제거 mutation은 허용하는 차이를 확인했다. mutation은 폐기했고 host pin/배포 자산/Action과 승인된3함수 밖 기존 함수 본문은 불변이다. BOOT/probe는 sh -n만 수행했으며 실제 guest 실행 증거가 아니다.

### M1-124 / CPx10 N1~N3 및 후속 신뢰 setup 절차

boot 상태는 `/run/wakeio-m1-boot` root0700에만 둔다. relay `/run/wakeio-m1/relay.sock`과 분리하므로 relay 접근을 위해 boot 경로 권한을 바꾸지 않는다.
`complete:none`은 현재 source-free OS guard 완료만 뜻한다. Stopped profile의 마지막125는 미구현 backend 거부이며 실행 권한은 없다. 앞의 출력 폐기로 쓰이지 않던 trailer echo는 제거한다.
complete phase 실패 사유는 실제 probe의10개로 제한한다. bootstrap_failed/user_create_failed는 failed phase에서만 허용하고 complete 조합은 거부한다. 상태/행동을 넓히는 API는 추가하지 않는다.

아래는 후속 root 패킷과 보안 체크포인트에서 구현·실측할 순서다. 이번 패킷은 설치/다운로드/VM 실행을 하지 않는다. 각 단계 완료 전 source 빌드/target 실행은 금지다.
1. R9 Docker 자산 증거의 arm64/Noble Engine·CLI·rootless-extras29.9.2와 containerd2.1.5 네 deb를 후보로 검토한다. 크기/raw SHA는 측정됐지만 제품 pin 승격·Release/InRelease 서명 체인은 아직 승인/검증되지 않았다.
2. 별도 승인한 vendor key fingerprint로 signed Release→Packages→네 deb bytes를 검증한다. Ubuntu 의존 deb도 서명된 archive metadata와 고정 version/arch/size/SHA에 결속하고 서명 불명/혼합/교체는 거부한다. HTTPS나 기존 Packages SHA만으로 서명 검증을 대신하지 않는다.
3. UID 전용 VM의 실제 설치 package 버전/상태를 안전한 metadata로 먼저 확인한다. uidmap/newuidmap/newgidmap·dbus-user-session·iptables/nftables·libseccomp2·AppArmor/rootlesskit 조건 등 미측정 의존성 pin과 bytes를 R9가 채우기 전 설치를 시작하지 않는다.
4. 소유 VM 안에서만 패키지 lifecycle 전에 rootful docker.service/docker.socket/containerd.service의 자동 시작을 막고 사후 비활성/비실행을 확인한다. VM 전용 policy-rc.d·unit mask의 소유/복원 범위를 lease에 묶고 host/Desktop의 전역 설정은 건드리지 않는다.
5. 검증된 패키지 bytes만 전달해 고정 trusted 설치 절차를 실행한다. source/host credential/env/agent/mount는 전달하지 않는다. maintainer script·설치 부작용의 허용 범위와 실패 rollback은 별도 보안 검토 대상이다.
6. UID10001·정확 subid·non-sudo·systemd user/cgroupv2 위임을 다시 검사한 뒤 전용 user unit으로 rootless daemon만 시작한다. 고정 executable/config·private 데이터/runtime/socket과 실제 rootless SecurityOptions를 lease에 결속한다. rootful이나 단순 non-root를 rootless로 표시하지 않는다.
7. private relay를 별도 경로에 구성한다. 관리 SSH 사용자 traversal과 socket 소유/권한·peer identity를 확인하되 root0700 boot 경로는 유지한다. controller의 고정 argv/대상 allowlist·bounded stdio만 공개하며 Target에 임의 Docker API나 socket 권한을 주지 않는다.
8. 실제 cpu/memory/pids 제한·seccomp·rootless 정보를 daemon/container/cgroup probe로 대조하고 IPv4/IPv6 direct IP·DNS·metadata·host gateway·CONNECT/redirect 우회를 거부하는 egress datapath를 실측한다. canonical Maven 정책 함수나 proxy env 설정은 강제 증거가 아니다.
9. 자산·daemon·자원·egress·relay 장벽이 모두 맞고 R9가 독립 검증하기 전 backend는 unavailable/verified=false다. 온라인 Maven allowlist의 정상 fetch와 금지 경로 차단을 함께 증명하며 offline cache만으로 지원 범위를 축소하지 않는다.
10. 기존30초 session·5초 probe·16KiB·전체 deadline/abort·별도 bounded cleanup을 늘리지 않는다. 이 한도에 준비 단계를 담지 못하면 unavailable로 중단하고 후속 설계 검토를 요청한다. 종료/실패는 소유 process group·Stopped/부재·임시 자산 정리를 확인하며 불명은 sticky다.

남은 미정은 Ubuntu 의존성/선택 network driver·AppArmor bytes와 pin, 실제 guest package 상태, vendor signature key/chain과 설치 lifecycle 범위다. 기존 Docker bytes 측정을 설치 성공·rootless/egress 실측으로 바꾸지 않는다.

### M1-126 / sudo 전체 목록의 의미와 non-sudo guard

f18의 failed:sudo_allowed는 실제 닫힌 관측이다. 그 시점의 guard는 exit0만 보았으므로 실제 sudo 권한 존재를 확정하는 근거가 아니다.
공식 [display.c526–542](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/display.c#L526-L542)는 grant count0에도 정확한 no-grants 행을 출력하고 true를 반환한다. [sudoers.c963–971](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/sudoers.c#L963-L971)와 [policy.c1296–1302](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/policy.c#L1296-L1302)은 명령 없는 목록을 그 경로로 보낸다.
BOOT/probe 공통 non_sudo는 root·LC_ALL=C에서 전체 `sudo -n -l -U wakeio-m1`을 한 번만 조회한다. 특정 명령의 거부를 전체 무권한으로 해석하지 않는다.
확인된 short hostname은 단일 ASCII label·1~63자로 제한한다. hostname/list stream은80/513B로 먼저 잘라 메모리에만 담고 제어/NUL/non-ASCII를 불일치 문자로 바꾼다. 정확한 한 행·원래 개행·exit0 marker까지 같을 때만 허용한다.
전체 조회는 고정1초 timeout 안에서 수행한다. grant 목록·Defaults/추가 행·stderr 오류·nonzero·언어/plugin 표현 차이·잘림은 모두 non-sudo 입증 실패다. 원문 출력·hostname·자격정보를 파일/보고서/로그에 저장하지 않는다.
임의 plugin을 인증하는 범용 sudo 분석기가 아니며 승인된 source-free OS/sudoers 문법만 지원한다. backend·daemon·target 권한은 계속 unavailable이고 UID/subid·boot metadata·신원·cleanup·30초/5초·16KiB 조건은 그대로다.
자체 테스트는 공통 함수의 소유 shell fixture와 고정 Node 정책 mock만 실행한다. 실제 host root/sudo/hostname/계정 명령·guest/VM/target 실행은 없으며 실제 재측정은 후속 R9 담당이다.
M1-124는 자체 npm ci/build와 serial cleanup/compat62 pass, M1-126은 build와 같은 검증64 pass이며 fail/skip0이다. 소유 mock 검증이며 실제 sudo policy·guest/daemon/egress 성공을 뜻하지 않는다.

### M1-134 / CPx11 N3 및 source-free OS inventory

`OsPrerequisites.reason=sudo_allowed`는 **non-sudo 입증 실패이며 권한 존재 확정이 아니다**. non-root/hostname/명령 부재·timeout·정책/문법 불명도 같은 실패 사유에 포함된다. R9는 이 enum만으로 권한을 확정하지 않는다.
현재672 source-free 실측은 고정 probe observed=true와 정상 소유 cleanup을 얻었다. 이 사실은 daemon/resource/egress/backend 검증이나 새 inventory의 실제 성공을 뜻하지 않는다.
frozen capability는 고정 `inventory()`만 추가한다. 같은 현재 session의 성공한 probe 뒤, 활성 job이 없고 deadline/신원이 유효할 때만 허용한다. 사전·동시·종료/지연 호출과 인수는 guest I/O 전에 거부하며 guard 성공을 inventory로 대체하지 않는다.
고정 sudo/env-i argv는 release의 ID/VERSION_ID·uname arch와 allowlist22개의 dpkg-query 상태/version만 읽는다. OS 파일은 data로만 검사하고 source/eval하지 않는다. 계정/hostname/env/credential·apt/설치/네트워크 조회는 없다.
wire는 ubuntu24.04·VM pin과 같은 arch header, 고정 순서22행과 end22만 허용한다. row 상태는 dpkg의8개 상태 또는 missing이며 버전은 안전 ASCII128B 이하다. 제어문자·중복/추가/누락/잘림·다른 release/arch는 unknown이다.
누락은 C locale의 정확한 dpkg-query no-packages 오류 한 행·exit1 marker일 때만 missing으로 만든다. 다른 오류를 누락으로 추측하지 않는다. 개별 query는513B로 먼저 제한하고 전체 결과는16KiB 내에서 검증한다. 원문 오류/설정/부분 결과는 반환하지 않는다.
각 호출5초·기존 session30초·16KiB·최소 env·신원 전후 대조와 소유 cleanup을 유지한다. identity/transport 손실은 capability를 닫고 unknown으로 처리하며 정리 불명은 sticky다. 모든 inventory는 backendVerified=false다.
설치 상태/version은 의존 pin 선정용 metadata다. 독립 서명/bytes 검증과 후속 실행 승인을 대신하지 않으며 source/daemon/target 실행 권한은 없다. 이번 자체 검증은 owned Node mock뿐이며 새 capability의 실제 source-free 성공은 별도 승인 뒤 R9가 측정한다.
자체 npm ci/build와 serial cleanup/compat68 pass·fail/skip0을 확인했다. dpkg exit2를 missing으로 합치지 않도록 마지막 script 상태 보존을 보완하고 그 고정 script의 owned query fixture1 pass를 추가 확인했다. 실제 OS/package 조회나 VM 실행 증거가 아니며 배포 자산/Action과 parser host pin은 불변이다.

### M1-147/148 / 서명된 package download 준비 (설치·daemon은 후속)

이번 구현은 패킷의 작은 세로 단위 허용에 따라 **download/prepare까지 partial**이다. no-download 설치, rootful autostart 차단/복원, UID10001 daemon, Unix peer/버전/rootless 관측, relay/resource/egress는 구현하지 않았다. 설치·daemon·source/target API는 없다.
R9 f6c 실제 inventory(manifest `4cd3d68efd3766364a55c1f5826c541be434cba4252407c1f6f0aec03a96503f`)는 Ubuntu24.04/aarch64·16 installed/6 missing이다. uidmap/slirp4netns와 Docker4개가 missing이며 나머지 버전은 해당 summary의 관측값이다. 설치 성공으로 해석하지 않는다.
독립 host 상수는 Engine/CLI/extras `5:29.9.2-1~ubuntu.24.04~noble`의 기존 bytes/SHA와 containerd `2.4.2-3~ubuntu.24.04~noble`·19561964B·SHA7837470e586f0b5d228a5eefdd9674b6bd0f127c47841ae808b086ae7fe3f41a로 고정한다. 이전2.1.5 후보를 승격하지 않는다.
Docker key는3817B·SHA1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570·fingerprint9DC858229FC7DD38854AE2D88D81803C0EBFCD88이다. raw key SHA를 다시 대조하고 APT가 그 별도 signed-by key로 서명을 검증한다. fingerprint 문자열만으로 인증하지 않는다. R9의 실제 서명 검증은 부모 key의 독립 offline 인증이나 재현 build를 뜻하지 않는다.
`withLimaRootlessSetup`는 기존30초 OS session과 분리된 내부 준비 경로다. 고정300초(전체 caller deadline·기존600000ms tool hard cap 이하)이며 임의 timeout/명령/경로/origin/pin 인수는 받지 않는다. 같은 private HOME/rootfs/config/VZ/positive PID/binary·동의 첫 own-descriptor·sticky cleanup을 재사용한다. 일반 probe/inventory는5초·16KiB 그대로다.
frozen `preparePackages()`는 현재 session의 실제 고정 probe observed=true 이후만 허용한다. active/lifetime/deadline/abort를 I/O 전에 검사하고, 새 OS guard 및 신원을 전후 재검사한다. 사전·동시·late/인수 호출은 새 I/O 없이 거부한다. 일반 OS capability는 여전히 probe/inventory 두 개뿐이다.
고정 Python은 source-free 소유 guest에서만 실행한다. HTTPS Docker/Ubuntu ports3개 suite와 별도 key·image archive keyring을 사용한다. private APT_CONFIG가 먼저 로드되어 기존 parts/main/sources/trust/proxy/hook 설정을 상속하지 않는다. redirect·비인증/약한/만료/비보안 fallback은 허용하지 않는다.
APT의 표준 resolver와 `Version.fetch_binary(...allow_unauthenticated=False)`만 사용한다. 선택된 trusted origin·version/arch/size/SHA를 검사하고 Docker4개의 독립 pin을 대조한다. Ubuntu transitive 버전을 만들거나 자체 dependency resolver를 두지 않는다. 선택48개·개별128MiB·전체512MiB·metadata16KiB 상한이다.
[APT_CONFIG 순서](https://manpages.ubuntu.com/manpages/noble/man5/apt.conf.5.html), [공식 python-apt download API](https://apt-team.pages.debian.net/python-apt/library/apt.package.html#apt.package.Version.fetch_binary), [Cache resolver](https://apt-team.pages.debian.net/python-apt/library/apt.cache.html)를 따른다. guest python3-apt의 설치/지원 API는 아직 미측정이며 없으면 닫힌 실패다. 준비를 위해 추가 package를 먼저 설치하지 않는다.
APT acquisition은 root0700 private cache 안에서 trusted setup의 root로만 실행한다(`APT::Sandbox::User=root`). 이는 target sandbox/rootless 검증이 아니며 source·host 비밀·mount·forwarding은 없다. 공개 서명 metadata/key/deb 다운로드만 허용하는 준비 단계이고 raw daemon socket은 없다.
root0700 staging과 root-owned 안정 FD 검증을 유지하려고 acquire를 root로 실행하여 `_apt`의 권한 분리 방어를 끄는 실제 trade-off를 수용한다. 이는 source-free 폐기 VM의 download-only 단계에 한정되며 rootless 실행 준비나 완전 격리를 뜻하지 않는다.
선택 manifest는 실제 deb bytes 해시, 전후 동일한 signed APT index 목록의 raw SHA·크기 manifest digest, 전후 동일한 dpkg status digest를 묶어 guest0600에 저장한다. 반환은 닫힌 package metadata·digest뿐이며 lifecycle 원문/키/환경/계정/credential은 없다. 링크·owner/nlink/권한·FD/name identity·크기/시간/교체도 검사한다.
cache와 manifest는 현재 소유 VM 안에만 있고 정상 종료 시 VM과 함께 제거한다. host에는 허용 metadata를 toolchain input으로 남길 수 있다. JSON/복제/직접 parser 호출 결과는 실행 capability가 아니다. 모든 결과는 backendVerified=false·sourceExecutionAuthorized=false·daemonObserved=false다.
실패/한도/abort/신원 불명은 unknown/failed이며 scope를 닫는다. 소유 foreground PGID 종료→strict Stopped→SDK delete/부재 확인만 사용하고 불명은 sticky다. 일반 Stopped/버전/신원 거부와 별도 bounded cleanup은 완화하지 않는다. trusted 비동기 callback의 동기 무한 루프 선점 한계도 기존과 같다.
후속 설치는 이 manifest·cache·현재 신원을 다시 검증하고 no-download로만 진행해야 한다. 먼저 소유 policy-rc.d와 docker.service/docker.socket/containerd.service mask의 배타 생성·사후 비활성 검증을 구현해야 하며, 기존 파일/unit의 소유가 모호하면 거부한다. 아직 해당 설치 함수가 없어 autostart 순서의 실제 검증도 없다.
자체 npm ci ignore-scripts/build·cleanup/compose/compat 직렬90 pass·fail/skip0, 고정 Python AST 구문 검사와120/60을 확인했다. 초기 길이 검사4행은 줄바꿈으로 수정했다. mock은 guard/pin/서명 실패 metadata·한도·consent/lifetime/abort·sticky cleanup만 검증하며 실제 APT/VM/설치/daemon/네트워크 실행은0이다. 실제 download 준비 성공과 python-apt/의존 package·AppArmor/driver 지원은 승인 후 R9 과제다.

### M1-154 / 준비 실패의 닫힌 단계 진단

Python은 각 작업 전에 prerequisites/key/apt-config/index-update/index-snapshot/selection/download/digest/state-recheck/manifest 중 고정 stage를 설정한다. 실패는 `wakeio-rootless-packages-failure/v1:STAGE:operation_failed` 단일 행·exit125뿐이며 exception/message·APT 원문·URL 응답·키·환경·계정은 포함하지 않는다. stage는 실패한 작업 위치이며 암호 검증 실패 등 실제 원인의 확정이 아니다.
parent는 정상 종료된 소유 group/close·현재 신원·exit125·stderr 비어 있음·128B 이내 정확한 token/known stage가 모두 맞을 때만 unknown/operation_failed와 failureStage를 보존한다. signatureVerified/download_prepared/권한으로 승격하지 않는다. 성공 wire와 독립 pins는 그대로다.
unknown/extra/잘림·다른 exit·timeout/output cap/abort·정리/신원 불명은 stage를 신뢰하지 않고 기존 실패 경로로 닫힌다. 이전 테스트의 garbage exit125 기대만 prepare_unavailable에서 더 엄격한 invalid_metadata로 바꿨으며 실패/권한 false·sticky cleanup 기준은 유지했다.
자체 fixture는 prepare를 호출하지 않고 마지막 failure encoder에 합성 예외만 주입한다. 실제 apt/OS/VM·다운로드·설치·daemon 실행은 없다. 40efd의90 pass는 그 원래 코드의 결과이며 이번 결과와 구별한다. 설치 미완료·python3-apt/API 미측정·OS30초/읽기5초/16KiB·setup300초는 그대로다.
이번 build·cleanup/compose/compat 직렬93 pass·fail/skip0과120/60·diff-check를 통과했다. 최초 길이 검사3행은 의미 불변 줄바꿈으로 수정했으며 Docker/key 독립 pin AST와 배포 자산/Action은 불변이다. fixture가 실제 apt/다운로드 성공을 증명하지 않는다.

### M1-167 / index 세부 진단과 fdopen 소유권

기존10stage·stage-only failure wire를 유지하고 index-snapshot/state-recheck에만 optional failureDetail을 추가한다. list-io/name/kind/type/owner/links/mode/size/read/consistency/count/repo-presence를 닫힌 index-* token으로 구분한다. kind는 기존 허용 조건에서 실패한 이름의 `_Translation-` 표식 유무만 translation/other로 분류하며 파일명·경로·UID·본문·예외는 반환하지 않는다.
기존 InRelease/_Packages 종류·ASCII 이름·root owner/regular/nlink1/쓰기권한·크기/안정 FD/이름·개수/repo 존재·서명/origin/hash 조건은 그대로다. 성공 wire·index/status digest 구성과128B failure/16KiB 출력·300초setup/30초OS/5초read·신원/cleanup·false authority도 유지한다. 알 수 없는 detail이나 다른 stage와의 조합·추가/잘린 token은 거부한다.
세부 진단은 실패한 조건 위치만 나타낸다. acdb 실제 원인이나 Translation 실재·서명 성공·설치/실행 권한을 확정하지 않는다. 이번에는 Acquire::Languages나 종류 허용 범위를 바꾸지 않으며 실제 고정 cycle 재측정은 다음 CPx 승인 후 R9가 담당한다.
write_new는 fdopen 생성 실패 때만 원시 fd를 닫고 재던진다. stream 생성 뒤에는 context가 정상/쓰기 예외 모두 닫는다. 소유 합성 fixture는 filesystem/package/network 접근 없이 각 index guard 및 이 세 FD 경로와 원문 오류 비출력을 검증한다. 설치/daemon/target/VM/다운로드 실행은 없다.
자체 build·cleanup/compat 직렬80 pass·fail/skip0, Python AST/소유 guard·FD fixture·120/60·diff-check를 확인했다. 초기121자 footer 한 행은 줄바꿈으로 수정했다. 독립 pins·성공 wire parser AST와 생성물은 불변이며 이 결과는 실제 index 상태나 prepare 성공의 증거가 아니다.

### M1-181 / CPx15 N2의 상세 실패 보존

index guard가 구체 failureDetail을 기록한 뒤 close의 OSError가 겹쳐도 index_file은 이를 index-read로 덮어쓰지 않는다. detail이 비어 있는 단독 read/close 실패만 index-read를 기록한다. 소유 fixture는 owner guard ValueError→close OSError의 실제 예외 연결·기존 index-owner 보존과 단독 read/close의 index-read·원문 오류 비출력을 확인한다. wire/pins/guard/Acquire 설정·상한·신원/cleanup·false authority와 실제 prepare 실패 원인은 바꾸지 않는다. 실제 VM/prepare/download/설치/daemon/target 실행은 없다.

### M1-183 / 선택적 Translation acquisition 중지

R9 M1-180(manifest78f14e7127d2efc4fdc57362c9bd8b7897a5b03082ceedc6790de672fa617101)은 unknown/index-snapshot/index-kind-translation·package0·세 권한false와 정상 소유cleanup을 관측했다. SDK list652frame 중 parse failure1건의 원래 frame·구체 파일명/내용·SDK 원인은 미확인이다.
표준 [Acquire::Languages=none](https://manpages.ubuntu.com/manpages/noble/man5/apt.conf.5.html)을 고정 private config에 추가해 불필요한 번역 index acquisition을 중지한다. InRelease/package 서명·후보 selection/bytes·기존 unexpected-kind 거부/진단·FD/digest/pins/상한/cleanup은 유지한다. 파일 무시/삭제 fallback이나 종류 허용 확대는 없다.
소유 AST fixture는 apt_config를 mock filesystem/env/key로 실행해 실제 생성된 Languages=none, signed-by가 포함된 고정 HTTPS source4행, 인증/redirect/trust 설정과 부모 env 비상속을 검증한다. APT/서명 검증/네트워크의 실제 성공을 뜻하지 않으며 다음 CPx16 승인 후 R9가 새 prepare를 한 번 측정한다. M1-181의 복합 실패 detail 보존도 유지한다.

M1-183의 첫 cleanup/compat 검증은80 pass·1 fail였고 진단 재현도 exit1이었다. 둘 다 새 fixture key 정규식의 underscore 누락으로 기존 Dir::State::extended_states를 파싱하지 못한 helper 문법 오류이며 실제 APT/prepare 실패와 구분한다. M1-185는 underscore만 추가하고 생성 옵션 전체 집합/값의 정확한 동등 비교로 검증을 강화했다. 제품 설정이나 기대 값을 실패에 맞춰 바꾸지 않았다.
M1-185 재검증은 자체 build·cleanup/compat 직렬81 pass·fail/skip0이다. AST 소유 fixture의 전체32개 생성 옵션/값·source4행·부모 env 비상속과 M1-181의 겹친 오류/단독 read·close 보존도 통과했다. 120/60·diff-check 및 제품 코드가 M1-181에 Languages=none 한 줄만 추가된 것임을 확인했다. 실제 prepare 성공은 아직 미측정이다.
