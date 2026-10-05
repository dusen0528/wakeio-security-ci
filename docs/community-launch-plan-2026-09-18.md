# Wakeio Security CI 커뮤니티 출시 계획

작성일: 2026-09-18. 전략 제안과 소개문 초안이다. 실제 게시, DM, 광고 집행, npm 등록은 수행하지 않았다. 커뮤니티별 확인 사실과 불확실한 규칙은 [조사 기록](research/community-launch-research-2026-09-18.md)에 구분한다.

## 제안하는 첫 메시지

**계정이나 소스 업로드 없이, 코드와 배포 URL의 흔한 보안 실수를 CI에서 점검하는 무료 오픈소스.**

핵심 장면은 개발자가 자기 저장소에서 workflow를 추가하고, 위험 후보의 위치와 수정 방향을 확인하는 것이다. 소스가 없으면 지정한 공개 URL의 응답을 점검할 수 있다. 검사하지 못한 항목도 보고서에 남는다.

- 바이브코더·개인 개발자: 출시 전에 무엇을 점검할지 모르는 상황에서 시작한다. 처음부터 모든 검사 용어를 나열하지 않는다.
- Next.js/React·Supabase 사용자: 공개 환경변수, 제한된 client import, RLS migration의 실제 합성 예시를 보여 준다. 실제 DB 권한까지 자동 검증했다는 표현은 쓰지 않는다.
- Node/Python·API 개발자: 내장 JS/TS, 선택 Bandit 및 Gitleaks/OSV/Trivy, 명시적 GET 권한 정책을 구분한다. API 계정과 기대 권한은 사용자가 준비한다.

홍보 문구로 쓸 수 있는 사실은 무료 Apache-2.0, 로컬/CI 실행, 계정·LLM 키·소스 업로드 불필요, 소스·URL 입력, Markdown/JSON/SARIF 보고서다. 이 도구를 완전한 침투 테스트, 자동 결제·관리자 검사, 보안 인증, 운영 탐지율 보장으로 소개하지 않는다. 144개 테스트는 구현 검증이며 정확도 수치가 아니다. [현재 기능과 실행법](../README.ko.md)

## 첫 공개 전에 준비할 최소 자료

현재 공개 GitHub 저장소와 네 언어 README, 실행 가능한 Action은 있다. 다음 항목은 제안이며 이 문서를 작성하면서 새로 제작하거나 공개하지 않았다.

1. **30~45초 실행 영상 또는 GIF 하나.** 합성 취약 코드 → CI 실행 → 보고서의 파일/규칙/수정 방향 → 수정 후 같은 검사에서 해당 발견이 사라지는 흐름. 실제 고객 소스와 키를 쓰지 않는다.
2. **완성된 보고서 예시 하나.** 실제 도구가 생성한 합성 결과를 사용하고, 어떤 항목을 확인하지 못했는지도 보이게 한다.
3. **바로 실행할 예제 저장소 또는 명확한 데모 안내.** 우선 기존 합성 fixture와 [workflow 예제](../examples/github-action.yml)를 재사용한다. 새 데모 저장소의 존재를 미리 광고하지 않는다.
4. **고정된 preview 배포 지점.** 검토한 Action commit SHA와 버전을 안내하고, npm 배포를 완료한 뒤에만 실제 registry 설치 명령을 홍보한다. 현재 로컬 package 이름은 공개 registry 등록과 다르다.

첫 영상은 한 가지 문제만 보여 준다. 예를 들어 SQL 문자열 연결을 지원되는 parameter binding으로 바꾸고 동일 규칙 결과를 대조한다. 별도의 짧은 설명에서 엔진 누락은 exit 2라는 점을 보여 줄 수 있다. 전체 애플리케이션이 안전해졌다는 자막은 쓰지 않는다.

## 우선 채널과 소개 방식

2026-09-18 확인한 공개 안내를 바탕으로 한 제안이다. 실제 게시 화면의 최신 규칙과 계정 제한이 우선한다.

| 순서 | 채널 | 소개할 장면과 확인 조건 |
| --- | --- | --- |
| 1 | GeekNews Show GN | GitHub 저장소를 연결하고 제작 배경·작동하는 검사·한계를 설명한다. 본인 도구는 뉴스가 아닌 Show로 등록해야 한다. GIF는 저장소에 두고 글에서 연결한다. GN 본문은 이미지를 지원하지 않으며 YouTube 링크를 Show로 등록할 수 없다. 신규 가입자는 뉴스 링크 등록까지 일주일 제한 안내도 확인한다. [공식 이용법](https://news.hada.io/guidelines) |
| 1 | Reddit r/SideProject | 개인 프로젝트에 workflow를 추가하고 보고서를 확인하는 장면. 프로젝트 링크 제목은 `Wakeio Security CI - Free source and public URL checks for CI`처럼 프로젝트명과 짧은 설명 형식으로 한다. 피드백 공유 공간이라는 점은 확인했지만, 사이드바만으로 모든 자동필터나 AI 콘텐츠 허용을 확정하지 않는다. [공식 사이드바](https://www.reddit.com/r/SideProject/about/sidebar/) |
| 2 | Reddit r/nextjs | Next client 환경변수/import 검사에 대한 실제 합성 데모를 준비한 뒤 weekly show-and-tell에 소개한다. 독립적인 제품 홍보 글은 올리지 않는다. [공식 규칙](https://www.reddit.com/r/nextjs/about/) |
| 조건부 | Reddit r/webdev | Showoff Saturday에 기술적 구현과 실행 예시를 제작자가 직접 작성한다. 상업 홍보와 LLM 생성 글·댓글 제한이 있어 아래 AI 초안을 그대로 올리는 대상이 아니다. [공식 규칙](https://www.reddit.com/r/webdev/about/) |
| 후순위 | Hacker News Show HN | 설치 피드백과 데모가 준비된 뒤, 게시 가능한 계정에서 제작자가 직접 글을 작성한다. 현재 제한과 AI 문장 금지는 다음 절에 기록했다. |

r/opensource는 OSI 라이선스와 Promotional flair를 요구하고 과도한 자기 홍보를 제한한다. 또한 AI 생성 콘텐츠를 금지한다. 이 문구가 AI 보조로 개발한 저장소까지 어떻게 적용되는지는 공개 규칙만으로 확정할 수 없으므로, 우리 AI 소개문을 게시하거나 허용된다고 단정하는 경로에서 제외한다. [공식 규칙](https://www.reddit.com/r/opensource/about/)

Disquiet와 OKKY는 이번 조사에서 자유로운 OSS 홍보를 보장하는 구체적인 게시 경로·규칙을 충분히 확인하지 못했다. 1차 일정에 넣지 않고 별도 확인 후보로 남긴다. 국내 첫 채널은 확인된 Show GN에 집중한다.

## 채널 운영 원칙

채널의 우선순위는 제품과 독자의 적합성에 대한 제안이지 유입량 예측이 아니다. 첫 회에는 국내 한 곳과 Reddit 한 곳으로 범위를 좁히고 실제 설치 피드백을 반영한다. 같은 글을 여러 곳에 일괄 게시하지 않는다.

- 국내 개발자 커뮤니티에는 제작자가 직접 소개하고, 어떤 문제를 다루며 설치 뒤 어떤 보고서가 생기는지 설명한다.
- Reddit에는 자신이 제작자라는 점을 공개하고, 해당 subreddit에서 허용하는 self-promotion 형식·요일·flair를 따른다. 관련 있는 사례를 본문에서 설명하며 GitHub 링크는 보조로 둔다.
- 댓글에서는 사용자의 스택, 실패한 명령, 익명화한 오류를 먼저 확인한다. 계정 키나 고객 저장소 업로드를 요청하지 않는다.
- 별점·추천 교환, 가짜 사용자 후기, 대량 DM, 자동 댓글은 운영 방식에 포함하지 않는다. Reddit은 반복적 대량 노출과 원치 않는 자동·수동 참여를 스팸으로 본다. [Reddit 공식 정책](https://support.reddithelp.com/hc/en-us/articles/360043504051-Spam)

## Hacker News와 DEV의 추가 조건

Show HN은 실제로 사용해 볼 수 있고 제작자가 설명할 수 있는 작업을 요구한다. 가입 없이 실행할 수 있는 공개 저장소는 형식상 적합하지만, 현재 Show HN 임시 제한 공지가 있어 계정의 게시 가능 여부를 미리 확인해야 한다. 공식적인 최소 karma 수치는 확인하지 않았다. [Show HN](https://news.ycombinator.com/showhn.html), [제한 공지](https://news.ycombinator.com/showlim)

HN은 AI가 생성하거나 편집한 글을 게시하지 말라는 규칙이 있다. 이 문서의 한·영 초안을 HN에 복사하거나 AI로 HN 최종 게시문을 다듬는 경로를 권하지 않는다. 제작자가 실제 개발 경험과 자신이 답할 수 있는 설계 선택을 직접 작성한다. 추천·댓글 동원도 하지 않는다. [HN 가이드라인](https://news.ycombinator.com/newsguidelines.html)

DEV는 본문 자체에 충분한 기술 내용이 있어야 하며 홍보·백링크 중심 글을 제한한다. AI 보조 글에는 고지 요구가 있고, 해당 AI 가이드는 자신의 것을 포함한 사업·프로그램·강좌 홍보를 금지한다. 따라서 이 AI 초안을 DEV 홍보 글로 재사용하지 않는다. 후속 후보는 제작자가 직접 수행한 실험과 코드를 바탕으로 쓰는 기술 글이며 해당 규칙을 다시 확인한다. [DEV 약관](https://dev.to/terms), [AI 가이드](https://dev.to/guidelines-for-ai-assisted-articles-on-dev)

## 2주 실행 순서 제안

아래 날짜는 활동 순서를 뜻한다. 특정 요일의 홍보만 허용하는 커뮤니티는 그 일정에 맞춘다. 새 계정의 게시 제한을 우회하거나 활동량을 인위적으로 채우지 않는다.

| 시점 | 할 일 | 남길 결과 |
| --- | --- | --- |
| 1~2일 | 짧은 실제 데모, 샘플 보고서, 설치 안내와 preview 배포 상태 정리 | 게시물에서 바로 연결할 실행 자료 |
| 3일 | 국내 적합 채널 한 곳에 제작 배경과 실행 예시 소개 | 설치 성공/실패, 이해하기 어려운 문구 기록 |
| 4~5일 | 질문에 직접 응답하고 설치 장애·오경고 사례 재현 | 수정 또는 명시적인 미지원 범위 |
| 6~7일 | 규칙을 확인한 Reddit 한 곳에 영어 소개 | 개인 프로젝트에서의 실행 피드백 |
| 8~10일 | 필요한 경우 문제 하나를 깊게 설명하는 기술 글 제작 | 예: migration 파일에서 RLS를 어디까지 알 수 있는가 |
| 11~14일 | 초기 피드백을 반영한 뒤 두 번째 적합 커뮤니티 소개 | 다른 스택에서도 같은 실행 경로가 작동하는지 확인 |

첫 실험 목표는 **서로 다른 프로젝트 세 곳의 설치 피드백과 재현 가능한 개선 항목 한 건**으로 잡는다. 이는 제안한 운영 목표이며 예상 성과나 보장 수치가 아니다. 유료 광고는 이 초기 설치 흐름이 확인된 뒤에 검토한다.

## 한국어 소개 초안

아래 글은 본인 저장소·블로그 또는 AI 보조 소개문을 허용하는 채널을 위한 초안이다. 커뮤니티 규칙을 확인하고, 실제 동기와 데모 결과를 제작자가 확인한 뒤 사용한다. HN·DEV·r/webdev·r/opensource에 게시할 최종 문안이 아니다.

**제목: 코드와 배포 URL을 점검하는 무료 보안 CI 도구를 만들었습니다**

Wakeio Security CI를 공개했습니다. 개인 프로젝트를 배포하기 전에 흔한 보안 실수를 점검하고 싶은 개발자를 위한 오픈소스 CLI와 GitHub Action입니다.

계정이나 결제, LLM API 키 없이 실행할 수 있고, 소스코드는 자신의 컴퓨터 또는 CI runner에서 검사합니다. 코드가 없을 때는 지정한 공개 URL의 응답을 살펴볼 수 있습니다.

현재는 제한된 JS/TS 입력 흐름, Next.js·Supabase 관련 코드와 migration 후보, 공개 응답의 헤더·쿠키·JavaScript 등을 확인합니다. Gitleaks·OSV-Scanner·Trivy·Bandit도 선택해서 연결할 수 있습니다. API 권한 검사는 테스트 계정과 기대 결과를 명시한 GET 정책이 필요합니다.

결과는 Markdown·JSON·SARIF로 남습니다. 도구 누락이나 검사 실패도 별도로 표시합니다. 전체 취약점을 찾거나 실제 DB·클라우드 상태까지 확인하는 도구는 아니며, 현재는 개발 preview입니다.

처음 적용할 때 막히는 부분이나 수정된 코드에도 계속 나오는 경고가 있다면, 비밀값을 뺀 작은 재현 예시로 알려 주세요.

GitHub: https://github.com/dusen0528/wakeio-security-ci
한국어 설명: https://github.com/dusen0528/wakeio-security-ci/blob/main/README.ko.md

## English introduction draft

For the maintainer's own channels or a community that allows this form of AI-assisted project introduction, after checking that community's rules. Not a submission for HN, DEV, r/webdev, or r/opensource.

**Title: Wakeio Security CI - Free source and public URL checks for CI**

I built Wakeio Security CI for developers who want to check common security mistakes before releasing a side project. It is an Apache-2.0 CLI and GitHub Action that runs without a Wakeio account, an LLM key, or uploading your source to a hosted scanner.

It includes bounded JS/TS checks, selected Next.js and Supabase migration rules, and checks of explicitly selected public web responses. You can also enable Gitleaks, OSV-Scanner, Trivy, or Bandit. Read-only API authorization checks require your own test actors and explicit expected results.

The output is Markdown, JSON, and SARIF. Incomplete checks remain visible; missing tools and failed checks do not become a successful scan. It is a development preview with documented limits, including no general cross-function analysis or live database/cloud audit.

I would appreciate reproducible feedback on setup friction and false positives. A small synthetic example with credentials removed is enough.

Repository: https://github.com/dusen0528/wakeio-security-ci

## 지속해서 쓸 콘텐츠 주제

- Next.js에서 공개 환경변수와 서버 Secret을 구분할 때 확인할 것: 지원되는 정적 import 예시와 한계를 함께 제시.
- Supabase migration에서 RLS 누락 후보를 찾는 방법: SQL 파일의 선언과 live DB 상태 차이를 설명.
- 보안 검사에서 exit 0/1/2를 구분한 이유: 발견, 미완료, 검사 범위의 실제 보고서를 대조.
- Gitleaks·OSV·Trivy·Bandit 결과를 하나의 CI 보고서로 다루기: 엔진을 명확히 밝히고 설정·데이터 전송 범위 설명.

각 글은 실행 가능한 합성 코드, 결과, 수정 방향, 확인 범위로 구성한다. 공개 사이트를 무단 점검해서 홍보용 취약점 사례로 쓰지 않는다.

## 초기 반응 뒤의 확산

동일한 소개 글을 재게시하기보다, 실제로 자주 막힌 상황을 하나씩 해결하는 자료를 남긴다. 첫 적용 사례가 확보되면 해당 사용자의 공개 허락을 받은 범위에서 스택·실행 방법·수정한 문제와 남은 한계를 설명한다. 합성 예시를 실사용 후기처럼 표시하지 않는다.

지속 유입의 다음 후보는 Next.js·Supabase 등 starter/template의 선택형 CI 가이드다. 우선 우리 저장소에 최소 workflow 적용 예제를 만들고, 관련 프로젝트의 기여 지침에 맞는 경우에만 maintainer에게 제안할 수 있다. 같은 내용의 PR을 여러 저장소에 자동 생성하는 방식은 계획에 넣지 않는다. 이것은 후속 전략이며 이번 작업에서 외부 연락이나 PR을 만들지 않았다.

## 지표: 추가 추적 코드 없이 시작

2026-09-18 확인한 저장소는 공개 상태이며 GitHub Release는 없다. 같은 날 공개 npm registry의 `wakeio-security-ci` 조회는 E404였다. 아직 npm 배포 전이므로 npm 다운로드 수를 성과로 제시하지 않는다.

우선 채널별 게시일과 링크, GitHub 방문·clone·별 수 변화, 공개된 설치 피드백만 기록한다. GitHub Traffic은 최근 14일 방문과 full clone, 유입 사이트 등을 제공하므로 장기 비교가 필요하면 수동으로 주간 수치를 보관한다. 방문·clone을 실사용자나 설치 완료 수로 해석하지 않는다. [GitHub 공식 문서](https://docs.github.com/en/repositories/viewing-activity-and-data-for-your-repository/viewing-traffic-to-a-repository)

npm 배포 뒤에는 사용자가 원한 주간 다운로드 수를 주요 관찰 지표로 쓸 수 있다. npm은 기간별 패키지 다운로드 API를 제공한다. 다만 다운로드 수는 고유 사용자 수나 보안 검사 실행 수와 다르다. [npm 다운로드 API](https://github.com/npm/registry/blob/main/docs/download-counts.md)

**현재 GitHub Action은 저장소의 미리 빌드한 bundle을 실행하고 npm에서 이 패키지를 설치하지 않는다. 따라서 Action 경로의 사용량은 npm 다운로드 수에 포함되지 않는다.** 이는 현재 [action.yml](../action.yml)과 [실행 스크립트](../scripts/action-run.mjs)에서 확인한 배포 구조다. 숫자를 늘리기 위해 불필요한 npm 설치나 사용자 추적을 추가하지 않는다.
