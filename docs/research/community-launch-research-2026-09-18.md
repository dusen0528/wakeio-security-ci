# 커뮤니티 출시 조사 — 2026-09-18

읽기 전용 조사다. 외부 게시, DM, 광고, 계정 생성은 하지 않았다. Luna가 커뮤니티 조사 결과를 전달했고 부모가 핵심 공식 페이지를 독립 확인해 아래 기록과 [실행안](../community-launch-plan-2026-09-18.md)을 정리했다. 공개 규칙을 확인한 것이며 특정 계정의 게시 가능 여부나 게시물 승인까지 검증한 것은 아니다.

## 확인한 규칙과 제안

| 채널 | 확인한 사실 | Wakeio 적용 제안 |
| --- | --- | --- |
| r/SideProject | 프로젝트 공유·건설적 피드백 공간이며 프로젝트 링크에 프로젝트명 - 짧은 설명 형식을 안내한다. [사이드바](https://www.reddit.com/r/SideProject/about/sidebar/) | 1차 해외 후보. 실제 CI와 보고서를 보여 준다. 사이드바에 없는 AI 정책·자동필터 허용을 추정하지 않는다. |
| GeekNews Show GN | 본인 또는 소속 조직의 도구는 뉴스가 아닌 Show로 등록. 사용 가능한 작업물이어야 하고 반복 배포를 제한한다. 가입 후 뉴스 링크 등록까지 일주일 제한 안내, 본문 이미지 미지원, Show의 YouTube 링크 금지가 있다. [이용법](https://news.hada.io/guidelines) | 1차 국내 후보. GitHub를 직접 연결하고 GIF는 README에 둔다. 신규 계정의 실제 Show 등록 조건을 게시 화면에서 확인한다. |
| r/opensource | LICENSE에 OSI 목록 라이선스 필요, 프로젝트 공유에 Promotional flair 사용, 과도한 자기 홍보·일회성 링크 투척 제한. AI 생성 콘텐츠는 금지한다. [규칙](https://www.reddit.com/r/opensource/about/) | Apache-2.0이라는 이유만으로 게시 허용을 단정할 수 없다. AI 보조 저장소에 대한 적용 범위가 불명확해 1차 계획에서 제외한다. |
| r/webdev | Showoff Saturday에 프로젝트 소개와 피드백을 한정한다. 상업 홍보를 금지하고, LLM 생성 글·댓글을 저품질 콘텐츠로 분류한다. [규칙](https://www.reddit.com/r/webdev/about/) | 조건부 후속 후보. 기술적 작업을 제작자가 직접 설명한다. AI 소개 초안을 복사하는 경로로 쓰지 않는다. |
| r/nextjs | Next.js 자체에 관련된 글이어야 한다. 프로젝트 소개는 weekly show-and-tell로 안내한다. [규칙](https://www.reddit.com/r/nextjs/about/) | Next client/env/import 합성 데모를 준비한 뒤 주간 글에 소개하는 후속 후보. 독립적인 홍보 글을 올리는 경로가 아니다. |

위 순위와 적합성은 제품 기능을 기준으로 한 판단이다. 유입량, 별 수, 승인 가능성을 보장하지 않는다. Reddit의 반복적 대량 홍보·원치 않는 참여·스팸 자동화를 피한다. 보편적인 고정 karma 기준을 추정하지 않는다. [Reddit 공식 스팸 정책](https://support.reddithelp.com/hc/en-us/articles/360043504051-Spam)

## 후순위 채널

HN은 실행 가능한 작업물, 제작자의 설명과 참여를 요구한다. 현재 Show HN 임시 제한 공지가 있고 AI가 생성하거나 편집한 글을 금지한다. 본 실행안의 AI 초안을 HN에 게시하지 않는다. [Show HN](https://news.ycombinator.com/showhn.html), [제한 공지](https://news.ycombinator.com/showlim), [가이드라인](https://news.ycombinator.com/newsguidelines.html)

DEV는 충분한 본문과 기술적 가치를 요구하고 홍보·백링크 중심 콘텐츠를 제한한다. AI 보조 글은 고지와 사실 확인 요구가 있으며, AI 가이드는 본인의 사업·프로그램·강좌 홍보도 금지한다. 따라서 이번 AI 소개 초안의 배포 대상에서 제외한다. [약관](https://dev.to/terms), [AI 가이드](https://dev.to/guidelines-for-ai-assisted-articles-on-dev)

Disquiet와 OKKY도 조사 후보였지만, 이 기록에서 직접 확정할 수 있는 최신 게시 경로·허용 범위가 충분하지 않아 1차 채널로 추천하지 않는다. 플랫폼 전체 약관만으로 특정 게시판의 홍보 허용을 추정하지 않는다.

## 제품 사실과 지표

공개 저장소와 현재 README, Action 실행 경로를 2026-09-18 확인했다. 무료 로컬/CI 도구, Apache-2.0, 소스·URL·명시적 GET API 정책, 선택형 외부 엔진, Markdown/JSON/SARIF와 검사 한계를 소개할 수 있다. npm 조회는 E404였고 GitHub Release는 없었다. [공개 README](https://github.com/dusen0528/wakeio-security-ci)

GitHub Traffic은 최근 14일 방문·full clone 등의 지표를 제공한다. 조회·clone은 설치 완료 사용자 수가 아니다. [GitHub 문서](https://docs.github.com/en/repositories/viewing-activity-and-data-for-your-repository/viewing-traffic-to-a-repository)

npm 배포 뒤에는 기간별 다운로드 API를 사용할 수 있다. 현재 Action은 미리 빌드한 bundle을 실행하므로 npm 패키지 다운로드가 발생하지 않는다. 따라서 Action 사용량을 npm 다운로드 수로 추정하지 않는다. [npm API](https://github.com/npm/registry/blob/main/docs/download-counts.md), [현재 실행 코드](../../scripts/action-run.mjs)
