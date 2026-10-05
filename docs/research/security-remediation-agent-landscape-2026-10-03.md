# Wakeio CI의 선택형 보안 에이전트·자동 수정 설계와 경쟁 조사

기준일: 2026-10-03 · 대상: wakeio-security-ci의 선택적 에이전트 호출 제품 방향

## 결론과 현재 기준

사용자가 선택한 Codex·Claude를 호출해 취약점 분석과 수정안을 생성하는 것은 가능하다. 추천은 **무료 결정론적 검사기 + 선택형 agent adapter + 실행기가 통제하는 수정 검증**이다. 취약점별 TOML 프로필은 이 구조에 적합하지만, 자연어 지침과 실제 권한·성공 조건을 분리해야 한다. 이 문서는 제안이며 새 아키텍처가 채택되거나 구현되었다는 기록은 아니다.

이번에 확인한 저장소는 `wakeio-security-ci`다. 다른 프로젝트의 결정 맥락을 이 저장소의 결정으로 옮겨 적용하지 않았다.

| 구분 | 이번 조회에서 확인한 내용 |
| --- | --- |
| 유지할 기준 | 기본 CLI·Action은 Wakeio 계정·구독·전용 서버·LLM token 없이 실행한다. 기본 소스 검사는 대상 script·build·test·hook을 실행하지 않는다. 원문 코드 전송을 기본으로 추가하지 않는다. |
| 현재 코드 | 제한된 정적 검사·외부 scanner·URL 관찰·GET 기반 API 권한 대조·JSON/SARIF/Markdown 보고·범위와 provenance에 따른 비교가 있다. 일반 CLI에는 agent·repair·apply 옵션이 없다. |
| 현재 실행 실험 | Schemathesis worker는 합성 WSGI fixture 범위다. 일반 대상 앱의 실행·live DAST·격리된 패치 검증을 제공한다고 확대하지 않는다. |
| 변경 제안의 이유 | 사용자가 원하는 목표가 발견·안내를 넘어 중요한 취약점의 패치이므로, 기존 검사 뒤에 수정 생성과 실제 수정 전후 검증을 추가해야 한다. |
| 확인 필요 | 실제 provider 인증·접근 권한·유료 호출, 대상 저장소의 실행 환경, 제공자 간 동일 테스트 결과, 자동 수정 성공률은 이번에 검증하지 않았다. |

근거 파일: [공개 OSS 요구](../session-requirements.md), [구현 계약](../implementation-contract.md), [CLI](../../src/cli.ts), [비교](../../src/compare.ts), [프로세스 경계](../../src/source/process.ts), [Schemathesis 범위](../schemathesis-fixture-worker.md). 파일 내용은 읽었지만 기존 구현 전체의 테스트를 재실행하지 않았다. 작업 트리의 기존 변경을 이 조사에서 수정·되돌리거나 커밋하지 않았다.

## 조사 범위와 판정 기준

지정된 제품군을 선별 비교한 조사이며 시장 전체의 전수조사나 우열 평가가 아니다. 공식 문서·제품 페이지·공식 저장소만 사용했다. 서비스 스캔, 유료 모델 호출, 외부 메시지, 패치·테스트·PR 실행은 수행하지 않았다. 기능 확인은 공급자가 공개한 계약을 확인했다는 의미이며 실제 사용 검증이 아니다.

**문서 확인**은 기능·권한·제약의 공식 명시, **판매사 주장**은 정확도·고객 성과·공급자 데모 결과다. **독립 검증**은 외부 평가자의 재현이며 이번 조사에서는 확인하지 않았다. 내부의 별도 모델 검토를 독립 검증으로 계산하지 않았다. 미확인은 기능 부재를 뜻하지 않는다.

실행재현과 재현 절차 작성을 구분한다. 재검증은 모델 재심사·정적 검사·회귀 테스트·공격 재시도로 나눈다. BYO key·LLM·agent·runner는 별개다. 자체 CI는 고객 runner를 의미한다. 공개 가격의 계약·한도는 재확인이 필요하다.

## 기능 비교

| 제품·기능 | 발견 / 문맥분석 | 실행재현 | 코드 패치 | 재검증 | PR 전달 |
| --- | --- | --- | --- | --- | --- |
| CodeQL + Copilot Autofix | 정적 분석 결과와 코드 문맥 | 공격 실행 보장 미확인 | 단일 수정안 제안 | 사용자의 리뷰·후속 검사 필요 | 사용자가 적용·전달 |
| GitHub agentic autofix | 경고를 받아 저장소 탐색 | 도구 실행 가능, 공격 재현 보장 미확인 | 에이전트가 수정·반복 | 기본 CodeQL query suite 재실행 | 에이전트 PR |
| Dependabot security updates | 알려진 의존성 취약점·버전 분석 | 미확인 | manifest·lockfile 업데이트 | 저장소 CI에서 확인 | 자동 업데이트 PR |
| Semgrep Multimodal + Autofix | SAST·문맥·AI triage | 실제 실행 보장 미확인 | AI 변경·draft PR/MR | 기존 Assistant의 엔진 검사 설명 있음; 현재 PR 생성의 전체 검사 계약 미확인 | draft PR/MR |
| Snyk Code + Snyk Agent Fix | SAST·수정 예제·코드 문맥 | 미확인 | 단일 파일 수정 후보 | Snyk Code 검사·실패 피드백 반복 | IDE 적용 / 기존 PR 제안 |
| Claude Code Security Reviewer | PR diff 의미 분석·오탐 필터 | 기본 흐름에서 미확인 | 수정 안내; 자동 패치 흐름 미확인 | 모델 기반 오탐 필터 | PR 보안 리뷰 댓글 |
| Claude Security | 저장소·데이터 흐름·다단계 분석 | 재현 절차 제공, 실행 보장 미확인 | Claude Code 세션으로 인계 | finding 다단계 검토; 패치의 자동 공격 재검증 미확인 | 수정 세션 후 전달 |
| CodeRabbit Security + Autofix | 코드 관계·reachability·AI 검토 | live exploit 보장 미확인 | cloud agent 수정 | setup·build 검사; 실패해도 변경 전달 | commit / stacked PR / 보안 수정 PR |
| SonarQube AI CodeFix | Sonar 분석 결과·문제 코드 | 미확인 | 해당 문제의 수정안 | 적용 후 구성된 분석으로 재검사; 자동 실행재현 미확인 | IDE 적용; 자율 PR 생성 미확인 |
| Aikido AutoFix + AI Pentesting | SAST/IaC 또는 실행 중 앱의 공격 분석 | Pentesting은 실제 대상에 요청 | 확인된 문제의 수정 PR | 배포 후 공격 재시도·Continuous Pentesting | AutoFix PR |
| OpenHands / SWE-agent | 작업·도구·프롬프트에 따라 구성 | terminal·sandbox에서 가능 | 파일 편집 | 명령·테스트로 구성 가능; 보안 성공 판정은 통합 책임 | 구현·워크플로 구성에 따라 가능 |
| Codex Security | CLI/SDK·저장소/PR 문맥 분석 | 가능할 때 확인·재현 | accepted finding 단위의 제한된 수정 | 가능한 경우 수정 전 실패·수정 후 통과와 정상 기능 확인; 불가능하면 증거 공백 기록 | 검토·정상 코드 리뷰 경로로 전달 |

## 실행 주권과 비용 비교

| 제품군 | 고객 소유 CI / 실행 환경 | BYO agent provider | 공개 비용·접근 조건 |
| --- | --- | --- | --- |
| GitHub | CodeQL: 자체 CI / agentic: hosted | 외부 agent 선택 미확인 | 공개 Autofix 무료; private 라이선스·agent credits |
| Semgrep | scanner: 자체 CI / AI: hosted | 모델 허용 설정; BYO agent 미확인 | Teams contributor당 월 $30부터·credits |
| Snyk | scanner: CI 연동 / Agent Fix: hosted | 외부 agent 교체 미확인 | SAST Free/Team과 Agent Fix Enterprise 구분 |
| Claude | Reviewer: 고객 runner / Security: hosted | Reviewer API key; provider는 Claude | API·runner 비용 / Enterprise beta·token 비용 |
| CodeRabbit | 리뷰 CLI·IDE / 수리 cloud sandbox | 로컬 agent handoff; cloud 교체 미확인 | Autofix Essentials 이상; Deep Scan 별도 과금 |
| Sonar | 자체 Server·scanner / 지정 LLM | Azure OpenAI BYO model; agent 아님 | Cloud Team/Enterprise; Server Enterprise/DC |
| Aikido | local scanner / hosted pentest | 외부 agent 교체 미확인 | 제한된 무료 AutoFix; pentest 별도 |
| OpenHands / SWE-agent | 자체 서버·Docker·자동화 | ACP agent / LLM 선택 | MIT; 모델·compute·운영 비용 별도 |
| Codex Security | CLI/SDK를 고객 CI에서 실행 가능 | 일반 Codex/Claude adapter와 별도 전문 backend | 공개 패키지이나 실제 scan에는 Codex Security 접근 권한 필요 |

## 제품별 공식 근거와 설계 시사점

### 1. GitHub: 탐지·제안·에이전트 수정·의존성 업데이트를 구분해야 한다

CodeQL CLI는 고객 CI에서 정적 분석 후 SARIF를 GitHub에 전달할 수 있다. 실행 환경 소유 자체는 차별점이 아니다. Dependabot은 알려진 취약 의존성의 업데이트 PR 기능이며 임의의 업무 로직 수리와 구분한다. [CodeQL 외부 CI](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools), [Dependabot 기능 구분](https://docs.github.com/en/code-security/tutorials/secure-your-dependencies/dependabot-quickstart)

현재 공식 문서는 기존 **Copilot Autofix**와 public preview인 **agentic autofix**를 구분한다. 전자는 사용자가 검토하는 단일 제안이며, 후자는 Copilot cloud agent가 여러 파일의 문맥을 탐색하고 수정·검증을 반복한 뒤 PR을 연다. 다만 기본 code-scanning query suite의 CodeQL 재검사로 custom query나 security-extended suite의 해결을 확인할 수 없다고 명시한다. 제삼자 도구의 경고에 대한 수정 품질도 보장하지 않는다. [Autofix 동작과 제약](https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning)

공개 저장소의 일반 Autofix에는 Copilot 구독이 필요하지 않으며 AI credits도 소비하지 않는다. 비공개 조직 저장소는 Code Security 권한이 필요하고 공개 가격은 active committer당 월 $30이다. 에이전트 수정 세션은 별도 credits를 소비한다. Dependabot security/version updates는 Free에도 포함된다. [보안 가격](https://github.com/security/plans), [GitHub 요금제](https://github.com/pricing)

**설계 반영:** 원래 scanner·query set으로 재검증하고 경고 종료와 검사 통과를 구분한다. 제안 생성과 agent 실행의 권한·과금을 분리한다.

### 2. Semgrep: Assistant의 설명과 Autofix의 실제 코드 변경은 다른 기능이다

기존 Assistant overview 링크는 현재 **Semgrep Multimodal** 문서로 연결된다. 정적 분석에 AI 탐지·triage·수정 안내를 결합하고 triage 이력·Memories를 이용한다. 중요도·confidence에 따른 자동 분석과 diff 스캔의 호출 한도가 있어 선택적 호출 방향과 겹친다. [Multimodal 범위](https://docs.semgrep.dev/semgrep-multimodal/overview)

현재 리디렉션된 **Semgrep Agentic Workflows (beta)** 문서는 내장 탐지 파이프라인을 제공한다. 프로그램 분석·결정론적 도구·제한된 AI 추론을 결합하며, AI detection의 IDOR·인가 분석과 함께 기존 rule 검사보다 넓은 문맥을 다룬다. 현재 beta에서는 custom workflow 생성·수정·공개, local CLI·고객 CI 실행, 예약 실행을 지원하지 않는다고 명시한다. 이전 개요의 Python custom workflow·dependency autofix 설명을 현재 계약으로 적용하지 않았다. 실제 공격 재현·패치의 전체 회귀 검증 계약은 이 개요에서 확인하지 못했다. [현재 Workflows 공식 개요](https://docs.semgrep.dev/workflows/overview)

**Suggested fix**, rule-defined fix, **Autofix**를 구분해야 한다. 현재 Autofix는 코드 변경을 만들어 branch와 draft PR/MR를 생성한다. Bedrock의 Claude 모델 허용 및 SCM 쓰기 권한이 필요하며, 해당 Autofix 조건에는 AI model selection을 따르지 않는다고 적혀 있다. Memories도 PR 생성에 직접 투입되는 것이 아니라 기존 remediation guidance를 통해 간접 반영될 수 있다. [Code Autofix 계약](https://docs.semgrep.dev/semgrep-code/triage-remediation/autofix)

2024년 기술 설명은 생성 코드를 Semgrep engine으로 재검사하는 루프를 공개했다. 그러나 이것을 현재 draft PR 생성마다 전체 빌드·테스트·공격 재현을 수행한다는 보장으로 확대할 수 없다. 공식 metrics의 96% human agreement는 사용자 피드백과 내부 평가이며 패치의 보안 성공률이 아니다. Teams 가격과 AI credits도 기능별 소비 조건을 확인해야 한다. [검사 루프 설명](https://semgrep.dev/blog/2024/the-tech-behind-semgrep-assistant/), [평가 방법](https://docs.semgrep.dev/semgrep-multimodal/metrics), [가격](https://semgrep.dev/pricing/)

**설계 반영:** 중요도·confidence로 호출 예산을 정하고 조직별 수정 지침을 반영한다. 설명과 diff 생성을 구분하며 실제 전달된 지침을 기록한다.

### 3. Snyk: 정적 분석의 피드백 루프는 제공하지만 애플리케이션 실행 검증과는 다르다

정확한 제품명은 **Snyk Code + Snyk Agent Fix**이며 과거 이름은 DeepCode AI Fix다. 2026년 5월 업그레이드 공식 자료는 Claude 계열 모델, 전문가 수정 예제의 동적 검색, 검사 실패를 다음 생성에 반영하는 agentic retry를 설명한다. 과거의 “자체 hosted LLM만 사용”이나 일부 언어만 지원한다는 소개를 현재 조건으로 반복하면 안 된다. [2026년 변경 공지](https://updates.snyk.io/announcing-agent-fix-new-agentic-workflow-and-model-upgrade/)

수정 candidate를 Snyk Code로 검사해 기존·신규 문제를 확인한다. 그러나 자동 수정은 **단일 파일 중심이며 여러 파일에 걸친 취약점을 자동 수정하지 않는다**. 사용자의 리뷰와 적용 후 재스캔도 요구한다. PR 경로에서는 기존 Snyk inline comment에 수정안을 요청·적용하며, Local Engine에서는 지원되지 않는 제약이 있다. [최신 문서 소스](https://github.com/snyk/user-docs/blob/main/scan-fix-and-prevent/scan-with-snyk/snyk-code/manage-code-vulnerabilities/fix-code-vulnerabilities-automatically.md), [PR 적용 조건](https://learn.snyk.io/lesson/checking-your-code-with-pr-checks/)

2026-08-18 내부 benchmark는 약 150개 단일 파일의 보안·기능 테스트를 사용했다. 전체 저장소 수리나 고객 테스트의 매번 실행을 입증하지는 않는다. 공식 교육은 Agent Fix를 Enterprise 기능으로 명시한다. Free/Team의 SAST 스캔 한도와 자동 수정 접근권을 구별해야 한다. [평가와 한계](https://snyk.io/blog/snyk-agent-fix-remediation-benchmark/), [접근 조건](https://learn.snyk.io/lesson/snyk-in-an-ide/), [현재 가격](https://snyk.io/plans/)

**설계 반영:** scanner 실패를 수정 루프에 되돌리고 취약 입력 차단과 정상 기능 유지를 함께 성공 조건으로 사용한다.

### 4. Anthropic: 보안 리뷰 Action과 Claude Security는 별도 제품 경로다

공식 저장소의 이름은 **Claude Code Security Reviewer**이고 Action 식별자는 `anthropics/claude-code-security-review`다. PR diff의 의미 분석, 오탐 필터, 보안 finding 댓글·결과 artifact가 주요 계약이다. 로컬 `/security-review`도 설명하지만 기본 Action 흐름에는 자동 패치 PR과 테스트 실행을 완료하는 수리 계약이 없다. README는 prompt injection에 대해 hardened되지 않았고 trusted PR만 검토하라고 명시한다. 사용자 API key와 runner를 쓰는 방식이지만 여러 공급자의 agent를 선택하는 제품은 아니다. [공식 Reviewer 소스](https://github.com/anthropics/claude-code-security-review)

**Claude Security**는 이전 Claude Code Security의 현재 이름이다. 2026-04-30 발표는 Enterprise public beta, 문맥 분석·targeted/scheduled scans·finding 검토·Claude Code on the Web 인계를 설명한다. finding 재심사는 실제 공격이나 패치 회귀 검증과 구분한다. [제품명과 beta 발표](https://claude.com/blog/claude-security-public-beta)

현재 공식 도움말은 스캔을 direct token cost로 과금하며 추가 Security 플랫폼 요금은 없다고 설명한다. GitHub.com/GitHub Enterprise Server 지원, severity 설정 미지원, 확률적 스캔, 데이터 보존 예외를 명시한다. Enterprise 접근 조건과 대상 코드의 권리 조건도 있다.  [현재 접근·비용·제약](https://support.claude.com/en/articles/14661296-use-claude-security)

**설계 반영:** PR 입력과 실행 권한을 분리한다. finding 검토와 patch 검증을 구분하고 확률적 분석과 고정 scanner 결과를 함께 기록한다.

### 5. CodeRabbit: 리뷰 handoff와 자체 수리 agent를 혼동하면 안 된다

**CodeRabbit Security**의 AI Deep Scan은 저장소 관계와 코드 근거로 후보를 확인하며 reachability와 exploitability를 구분한다. 현재 문서는 이 스캔이 SCA나 SBOM을 수행하지 않는다고 명시한다. 부분 coverage와 확인하지 못한 영역도 기록한다. **Fix with AI**는 supported finding에서 수리 task와 PR/MR를 만들며 자동 merge와는 구분된다. [Security 범위](https://docs.coderabbit.ai/security)

**CodeRabbit Autofix**는 자체 리뷰의 unresolved instruction을 모아 coding agent를 실행한다. 저장소 setup·build 검증을 수행하지만, **검증 실패 시에도 생성된 변경을 전달한다**. commit 또는 stacked PR를 선택할 수 있고 merge conflict가 있으면 작업을 중단한다. 따라서 PR 존재를 검증 성공으로 해석하면 안 된다. cloud Coding Agent는 별도 sandbox에서 동작하며, IDE의 Fix with AI나 Plan의 Agent Handoff는 사용자의 로컬 agent에 문맥·프롬프트를 전달하는 다른 경로다. [Autofix 동작](https://docs.coderabbit.ai/finishing-touches/autofix), [Coding Agent 구분](https://docs.coderabbit.ai/code), [사용자 agent handoff](https://docs.coderabbit.ai/plan/agent-handoff)

현재 가격은 Essentials 연간 결제 환산 월 $24/developer, Team $48, Advanced $72다. Autofix는 Essentials 이상이고 지속 PR 보안 리뷰는 Advanced/Enterprise, AI Deep Scan은 별도 사용량 과금이다. Agent 가격 표시는 분당 $0.40이며 구체적인 task의 적용 과금은 계약을 확인해야 한다. [공식 가격](https://www.coderabbit.ai/pricing)

**설계 반영:** 수정·빌드·보안 검증·전달을 별도 상태로 둔다. 사용자 agent에게 인계한 뒤 결과를 회수하지 못했다면 검증 완료로 표시하지 않는다.

### 6. Sonar: BYO model 지원은 BYO agent 실행보다 좁다

**SonarQube AI CodeFix**는 일부 규칙의 수정안을 제공한다. Cloud는 Team/Enterprise, Server 2026.1 LTA는 Enterprise/Data Center에서 제공되며 Server는 Azure OpenAI BYO model을 지원한다. BYO 경로도 프롬프트·규칙 수신을 위한 인터넷 연결이 필요하다. [Cloud 조건](https://docs.sonarsource.com/sonarqube-cloud/administering-sonarcloud/ai-features/enable-ai-codefix), [Server BYO 조건](https://docs.sonarsource.com/sonarqube-server/2026.1/instance-administration/ai-features/enable-ai-codefix)

문서상 사용자는 Generate AI Fix를 선택하고 IDE에서 제안을 적용하거나 거절한다. 자율적으로 저장소 전체를 수정해 PR을 만들고 exploit을 재실행하는 보장은 확인하지 못했다. 과거 공식 GA 설명은 eligible plan에 추가 비용 없이 포함된다고 안내했다. 현재 계약 가격과 허용량은 별도 확인이 필요하며, BYO 모델에는 모델 공급자 비용과 제한이 따른다. [GA 제공 범위](https://www.sonarsource.com/blog/ai-codefix-is-now-generally-available/)

**설계 반영:** 모델·소스 전달 경로·runner·외부 의존성을 각각 보여준다. 일부 규칙의 수정 지원을 전체 취약점 자동 수정으로 확대하지 않는다.

### 7. Aikido: 실행재현과 수정 후 공격 재시도를 가장 직접적으로 판매한다

**Aikido AutoFix for SAST and IaC**는 snippet을 Bedrock으로 보내 수정안을 생성하고 preview·PR·IDE 적용을 제공한다. confidence를 표시하고 merge 전 사람의 검토를 권한다. Local Scan 계정은 UI AutoFix 접근이 없고 IDE 경로는 사용할 수 있다는 예외가 있다. [AutoFix 공식 문서](https://help.aikido.dev/autofix-and-remediation/scope/ai-autofix-for-sast-and-iac-issues)

**Aikido AI Pentesting**은 실행 중인 애플리케이션에 공격을 시도하고 근거·재현 절차를 제공하는 제품이다. 공식 데모의 수리 흐름은 발견 → AutoFix PR → 사용자 merge·배포 → Attack retest다. 즉 SAST 수정안의 confidence와 live 대상에서 다시 공격한 결과를 같은 검증으로 합쳐서는 안 된다. escalation은 사용자 선택을 요구한다는 제품 경계도 있다.  [공식 데모·재시험 설명](https://www.aikido.dev/blog/ai-pentesting-demo), [AI Pentesting 제품](https://www.aikido.dev/attack/aipentest)

현재 **Continuous Pentesting / Aikido Infinite** 문서는 첫 full assessment와 연결 저장소, 최소 1,000 credits의 wallet을 요구한다. 실행 중 앱을 배포 또는 일정에 따라 재시험하며 agent당 10 credits, 1 credit=$1이다. 첫 평가의 “High/Critical 없으면 무료” 조건은 지속 실행에 적용되지 않는다. 플랫폼 무료 플랜의 월 10 AI AutoFix와 pentest 비용은 별개다. [지속 실행 조건](https://help.aikido.dev/pentests/continuous-pentesting), [가격](https://www.aikido.dev/pricing)

**설계 반영:** 대상·공격 범위·재배포·재시험 환경을 evidence에 기록한다. 로컬 재현과 실제 서비스 공격의 권한을 분리한다.

### 8. OpenHands / SWE-agent: 공급자 선택과 수리 runtime은 이미 재사용 가능하다

**OpenHands Agent Canvas**는 Claude Code·Codex·Gemini·ACP agent를 local·remote·cloud에서 실행한다. 사용자 agent 선택은 이미 존재하는 기능이다. 자체 hosting·Docker를 지원하지만 workspace 공유 시 충돌 가능성이 있고 sandbox 없는 실행은 호스트 파일에 접근한다. [Agent Canvas 공식 소스](https://github.com/OpenHands/OpenHands)

**OpenHands Software Agent SDK**는 terminal·file editing 도구, 로컬 또는 Docker/Kubernetes workspace, GitHub CI/CD 예제를 제공한다. 이는 수리 실행 기반이며 취약점 finding의 진위, 검증 명령, 공격 재현, 성공 조건까지 자동 보장하는 보안 제품은 아니다. 고객 소유 CI에서 호출할 수 있는 구성 요소로 평가해야 한다. [SDK와 실행 환경](https://github.com/OpenHands/software-agent-sdk)

**SWE-agent** 역시 선택한 LLM이 Docker에서 저장소를 탐색·수정·재현하도록 구성할 수 있고, 공식 CLI 예제에는 작업별 비용 한도가 있다. 다만 현재 유지관리자는 개발 중심이 **mini-swe-agent**로 이동했다며 앞으로 그쪽 사용을 권한다. 저장소의 MIT 라이선스와 모델 호출·compute 비용은 별개다. SWE-bench 성능을 보안 패치 성공률로 옮겨 쓰면 안 된다. [현재 유지관리 상태](https://github.com/SWE-agent/SWE-agent), [Docker·비용 제한 예제](https://swe-agent.com/latest/usage/hello_world/)

**설계 반영:** 기존 runtime 재사용 비용을 비교한다. 취약점별 재현 조건·독립 검사·중단 기준·변경 provenance를 제품 자산으로 삼는다.

## wakeio-security-ci에 반영할 우선 기능

다음은 비교에서 도출한 제안이다. 현재 코드에서 제공되는 기능과 구분하며, 아래 연동·실행 설계는 아직 구현되지 않았다.

1. **선택적 호출:** 중요도·confidence·노출 경로로 대상을 정하고 비용·시간·재시도를 제한한다. 미연결·예산 소진 이유도 보고한다.
2. **검증 수준 표시:** 분석·diff·정적 검사·회귀 검사·취약 입력 차단·PR을 별도 상태로 기록한다. 수정 전후 결과와 scanner·rule·commit·환경을 보존한다.
3. **불확실성 보존:** timeout·누락 의존성·partial coverage·재현 실패를 완료와 구분한다. 경고 소멸이나 테스트 약화만으로 해결을 확정하지 않는다.
4. **결과 회수:** 위치·데이터 흐름·공격 가설·허용 변경·정상 동작 조건을 전달하고 patch·로그를 같은 정책으로 검사한다. 미지원 조합을 자동 대체하지 않는다.
5. **검토 가능한 전달:** 실패한 diff에 이유를 붙이고 중복 작업을 방지한다. 충돌 시 대상을 재확정하며 PR 생성과 보안 성공을 구분한다.

차별화 가설은 고객 환경의 재현·동일 기준 재검사·보안과 기능 유지 근거를 갖춘 선택적 수리다. agent 선택 자체는 이미 경쟁 기능이다. 고객 수요와 검증 신뢰도는 별도 확인해야 한다.

## 추가 비교 — Codex Security: 전문 수리 workflow를 선택적으로 재사용할 수 있다

`@openai/codex-security`는 공개 CLI·TypeScript SDK와 CI 경로를 제공하지만 실제 scan에는 Codex Security 접근 권한이 필요하다. 일반 Codex SDK 연결과 이 전문 제품의 접근 권한은 별개다. [Security](https://learn.chatgpt.com/docs/security), [CI](https://learn.chatgpt.com/docs/security/cli/ci), [SDK](https://learn.chatgpt.com/docs/security/sdk)

공식 수리 workflow는 accepted finding 한 건을 제한된 수정으로 처리하고, 가능하면 수정 전 실패·수정 후 통과하는 회귀 테스트와 정상 기능을 확인한다. 시험이 불가능하면 대체 검증과 증거 공백을 남긴다. 따라서 Wakeio가 모든 탐지·수리 runtime을 독자 구현해야 하는 것은 아니다. 다만 해당 기능을 무료 기본 경로의 필수 의존성으로 만들면 현재 요구와 어긋난다. [수리·검증 workflow](https://learn.chatgpt.com/docs/security/plugin/fix-findings)

AI 재스캔은 달라질 수 있고, 경고 소멸이나 scan 비교만으로 수정 성공을 입증하지 못한다는 공식 FAQ도 현재 Wakeio의 보수적인 비교 계약과 맞는다. 전용 backend를 연결하더라도 Wakeio가 coverage·원래 재현 조건·최종 검증 결과를 회수해야 한다. 비용 한도도 일부 제품에서는 추정치여서 진행 중 요청으로 초과할 수 있다. [Security CLI FAQ](https://learn.chatgpt.com/docs/security/cli/faq)

## 연결 방법: provider-neutral 계약과 얇은 adapter

연동 가능한 공식 경로는 존재한다. 제품 UI에서 로그인한 사실만으로 CLI·SDK의 인증과 모델 접근이 확인되는 것은 아니다. 이번 로컬 점검은 `codex-cli 0.160.0`, `Claude Code 2.1.195`의 설치·버전·도움말까지만 확인했고, 인증 파일이나 API key 값을 읽거나 실제 inference를 호출하지 않았다.

| 경로 | 활용 | 주의할 점 |
| --- | --- | --- |
| Codex CLI `codex exec` | CI용 비대화형 실행, 구조화된 결과 수집 | 저장된 CLI 인증 재사용과 CI용 API key 인증을 구분. read-only 분석과 격리 workspace 수정을 명시적으로 분리 |
| Codex TypeScript SDK | Node 패키지에서 세션·진행 이벤트·결과 제어 | 공식 SDK를 adapter 뒤에 두고 버전을 고정. 과거 Codex MCP server 예제를 새 실행 기반으로 삼지 않음 |
| Claude CLI `claude -p` | 비대화형 실행과 JSON 결과 수집 | 자동 설정·hook·MCP 로딩을 통제. `--bare`가 도구 권한을 전부 제거하는 것은 아님 |
| Claude Agent SDK | TypeScript/Python의 도구·권한·서브에이전트 제어 | 제삼자 제품의 claude.ai 로그인 제공은 사전 승인 없이 허용되지 않는다는 공식 안내가 있으므로 API key 경로를 기본 설계로 삼음 |
| 전문 Security backend | Codex Security 등의 자체 탐지·수리 workflow 재사용 | 별도 접근 권한·비용·소스 전달·검증 계약을 표시하고 미접근 시 다른 backend로 조용히 대체하지 않음 |

근거: [Codex SDK](https://learn.chatgpt.com/docs/codex-sdk), [Codex 비대화형 실행](https://learn.chatgpt.com/docs/non-interactive-mode), [Codex 인증](https://learn.chatgpt.com/docs/auth), [Claude 비대화형 실행](https://code.claude.com/docs/en/headless), [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/overview).

adapter의 입력은 finding ID, 고정된 source snapshot, 관련 문맥·증거, 허용 작업, 검증 계획, 제한 예산이다. 출력은 triage, 근거, patch, 수행 내역과 실행 상태다. 모델의 최종 문장이나 process exit 0을 보안 검증 성공으로 변환하지 않는다. schema validation과 경로·해시 대조는 별도로 수행한다.

CLI/SDK별 옵션은 같지 않다. 예를 들어 Claude의 `allowedTools`는 사전 승인 목록이지 그 목록 밖 도구를 제거하는 설정이 아니다. 실제 도구 집합·거절 규칙·실행 격리를 함께 적용해야 한다. turns·시간·비용 한도는 adapter가 지원하는 조건을 preflight하고 미지원이면 오류로 보고한다. 비용 추정과 확정 청구 상한은 구분한다. [Claude 설정 계약](https://code.claude.com/docs/en/agent-sdk/configuration)

기본 패키지에 모든 SDK를 항상 설치하지 않고 선택 adapter로 로딩하는 것을 추천한다. 첫 adapter 하나로 종단 검증을 만들고 같은 contract test로 두 번째 제공자를 붙인다. 새 대화 세션에서 작업하는 연동이지 이 앱의 기존 사용자 대화를 자동으로 장악하는 기능은 아니다.

## 추천 실행 구조: 역할은 나누되 모든 역할을 LLM으로 만들지는 않는다

붙여넣은 Planner / Worker / Verifier / Report 구조는 문맥 수집과 책임 분리에 유용하다. 패치 목표를 위해서는 Repair 단계를 추가하고, 최종 Verifier의 권한을 모델이 아닌 실행기에 둬야 한다.

```text
고정된 snapshot + 신뢰된 TOML 정책
                  │
                  ▼
기존 scanner + 필요한 취약점 프로필 선택
                  │
                  ▼
증거·관련 코드 수집 → 선택한 agent의 분석
                  │
                  ▼
격리된 복사본에서 재현 테스트 작성·수정 전 실패 확인
                  │
                  ▼
Repair agent: 범위가 제한된 patch 생성
                  │
                  ▼
실행기: 동일 재현 테스트 + 정상 기능 + 기존 검사 재검증
                  │
                  ▼
patch 파일 + 검증 기록 → 명시적 적용 / 별도 승인 PR
```

- 필수 scanner와 최소 검증은 결정론적으로 선택한다. LLM Planner가 필수 검사를 빼거나 실행 실패를 clean으로 바꾸지 못한다.
- Analysis·Repair·Review는 역할이며 반드시 서로 다른 LLM 프로세스를 뜻하지 않는다. 처음에는 한 provider worker와 실행기 소유 검증기로 충분하다.
- 기존 경고만 triage하면 scanner의 사각지대는 그대로 남는다. 선택적 deep 모드는 auth·tenant 경계·입력→위험 실행 경로를 별도로 탐색하되 coverage와 문맥 예산을 기록한다.
- 읽기 중심 분석은 제한된 병렬 실행이 가능하다. 같은 파일을 고치는 작업은 직렬화하거나 별도 복사본에서 충돌을 판정한다. 첫 버전은 finding 한 건씩 수정한다.
- Report는 고정된 결과에서 JSON/SARIF/Markdown을 만드는 기존 방식으로 충분하다. 필수 Report LLM이나 별도 DB·분산 scheduler는 지금 필요하지 않다.

“이 패키지만으로 수리”는 사용자에게 하나의 명령·workflow를 제공한다는 의미로 정의하는 것이 정확하다. AI 모델, runner, 의존성, 대상 테스트 환경까지 의존성이 없어지는 것은 아니다. 클라우드 agent는 선택한 코드 문맥을 외부 모델에 전송하므로 기존의 기본 무전송 약속과 분리해 고지·동의해야 한다.

## 취약점별 TOML 프로필: 지침과 실행 계약을 함께 관리

사용자의 `.toml` 제안은 권장한다. 핵심은 파일 형식보다 **버전 관리 가능한 보안 프로필을 단일 원본으로 두는 것**이다. Codex의 현재 custom agent 문서는 TOML을 사용하고, Claude native subagent는 Markdown/YAML 또는 SDK의 agent 정의를 사용한다. 동일 TOML 파일을 두 제공자가 그대로 읽는 공통 표준은 아니다. Wakeio가 공통 schema를 검증한 뒤 provider별 prompt·도구·권한 설정으로 변환해야 한다. [Codex custom agents](https://learn.chatgpt.com/docs/agent-configuration/subagents), [Claude custom subagents](https://code.claude.com/docs/en/sub-agents)

처음에는 중앙 설정 하나와 취약점 계열별 프로필 몇 개면 충분하다. CWE마다 독립 프로세스를 수백 개 띄우지 않는다. 예시는 SQL injection, 객체 단위 인가/IDOR, SSRF, command injection, path traversal다. 의존성·secret 검사는 기존 결정론적 worker를 우선 사용한다.

아래는 **새로 제안하는 Wakeio schema 예시**다. 현재 CLI 옵션이나 Codex/Claude native TOML schema가 아니며, 실제 TOML 파일을 설치하지 않았다. `write_paths`는 수정용 격리 복사본 안의 경로다. 사용자 원본 작업 트리 쓰기 권한이 아니다.

```toml
schema_version = 1

[run]
provider = "codex"
mode = "repair"
output = "patch"
max_parallel = 2
max_attempts = 2
timeout_seconds = 600

[profiles.sql_injection]
cwe = ["CWE-89"]
instructions = """
외부 입력에서 실제 SQL 실행점까지의 경로를 확인한다.
실제 parameter binding과 sanitizer를 확인하고 문자열 결합만으로 확정하지 않는다.
값은 parameter binding으로 분리하고 동적 식별자는 별도 allowlist가 필요한지 확인한다.
기존에는 실패하고 수정 후 통과하는 회귀 테스트와 정상 쿼리 동작을 제시한다.
재현·기대 동작을 확인하지 못하면 검증 완료라고 보고하지 않는다.
"""
read_paths = ["src/**", "tests/**", "package.json"]
write_paths = ["src/**", "tests/security/**"]
required_evidence = ["source_sink_trace", "regression_red_green", "normal_behavior"]
required_checks = ["security_regression", "normal_behavior", "source_rescan"]

[policy]
original_checkout_write = false
commit = false
push = false
deployment = false
test_disable = false
target_network = "local-fixture-only"
```

정책은 다음 세 부분으로 구분한다.

| 부분 | 내용 | 책임 |
| --- | --- | --- |
| 모델 지침 | 무엇을 추적하고 어떤 오탐·우회·수정 방식을 검토하는가 | agent prompt에 전달; 결과의 정확성을 보장하지 않음 |
| 기계 정책 | 도구·경로·network·예산·재시도·출력·금지 변경 | 실행기와 격리 환경이 강제; 자연어 지침에만 의존하지 않음 |
| 검증 계약 | 기대 보안 동작, 원래 재현, 정상 control, 필수 test·scanner | 패치 전에 고정하고 실행기가 결과를 직접 판정 |

`target_network`는 검증 대상 통신 범위를 뜻한다. 클라우드 inference 연결은 별도 credential proxy 경로이며 테스트 컨테이너에 모델 키를 전달하지 않는다. 임의 shell 문자열을 TOML에서 자동 실행하지 않고 `required_checks`를 승인된 검증 ID에 매핑한다. 새 저장소를 위한 test 명령 등록은 별도 신뢰·실행 승인을 거친다.

정확하게 지정하려면 다음을 구현해야 한다.

1. schema 버전, 알 수 없는 키, 잘못된 타입, 중복/충돌 정의, 음수·무제한 예산을 엄격히 거부한다. `String(value)`로 타입을 완화하지 않는다.
2. provider가 지정 정책을 실제로 지원하는지 확인한다. 지원하지 않는 권한·한도를 조용히 무시하거나 더 넓은 권한으로 실행하지 않는다.
3. PR이 TOML·지침·검증기를 고쳐 권한을 늘리거나 성공 기준을 낮추지 못하도록 신뢰된 base revision 또는 승인된 정책 버전을 사용한다. 프로젝트 override는 권한을 줄이는 방향으로만 허용한다.
4. TOML 원문과 변환된 provider 설정의 해시·버전·적용 scope를 결과에 남긴다. API key는 TOML에 쓰지 않으며 credential broker/명명된 secret 참조로만 연결한다.
5. 분석과 수정 권한을 분리한다. 다른 provider로 전환하거나 subagent를 추가해도 실행기의 상한은 유지한다. 모델이 서브에이전트를 마음대로 재귀 생성하지 못하도록 전체 요청·동시성 한도를 둔다.

## 실제 수리 성공 판정과 안전 경계

수정안 생성은 시작일 뿐이다. 초기 제품은 아래 조건을 모두 만족한 경우에만 **해당 선언된 사례에 대한 검증 완료**로 표시한다. 모든 취약점이 없어졌다는 표현은 사용하지 않는다.

1. 원래 snapshot에서 고정된 보안 회귀 테스트가 해당 보안 assertion 때문에 실패한다. 설치 실패·compile 오류·timeout은 재현 성공이 아니다.
2. 동일 테스트·fixture·검증 계획으로 patch 후 통과한다. 테스트 삭제·skip·assertion 약화·scanner 제외는 실패 처리한다.
3. 정상 동작 control과 필요한 기존 lint/type/build/test가 통과한다. baseline부터 실패한 필수 검사나 실행 불가 환경은 증거 공백으로 남긴다.
4. 원래 scanner·rule·대상 scope로 재검사하고 새로운 관련 경고를 확인한다. 경고 소멸만을 성공 조건으로 삼지 않는다.
5. diff가 허용된 경로와 범위에 있고 CI 정책·credential·검증기·public API를 허가 없이 변경하지 않는다.

필수 테스트가 skip되거나 실제 엔진이 없으면 repair의 검증 완료는 실패해야 한다. 메타데이터 비교만 하지 않고 실제 합성 요청·입력의 안전한 fingerprint와 설치된 engine 버전을 확인한다. lockfile hash는 실제 실행 버전·binary hash·sandbox image digest를 대신하지 못한다. 민감값의 공개 hash를 만들지 않고 비민감 합성 데이터에 한정한다.

agent가 작성한 새 테스트도 자동으로 믿지 않는다. patch 전에 검증 계획과 테스트를 잠그고, 실행기는 원래 코드와 수정 코드 양쪽에서 직접 돌린다. 최초 평가 corpus에는 별도 작성한 검증기도 둬 동일 모델의 테스트와 patch가 함께 틀리는 문제를 측정한다.

현재 `runProcess`의 argv·환경변수 축소·timeout·process group 종료는 재사용 가능한 감독 기능이지만 hostile 코드 실행 sandbox는 아니다. 수정·build·test에는 비루트 격리 환경, 호스트 secret·Docker socket 미마운트, 자원/시간 제한, 대상 network 제한이 별도로 필요하다. inference 인증정보는 테스트 환경 밖에서 관리한다. [Claude 안전한 agent 배포](https://code.claude.com/docs/en/agent-sdk/secure-deployment)

Codex 공식 문서는 저장소 script/test와 같은 job 환경에 모델 key를 넓게 노출하지 말고 proxy 경로를 활용하도록 안내한다. 공개/OSS CI에서 개인 계정 auth 파일 재사용 경로를 기본으로 제공하지 않는다. [Codex CI 인증·안전](https://learn.chatgpt.com/docs/non-interactive-mode#authenticate-in-automation)

untrusted PR을 secret·쓰기 권한이 있는 `pull_request_target`/`workflow_run`에서 그대로 checkout·실행하지 않는다. agent job, secret 없는 검증 job, 별도 최소권한 PR 전달 job을 분리하고 artifact도 불신 입력으로 검증한다. [GitHub Actions 안전 경계](https://docs.github.com/en/actions/reference/security/secure-use)

검토용 Markdown/SARIF에는 민감값·원문 로그를 내보내지 않는다. patch는 코드가 포함되는 별도 민감 artifact로 분류하고 비공개 보관·최소 접근·기한을 적용한다. 코드가 든 patch까지 무전송/무코드 결과라고 부르지 않는다.

## 결과 계약과 재현성

기존 Finding·CheckResult·ScanReport를 한번에 바꾸기보다 별도의 버전 있는 repair 결과를 연결하는 것을 추천한다. 최소 항목은 finding ID·증거 ID, source snapshot manifest/hash, 정책·검증 계획 hash, provider/model/CLI·SDK 버전, 변경 파일·diff hash, 실제 test와 scanner 결과, coverage·증거 공백, 비용/사용량·시간·중단 사유다.

상태는 분석됨 → 재현됨 → 수정안 생성됨 → 선언된 범위 검증됨 → 전달됨을 구분하고, 오류·부분·시간 초과는 별도로 둔다. 기존 비교의 `not_observed`를 `fixed`로 바꾸지 않는다. 동일 snapshot·정책·finding은 중복 작업을 방지하고 재시도는 횟수가 제한된 새 attempt로 기록한다. 동일 seed가 같은 LLM 답변을 보장한다고 약속하지 않는다.

처음은 run별 private artifact 디렉터리와 JSON manifest로 충분하다. 파일 경로 제한은 normalize/realpath·symlink·traversal 검증과 실제 filesystem 권한을 함께 적용한다. 폴더를 만들거나 프롬프트에 경로를 적은 것만으로 보안 경계가 생기지 않는다.

## 도입 순서와 완료 조건

아래 명령은 **향후 UX 제안이며 현재 미구현**이다. 기존 `scan --source` 문법은 유지한다.

```sh
wakeio-security-ci scan --source . --agent codex
wakeio-security-ci repair --source . --from report.json --agent claude --out repair-output
```

첫 명령은 분석만, 둘째는 격리 복사본에서 patch와 검증 기록만 생성하도록 권한을 분리한다. 원본 적용·commit·push·PR·merge·deployment는 별도 권한이다.

| 순서 | 구현 단위 | 완료 조건 |
| --- | --- | --- |
| 1 | 공통 schema·TOML 정책·Codex adapter 하나·read-only 분석 | 잘못된 타입/미지원 정책/미인증·timeout이 오류로 남고, 원본 무변경·원래 findings 보존을 검사 |
| 2 | 하나의 취약점 프로필로 종단 patch 검증 | 자체 Node/TS SQL injection fixture 한 건에서 원래 보안 test 실패 → 최소 patch → 보안/정상 control/기존 검사 통과 → private diff/검증 기록 출력 |
| 3 | Claude adapter와 동일 평가 corpus | provider가 달라도 같은 권한·실패 의미·검증 기준 적용. 인증 조건·실제 비용은 명시적 실험에서 별도 확인 |
| 4 | 프로필 확장·diff 영향 범위·제한된 병렬 분석 | auth/IDOR은 명시된 owner/other-user/anonymous·tenant 정책, SSRF는 허용된 로컬 fixture 등 검증 가능한 범위부터 추가 |
| 5 | 선택형 PR 전달·전문 Security backend | 최소권한 분리·중복/충돌 방지·검증 상태 표시; 자동 merge·production 공격·자동 배포는 기본에서 제외 |

SQL injection 예시는 첫 평가 후보이지 제품 전체 지원 약속이 아니다. known dependency 업데이트는 manifest·lockfile·실행 test를 함께 검증해야 하고, 노출 secret은 코드 삭제만으로 폐기·회전이 끝나지 않는다. RLS/권한·업무 정책·schema migration·외부 자격증명 변경은 기대 정책과 승인 없이는 자동 확정하지 않는다.

비교 평가에는 취약 입력 차단률뿐 아니라 정상 기능 유지, 신규 취약점, 오탐에 대한 불필요한 patch, 비용/시간, timeout·skip·partial 비율, 반복 실행 변동을 포함한다. 작은 synthetic corpus의 통과는 고객 코드·실서비스·production 수정 성과가 아니다.

## 개인 아키텍처 기준 적용

| 기준 | 적용 판단 | 이번 제안 |
| --- | --- | --- |
| 단순하고 설명 가능한 경계 | 지금 적용 | 기존 scanner를 유지하는 모듈형 단일 runtime; 얇은 provider adapter |
| 역할·계약을 먼저 정의 | 지금 적용 | finding/evidence/patch/verification을 구분하고 TOML schema를 버전 관리 |
| 느린 작업의 예산·관찰 가능성 | 지금 적용 | 전체/attempt 시간·동시성·요청 제한, 진행 이벤트·비용·중단 사유 |
| 재시도·중복·중단의 의미 | 지금 적용 | 고정 snapshot, finding별 ID, bounded attempt·checkpoint |
| 데이터·자격증명 경계 | 지금 적용 | 선택적 외부 코드 문맥 전달, 외부 credential broker, private patch |
| 실제 실행 격리 | 실행 모드 전 필수 | script/test opt-in, 제한 container/runner, 무secret 검증 |
| 실패 중심 검증 | 지금 적용 | test skip·wrong type·정책 무시·prompt injection·권한 확대·충돌을 실패로 검증 |
| 대규모 분산·영구 저장·자동 운영 | 필요 시 재검토 | DB·별도 queue·다중 LLM 지휘 체계·auto-merge는 초기에 보류 |

## 미확인 사항

실제 재현률·회귀 범위·데이터 경로·청구는 미확인이다. 계약 전 preview/GA·권한·과금을 재확인해야 한다. 공급자 성과는 독립 검증이 아니다.
