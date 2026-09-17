# Source adapter preview 0.4

2026-09-16 기준 source adapter 개선 내용입니다. 이 문서는 `runSource`가 수집한 allowlist snapshot을 대상으로 하는 범위와 남은 불확실성을 함께 설명합니다.

## 반영된 변경

- `src/source/framework.ts`의 SQL mask가 PostgreSQL 중첩 block comment를 depth로 처리합니다. double quoted identifier는 별도 private view에서 보존해 `"public"."users"`의 `DISABLE`과 `ENABLE`을 같은 테이블로 매칭하고, quoted case·공백·dot이 다른 식별자를 합치지 않습니다. ordinary string은 backslash를 escape로 취급하지 않고 `E'...'`에서만 취급합니다.
- Next/React 규칙은 `.env`, `.env.local` 같은 정적 key/value와 정적인 `process.env` property/element 참조를 연결합니다. `use client` 모듈에서 시작해 정적인 상대 import, re-export, `require`를 allowlist 안에서 따라가며 가져온 server-secret-shaped literal과 환경 참조를 후보로 냅니다. 파일 수준의 `use server` 모듈은 Next Server Action 경계로 보고 client graph에서 멈추며, React import만으로 Server Component를 client entry로 추정하지 않습니다. `next.config.*`의 `env` object는 key에 `NEXT_PUBLIC_`가 없어도 값을 애플리케이션에 노출할 수 있으므로 실제 secret 또는 secret-shaped 이름을 검사합니다. Supabase anon/publishable 이름과 값은 계속 제외합니다.
- migration snapshot에서 `CREATE TABLE` 뒤 `GRANT SELECT|INSERT|UPDATE|DELETE|ALL`이 있고 관찰된 `ENABLE ROW LEVEL SECURITY`가 없으면 `supabase:grant-without-observed-rls` medium/low candidate를 냅니다. `REFERENCES`나 `TRUNCATE` 전용 grant는 이 후보를 만들지 않습니다. 후보는 live database state나 배포 순서를 증명하지 않습니다.
- `src/source/dataflow.ts`는 Next route context와 request object의 destructured `params`, `query`, `body`, `headers`, `searchParams`, `formData`, loop element, 정적 object property write를 same-function 범위에서 전달합니다. `src/source/ast.ts`는 JSX `dangerouslySetInnerHTML`, `React.createElement`의 해당 prop, `prisma.$queryRawUnsafe`/`$executeRawUnsafe`/`$queryRaw`/`$executeRaw`, static `db["query"]`를 대표 sink로 관찰합니다. fixed literal과 parameterized argument는 후보를 만들지 않습니다.
- `requirements.txt`, `requirements-dev.txt`, `requirements-prod.txt`는 모든 package line이 `name==version`으로 고정된 self-contained 입력일 때만 OSV `--lockfile`로 전달합니다. `uv.lock`도 OSV 2.6 lockfile로 수집합니다. range, VCS/URL, editable line, `-r`/`--requirement`, `-c`/`--constraint`가 있으면 해당 파일을 제외하고 check를 `partial`로 유지합니다. pinned 파일과 unresolved 파일이 함께 있으면 pinned 입력만 검사하고 unresolved count를 note/metric으로 표시합니다.
- Bandit 결과의 `line_number`와 `line_range`는 실제 수집된 Python 파일의 줄 수 안에 있어야 합니다. 범위를 벗어나면 clean 결과 대신 `error`가 됩니다. B603 guidance는 rule-specific 공식 문서 링크를 사용합니다.

## 보장하는 출력 경계

finding에는 secret, requirement 원문, SQL/JS/Python source snippet, scanner의 `issue_text`를 넣지 않습니다. 위치와 rule 설명만 공개합니다. `confidence: high`는 shape와 정적 연결을 확인했다는 뜻이며, 배포 bundle·Next build replacement·live Supabase 권한을 확인했다는 뜻이 아닙니다.

framework의 import graph는 상대 경로와 정적 확장자/index 후보만 풉니다. package import, TypeScript path alias, non-literal dynamic import, 조건에 따른 실제 reachability, generated bundle은 unresolved입니다. 파일 수준 `use server` 경계 뒤의 반환값이 client에 안전한지, 실제 Next build가 어떤 stub/bundle을 만드는지는 검사하지 않습니다. React import 자체를 browser/client 경계로 보지 않으므로 `use client`가 없고 명확한 browser entry로 식별되지 않는 Server Component의 imported secret은 이 bounded rule에서 미검출될 수 있습니다. `.env` parsing은 단순 key/value와 알려진 secret/public-key shape만 사용하며 interpolation, runtime override, environment precedence를 계산하지 않습니다.

AST/dataflow는 의도적으로 same-function bounded analysis입니다. 인식하지 못한 helper의 반환값은 safe로 단정하지 않고 low-confidence unknown candidate로 남깁니다. raw SQL rule은 알려진 callee와 대표 argument 위치만 관찰하므로 모든 ORM/query builder를 포괄하지 않습니다. HTML 후보는 실제 tainted flow가 연결된 JSX prop 또는 assignment에 한정합니다.

`runSource`의 source finding에는 `source.v1`, check ID, rule ID, snapshot 상대 경로, 위치 줄에서 추출한 normalized semantic token을 SHA-256한 64자리 소문자 hex `comparisonKey`가 붙습니다. line/column, occurrence 순번, raw literal/secret은 hash 입력에서 제외합니다. 같은 rule/path/token이 서로 다른 위치에 있으면 같은 key를 유지해 비교 계층이 ambiguity로 처리합니다. 민감 파일은 source token 대신 고정 표식을 사용합니다.

RLS 후보의 `ENABLE` 이력은 수집된 migration 파일의 경로 순서에서만 계산합니다. live database, grants 외 권한 모델, rollback/branch 배포 순서, 정책의 실제 효과는 별도 검증 대상입니다. `DISABLE` 자체는 high candidate로 남을 수 있습니다.

## 검증

source 전용 변경과 경계 회귀 테스트는 다음으로 실행합니다.

```sh
npm run build
node --test build/tests/framework.test.js build/tests/dataflow.test.js build/tests/python.test.js build/tests/source.test.js
```

테스트에는 nested comment, quoted table case/dot/space/escaped quote, E string, CREATE+grant와 REFERENCES 대조, `.env.local` 및 상대 re-export, non-public `next.config` env, shared client entry dedup과 reachable parse error, stable/duplicate semantic anchor, destructured/loop/property dataflow, JSX/raw SQL risk-safe 쌍, pinned/unresolved requirements, `uv.lock`, Bandit line bound와 B603 URL이 포함됩니다. OSV 2.6.0 native adapter는 합성 `requests==2.19.1` requirements 입력에서 package 1개와 advisory 결과를 반환하는 것을 별도로 확인했습니다.
