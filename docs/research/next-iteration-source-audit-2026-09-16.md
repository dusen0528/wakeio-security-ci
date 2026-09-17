# v0.4 소스 규칙 후속 감사 — 2026-09-16

이 문서는 `wakeio-security-ci` 0.3.0-dev.1의 소스 규칙을 읽기 전용으로 감사한 기록이다. 범위는 `src/source/framework.ts`, `src/source/dataflow.ts` (요청에서 말한 `ast/dataflow.ts`에 해당하는 현재 경로), `src/source/ast.ts`, `src/source.ts`, `src/source/python.ts`이다. 프로덕션 코드와 회귀 테스트는 수정하지 않았다.

> 과거 버전 감사 기록입니다. 아래 줄 번호와 발견 사항은 당시 0.3 코드 기준이며, 현재 구현 및 수정 검증은 [0.4 검증 기록](../verification-0.4.md)을 참고하세요.

## 검증 전제와 판정 기준

부모 에이전트가 확인한 최신 baseline은 Node.js 22.22.1, `npm test` 99/99 통과다. 이 감사는 다음 빌드를 사용했다.

```text
build/src/cli.js
build mtime: 2026-09-16 21:09:25 KST
```

각 사례는 `mkdtemp` 아래에 합성 파일을 만들고 다음 명령으로 실행했다. 대상 JS/TS/SQL/Python은 읽기와 staging만 했고 import, build, test, install script는 실행하지 않았다. Python adapter 사례의 실행 파일은 adapter JSON 경계를 확인하기 위한 별도 합성 scanner이며, 대상 `app.py`를 실행하지 않는다.

```sh
node build/src/cli.js scan \
  --source "$TMP" --tools none --out "$TMP/reports" --fail-on none
```

여기서 `contract defect`는 현재 코드가 `completed` 또는 clean으로 끝나면서 같은 입력의 의미를 잘못 판정하는 경우다. `documented coverage gap`은 0.3 문서가 이미 제외한다고 밝힌 구문·경계다. 후자는 v0.3의 계약 위반으로 부르지 않고 다음 버전의 범위 확장으로 남긴다. `partial`과 exit 2가 남은 사례는 clean certification으로 둔갑하지는 않지만, 유효한 입력을 잃거나 검사 범위를 줄이는 문제로 기록한다.

## 우선순위 결과

### P0 — 중첩 SQL 주석이 닫힌 상태에서 완료된 오경고

재현 입력:

```sql
/* outer migration note
   /* nested note */
   ALTER TABLE public.documents DISABLE ROW LEVEL SECURITY;
*/
SELECT 1;
```

관찰 결과는 `exit 0`, `source.framework=completed`, `findings=1`이며 `supabase:disable-row-level-security`가 `supabase/migrations/001_init.sql:3:33`에 high/low로 생성됐다. PostgreSQL의 중첩 block comment에서는 `ALTER TABLE` 줄 전체가 주석 안에 있으므로 이 finding은 오경고다. 외부 block comment가 모두 닫혀 있어 `partial`도 표시되지 않는다.

근거는 `maskSql`이 block 상태에서 첫 `*/`만 만나면 normal로 돌아오는 [framework.ts:190-199](../../src/source/framework.ts)와, 마스킹 결과를 그대로 RLS 정규식에 넘기는 [framework.ts:342-354](../../src/source/framework.ts)다. 현재 lexer에는 중첩 깊이가 없다. 이는 주석과 문자열을 무시한다는 기존 정상 사례 계약을 깨는 실제 correctness bug다.

수정 acceptance:

- 중첩 깊이를 추적해 바깥 comment가 닫힐 때까지 본문을 마스킹하고, 위 사례는 `completed`/finding 0이어야 한다.
- 바깥 comment가 끝까지 닫히지 않으면 기존처럼 `partial`이고, false finding을 `completed`로 내보내지 않아야 한다.
- 줄 위치 보존과 단일 block comment, line comment, quoted string, dollar quote 회귀 사례를 유지한다.

### P0 — 인용된 테이블명이 같은 파일의 ENABLE 상태 추적을 깨뜨림

재현 입력:

```sql
ALTER TABLE "public"."users" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."users" ENABLE ROW LEVEL SECURITY;
```

관찰 결과는 `exit 0`, `source.framework=completed`, `findings=1`이며 첫 줄의 `supabase:disable-row-level-security` high/low가 `:1:30`에 남았다. 같은 파일의 같은 테이블에 ENABLE이 뒤따르므로 기존 unquoted 회귀 사례처럼 finding이 없어야 한다.

`maskSql`은 double-quoted 영역도 공백으로 바꾼다([framework.ts:218-232](../../src/source/framework.ts)). 그 결과 `rlsOperation`의 테이블 정규식([framework.ts:312-317](../../src/source/framework.ts))은 action은 읽지만 table을 얻지 못한다. 이후 `laterSameTableOperation`은 table이 있을 때만 비교되므로([framework.ts:348-353](../../src/source/framework.ts)) ENABLE을 연결하지 못한다. PostgreSQL migration에서 대소문자·예약어·특수문자를 보존하려는 인용 식별자는 흔하므로 실제 contract defect다.

수정 acceptance:

- masking용 text와 상태 비교용 identifier token을 분리하거나 quoted identifier를 보존해 `"public"."users"`를 두 statement에서 동일한 normalized table로 비교한다.
- 위 toggle은 `completed`/finding 0이어야 하고, quoted DISABLE만 있는 사례는 기존처럼 high candidate여야 한다.
- unquoted `public.users`와 `ALTER TABLE ONLY ...` 회귀도 모두 통과해야 한다.

### P1 — Next public env와 client import 경계가 clean으로 끝나는 문서화된 누락

재현 입력:

```text
.env.local
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=sb_secret_SYNTHETIC_SERVER_KEY_12345

app/page.tsx
"use client";
import { createClient } from "@supabase/supabase-js";
const client = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
);
export default function Page() { return null; }
```

관찰 결과는 `exit 0`, `source.framework=completed findings=0`, `source.builtin-ast=completed findings=0`이다. framework check가 검사한 recognized file은 `page.tsx` 1개이며 `.env.local`은 값이 있는 파일이어도 framework finding이 없다. `next.config.js`의 `env`에 같은 public 이름을 넣거나, client 파일이 별도의 `secret.ts`에서 `sb_secret_...`를 import하는 사례도 framework `completed findings=0`으로 재현됐다.

코드상 `.env*`는 collector에서 `secret` category가 된다([collector.ts:207-225](../../src/source/collector.ts)). framework 적용성은 migration 또는 `code` category frontend만 본다([framework.ts:153-159](../../src/source/framework.ts)). 한 frontend 파일 안에서도 local variable declaration, literal, React import만 수집하고([framework.ts:114-146](../../src/source/framework.ts), [framework.ts:390-428](../../src/source/framework.ts)), `.env` 값·`process.env` 연결·import graph는 해석하지 않는다. 이는 `preview-0.3.md:20`, `checklist.md:18`이 `.env` 빌드 의미와 전체 import 경계를 명시적으로 제외한 documented gap이다. `--tools none`은 Gitleaks도 요청하지 않으므로 위 결과는 현재 계약상 clean이지만, 사용자가 이 framework check만 보고 client boundary가 안전하다고 오해할 수 있는 중요한 후속 범위다.

수정 acceptance:

- `.env*`, `next.config.*`, `process.env.NEXT_PUBLIC_*`를 값 원문 없이 metadata/reference로 연결하고, 실제 secret 값은 보고서에 넣지 않는다.
- static relative import graph에서 client module이 참조하는 server-secret literal와 public env assignment를 후보로 올린다. dynamic import, build plugin, deployed bundle은 `unknown` 또는 별도 incomplete로 남긴다.
- client에 안전하게 노출 가능한 Supabase anon/publishable key는 기존처럼 secret으로 단정하지 않는다.
- graph·env 분석이 실행되지 않거나 수집이 잘리면 framework를 `completed` clean으로 내보내지 않고 coverage note/status를 남긴다.

### P1 — CREATE TABLE과 grant만 있는 Supabase migration은 RLS 미활성을 완료로 둠

재현 입력:

```sql
CREATE TABLE public.documents (
  id uuid primary key,
  owner_id uuid not null,
  body text
);
GRANT SELECT ON public.documents TO authenticated;
```

관찰 결과는 `exit 0`, `source.framework=completed findings=0`이다. 구현의 `migrationFindings`는 [framework.ts:342-387](../../src/source/framework.ts)에서 `DISABLE ROW LEVEL SECURITY`와 `CREATE POLICY` + PUBLIC/`true`만 검사하며 `CREATE TABLE`, `GRANT`, `ENABLE`의 관계를 추적하지 않는다. `checklist.md:19`와 `preview-0.3.md:20`이 현재 범위를 명시적 RLS 해제와 PUBLIC true 정책으로 좁혔으므로 v0.3 bug가 아니라 documented coverage gap이다. 다만 exposed table에 grant가 있고 RLS를 켠 흔적이 없는 Next/Supabase 소비자에게 가장 위험한 incomplete-clean 사례 중 하나다.

수정 acceptance:

- migration SQL 이력 안에서 `CREATE TABLE`/`ALTER TABLE` 및 grant를 table별로 수집하고, 이후 `ENABLE ROW LEVEL SECURITY`가 관찰되지 않은 exposed table을 low/medium candidate로 표시한다.
- 다른 migration에 뒤늦게 ENABLE이 있는 경우 파일명 순서와 statement 순서를 기준으로 이력 후보만 계산하고, live DB 상태라고 표현하지 않는다.
- RLS 최종 상태를 알 수 없는 동적 SQL·누락 migration·partial collection은 `unknown`/`partial`로 남긴다. policy와 grant가 함께 있어도 policy가 grant를 제거하지 않는다는 점을 결과 설명에 포함한다.

### P1 — consumer 구문을 모델링한 route context·iteration·closure·JSX HTML을 놓침

아래 사례들은 모두 정상적으로 parse되며, 기존 CLI로 `exit 0`, `source.builtin-ast=completed`, 관련 sink finding 0을 관찰했다. input/sink 전달을 분리해 확인하는 합성 코드이며, Next route의 세 번째 db 인자나 React 컴포넌트의 req.query가 실제 프레임워크 호출 계약이라는 뜻은 아니다. 후속 acceptance에는 지원하는 Next 버전의 params 형태와 실제 React props를 사용하는 유효한 예제를 추가해야 한다.

1. Next App Router의 destructured context:

   ```ts
   export function GET(request: Request, { params }: { params: { id: string } }, db: any) {
     const id = params.id;
     return db.query("select * from documents where id = " + id);
   }
   ```

   `declareParameter`는 identifier parameter가 아니면 UNKNOWN으로 시작한다([dataflow.ts:259-266](../../src/source/dataflow.ts)). 따라서 `{ params }`의 `params.id`는 input root로 연결되지 않는다.

2. request array iteration:

   ```ts
   export function GET(req: any, db: any) {
     let id: any;
     for (const candidate of req.query.ids) id = candidate;
     return db.query("select * from documents where id = " + id);
   }
   ```

   `for...of`는 iterable expression만 분석하고([dataflow.ts:387-396](../../src/source/dataflow.ts)), initializer에 값이 없는 `const candidate`를 UNKNOWN으로 선언한다([dataflow.ts:468-477](../../src/source/dataflow.ts)).

3. closure/zero-argument wrapper:

   ```ts
   function GET(req: any, db: any) {
     const id = req.query.id;
     const build = () => "select * from documents where id = " + id;
     return db.query(build());
   }
   ```

   function-like body는 별도 새 `FlowEnv`에서 다시 분석되고([dataflow.ts:248-257](../../src/source/dataflow.ts)), 인자가 없는 helper 호출의 반환은 UNKNOWN으로 끝난다([dataflow.ts:675-685](../../src/source/dataflow.ts)). 문서가 interprocedural/cross-file 흐름을 제외한다고 밝힌 documented gap이다.

4. React JSX sink:

   ```tsx
   "use client";
   export function Widget(req: any) {
     return <div dangerouslySetInnerHTML={{ __html: req.query.html }} />;
   }
   ```

   `ast.ts`의 관찰기는 binary assignment와 call만 sink로 검사한다([ast.ts:126-160](../../src/source/ast.ts)). JSX attribute/property를 sink로 연결하지 않으므로 finding이 없다. `checklist.md:10`, `preview-0.3.md:20`의 framework semantics 제외에 해당하지만, 제품 설계가 Next/React 위험 HTML을 후속 목표로 선언한 만큼 별도 P1 범위 확장으로 올린다.

추가로 `ctx.request.query.id`, `function GET({ query }, db)`, `req.params[keyFn(req.query.key)]`, `db["query"](query)`, tagged SQL template, `prisma.$queryRawUnsafe(query)`도 이 build에서 각각 finding 0이었다. `req`, `request`, `params` 등 제한된 root 이름과 정적 sink 이름만 지원한다는 [dataflow.ts:58-104](../../src/source/dataflow.ts) 및 [ast.ts:24-28](../../src/source/ast.ts) 계약의 구체적인 경계다. 우선 route context와 JSX를 먼저 보강하고, helper/property mutation은 별도 bounded phase로 유지하는 편이 안전하다.

수정 acceptance:

- `{ params }`, `{ searchParams }`, `for...of`/`for...in` binding에 root/property provenance를 부여하고 기존 shadowing·fixed reassignment 회귀를 유지한다.
- JSX `dangerouslySetInnerHTML`, `React.createElement`의 `dangerouslySetInnerHTML`, static tagged SQL/raw API를 명시적 sink 목록으로 넣되, safe parameterized query는 오경고하지 않는다.
- closure/cross-file 해석을 추가하기 전에는 현재처럼 low-confidence unknown helper와 documented unsupported scope를 유지하며 completed를 전체 프로그램 분석으로 표현하지 않는다.

## 추가로 확인한 parser 및 상태 경계

### P1 — PostgreSQL standard-conforming string의 backslash가 유효한 migration을 partial로 만듦

`standard_conforming_strings=on`인 PostgreSQL migration의 합성 입력:

```sql
SET standard_conforming_strings = on;
SELECT 'literal\';
ALTER TABLE public.documents DISABLE ROW LEVEL SECURITY;
```

실제 SQL에서는 backslash가 ordinary string의 문자이고 두 번째 줄의 quote에서 string이 닫힌다. 현재 `maskSql`은 모든 single-quoted string에서 backslash 다음 문자를 escape로 소비한다([framework.ts:202-215](../../src/source/framework.ts)). 결과는 `exit 2`, `source.framework=partial`, finding 0, “unterminated SQL comment or literal” note다. 따라서 clean으로 인증하지는 않지만 유효한 뒤쪽 DISABLE을 잃는다. E-string과 standard-conforming string을 구분하거나 PostgreSQL lexer를 사용해야 한다. acceptance는 위 사례의 `completed` + DISABLE finding과 실제 unterminated quote의 `partial`을 구별하는 것이다.

### P2 — 같은 migration 파일의 ENABLE은 추적하지만 migration 파일 간 최종 상태는 추적하지 않음

```text
supabase/migrations/001_disable.sql: ALTER TABLE public.documents DISABLE ROW LEVEL SECURITY;
supabase/migrations/002_enable.sql:  ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
```

결과는 `exit 0`, framework `completed`, 첫 파일의 high DISABLE finding 1개다. 각 파일을 독립적으로 `migrationFindings`에 넘기는 [framework.ts:431-445](../../src/source/framework.ts) 구조 때문이다. `preview-0.3.md:20`이 “파일 간 migration 최종 상태”를 제외하므로 이는 documented historical-scope limitation이다. 다음 단계에서 이력을 연결하더라도 live DB 상태나 deployment rollback window를 증명하는 finding으로 바꾸면 안 된다.

### P2 — PUBLIC true 정책의 nested predicate와 anon role은 현재 범위 밖

다음은 모두 `source.framework=completed findings=0`이었다.

```sql
CREATE POLICY open ON public.users FOR SELECT TO PUBLIC USING ((true));
CREATE POLICY open ON public.users FOR SELECT TO anon USING (true);
```

현재 predicate 정규식은 `USING (TRUE)` 또는 `WITH CHECK (TRUE)`의 단일 괄호만 찾고([framework.ts:366-384](../../src/source/framework.ts)), `anon`은 PUBLIC role로 취급하지 않는다. 이는 현재 문서가 PUBLIC true만 약속한 documented gap이다. SQL expression parser와 role/grant 모델을 함께 도입할 때 별도 candidate로 확장한다.

## Python adapter 감사

정상적인 adapter 경계는 확인됐다. Python 파일이 없으면 `not_applicable`, 지정한 Bandit 실행 파일이 없으면 `partial`/exit 2, malformed JSON은 `error`, scanner `errors` 또는 per-file metrics 누락은 `partial`이다. `runSource`는 Bandit staging을 `.py` allowlist로 제한한다([source.ts:472-484](../../src/source.ts)); adapter는 `--ignore-nosec`와 source snippet/`issue_text` 비노출을 유지한다([python.ts:231-271](../../src/source/python.ts)). 부모 baseline의 Bandit 1.9.4 실제 실행도 이 상태 경계를 통과했다.

합성 Bandit 실행 파일이 per-file metrics를 포함한 유효 JSON을 반환한 경우 `source.bandit=completed`와 finding 0/1이 정상 처리됐다. 그러나 다음 malformed-but-schema-shaped 출력도 `completed`로 통과했다.

이 adapter 사례의 실행 명령은 다음과 같고, `--bandit` 경로의 합성 파일은 구조화된 JSON만 출력했다.

```sh
node build/src/cli.js scan \
  --source "$TMP" --tools bandit --bandit "$TMP/bandit.mjs" \
  --out "$TMP/reports" --fail-on none
```

```text
app.py는 2줄뿐인데 result.line_number=999999,
result.line_range=[999999], test_id=B999
```

관찰 결과는 `exit 0`, `source.bandit=completed`, `bandit:B999 @app.py:999999`이다. `validateLineRange`는 1..10,000,000 범위만 확인하고([python.ts:179-183](../../src/source/python.ts)), 결과를 finding으로 만들 때 실제 `CollectedFile.text`의 줄 수나 `line_number`와 `line_range`의 관계를 확인하지 않는다([python.ts:233-255](../../src/source/python.ts)). Bandit 자체의 정상 출력이라고 주장하는 사례가 아니라, adapter가 외부 JSON 계약을 검증하는 경계의 실제 defect다.

수정 acceptance:

- `line_number`와 각 `line_range` 값이 매핑된 Python 파일의 실제 줄 수 이내인지 확인한다.
- line number가 range 안에 있고 range가 비어 있지 않으며, 파일별 metrics와도 모순되지 않는지 검증한다.
- 위 출력은 clean/completed가 아니라 `error` 또는 명시적 `partial`이어야 한다. 정상 Bandit output과 기존 source-snippet 비노출 테스트는 유지한다.
- `generated_at`은 현재 `requiredString`만 통과하면 임의 문자열도 허용하므로([python.ts:216-222](../../src/source/python.ts)), provenance를 결과에 의존할 다음 버전에서는 RFC 3339 검증을 별도 acceptance로 추가한다.

## 다음 iteration 권장 순서

1. **SQL lexer correctness**: nested comment depth와 quoted identifier token 보존을 먼저 고친다. 두 P0는 `completed` 결과의 실제 오경고이므로, RLS 기능 확장보다 우선 release gate에 넣는다.
2. **RLS migration inventory**: `CREATE TABLE`/grant/enable/policy를 table별 이력으로 모으되, live DB 판정과 migration 후보를 분리한다. partial collection과 dynamic SQL은 unknown으로 남긴다.
3. **Next boundary evidence**: `.env*`/`next.config.*`/relative import를 값 비노출 reference graph로 연결한다. graph를 만들 수 없는 dynamic build는 completed clean으로 표시하지 않는다.
4. **Consumer dataflow**: Next route context destructuring과 loop binding, React JSX HTML sink를 작은 단계로 추가하고 각 단계마다 vulnerable/fixed 쌍을 둔다. cross-function/type-aware 분석까지 한 번에 확장하지 않는다.
5. **Python parser hardening**: line/range/file consistency를 검증해 외부 adapter 결과가 허위 위치로 `completed`되지 않게 한다.

이 순서를 적용해도 결과는 정적 후보·관찰·advisory의 구분을 유지해야 한다. RLS live state, deployed Next bundle, 실제 Python 실행, 전체 import/build 의미는 별도 connector 또는 동적 검증 범위로 기록한다.
