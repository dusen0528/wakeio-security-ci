# pg query의 statement와 bind-data 역할

Ruleset `2026-10-05.6`는 수집한 JS/TS snapshot에서 제한된 pg `Pool`/`Client`
binding과 query 인자를 구분한다. 일반 request-shaped 입력 seed 및 SQL·shell·HTML의
taint는 유지한다. 실제 DB 실행, 설치본 버전, 요청 도달성이나 SQL injection을 확정하지 않는다.
API 연구 기준은 [pg@8.23.1의 고정 소스](https://github.com/brianc/node-postgres/tree/0980cefebe0ae461da8883703be049fe13ca96cf/packages/pg)와
[공식 parameterized query 설명](https://node-postgres.com/features/queries)이다.

## 지원 범위

- ESM named `Pool`/`Client`와 import alias, top-level const CJS destructuring을 지원한다.
  `require`의 lexical shadowing과 다른 script 파일의 동명 global은 인증하지 않는다.
  ESM default pg의 직접 `new pg.Pool()`/`new pg.Client()` 및 top-level const destructuring
  한 홉도 지원한다. 추가 namespace alias, native/deep/dynamic load, instance export/import는 proof 밖이다.
- 직접 const instance의 `.query(text[, values])` 또는 `.query(config)`를 구분한다.
  같은 모듈 내부 instance를 사용하는 exported named scalar wrapper와 상대 named importer는
  기존 argument-specific summary를 사용한다. Config 객체를 함수로 전달하거나 반환하는 것은 proof 밖이다.
- 생성자는 no-arg 또는 최대 16개의 닫힌 plain literal 옵션이다. 문자열 key는
  `connectionString`, `host`, `database`, `user`, `password`, `application_name`이며
  literal 또는 unshadowed `process.env`의 고정 key 읽기를 허용한다. 숫자 key는 `port`,
  `connectionTimeoutMillis`와 Pool의 `max`, `min`, `idleTimeoutMillis`, `maxUses`,
  `maxLifetimeSeconds`로 유한한 음이 아닌 literal이다. Boolean은 `keepAlive`, `ssl`,
  Pool의 `allowExitOnIdle`이다. Custom Client, hook, Promise, stream, connection,
  spread/getter/opaque 옵션은 proof를 얻지 않는다.
- Client `connect`/`end`, Pool `end`는 no-arg 직접 expression statement 또는 결과를 버리는
  await expression statement만 허용한다. 반환값 소비·callback·Pool `connect`/`on`/`once`는
  instance 노출 가능성으로 proof를 보류한다. Client.connect의 결과가 instance일 수 있기 때문이다.
- Config는 inline plain object 또는 직접 const plain object다. 필수 `text`, optional `values`,
  고정 문자열 `name`, literal `'array'`인 `rowMode`만 허용하며 최대 4개의 고유 own key다.
  `text`/`values` shorthand도 생성 시점 값을 보존한다. 이후 scalar 재할당으로 과거 값을 바꾸지 않는다.
- Values는 fresh array/직접 const array 또는 검증된 local/relative 함수의 actual·return을 통해
  전달된 array provenance다. 모든 요소가 primitive라는 인증은 아니다. 명시적 serializer,
  getter, new, opaque 호출/escape, 추가 alias, write/mutator, container 저장은 제외 proof를 보류한다.
  Named bind-data initializer와 indexed refs도 bounded 검사하며 재할당·깊은 member mutation·
  반사 쓰기·별도 container escape를 허용하지 않는다. Computed key/function-valued field도 proof 밖이다.

```ts
import { Pool } from 'pg';
const db = new Pool();
function route(req) {
  const values = [req.query.name];
  db.query({text: 'SELECT id FROM widgets WHERE name=$1', values});
  db.query({text: req.query.statement, values: []});
}
```

첫 호출은 지원 proof가 모두 충족될 때 해당 SQL 후보만 제외한다. 두 번째는 실제 text 입력이
statement argument에 도달한 정적 후보다. 일반 `db.query({text, values})`의 모양만으로
parameterization을 인증하지 않는다.

## Proof와 한계

판단은 기본 dispatch → 닫힌 statement 역할 → fixed-text/array 제외 순서다.
Package/constructor/instance customization, `submit` own/inherited/getter, Object/String/Array의
관련 prototype 쓰기·reflection·alias/escape가 관측되면 첫 단계부터 unknown이다.
Unshadowed `Object.keys`/`entries`/`getOwnPropertyNames` 같은 pure read를 blanket veto하지 않는다.
지원하지 않는 API 인자의 text처럼 보이는 key도 실제 statement 제어 증거로 승격하지 않는다.

수집 미완료, JS/TS parse 오류, 민감 JS/TS 제외, 불완전 index는 qualification을 금지한다.
외부 코드·미수집 경로의 부작용, 이미 변경된 runtime prototype, package tampering 및 서버 내부
동적 SQL은 이 정적 모델로 인증하지 않는다. 일반 외부 호출만으로 새 incomplete를 만들지는 않는다.

Array metadata는 origin과 flat taint의 immutable snapshot이다. 명시적 serializer/function 값을
관측한 객체의 SQL data-unavailable 상태는 인자·반환·join·cache key에도 보존하며 일반 taint를 바꾸지 않는다. 동일 origin의 branch는 양쪽 proof의
AND와 taint union, 다른 origin이나 metadata 부재는 proof 폐기를 사용한다. Parameter/return refs의
write/escape를 검사하며 shape 실패는 qualifier-only unknown이다. 일반 taint와 실제 trace는 남긴다.
Sync ordinary function 반환만 SQL literal/array/config proof를 보존한다. Async/generator 호출 반환은
proof를 제거하며 await만으로 복구하지 않는다. Async body에 전달된 실제 array formal은 별도 검증한다.

기존 예산 index 300000, flow 200000, aggregate 500000 및 summary/depth/edge/alias/trace 한도는 유지한다.
Ctor key 16, config key 4, array element 64, data-expression 128 nodes/depth 16을 넘으면 제외 proof가 없다.
Proof에 필요한 relative resolver 실패는 unknown이고 전체 검사는 기존 partial/CI exit 2를 유지한다.
Parse-valid index 완료가 전체 dependency closure나 모든 flow 완료를 의미하지 않는다. 실제 phase tick 소진은 기존 partial/CI exit 2다. 추가 shape 한도 자체는 새 incomplete 사유가 아니다.

## 보고서와 CI

기존 Finding/StaticFlow schema와 정제된 JSON·SARIF·Markdown·agent-report 경로를 유지한다.

| 판단 | 공개 의미 |
|---|---|
| `statement_input` | `ast:sql-input-sink`, severity high. Title은 `Request input reaches a SQL statement text argument`. Actual text의 tainted trace는 confidence medium, input-related unknown은 low다. |
| `unknown_role` | 같은 rule/severity high, confidence low. Title은 `Input-related SQL API argument roles are unresolved`. 관측된 argument input trace만 남기고 truncated로 표시한다. Text 제어나 취약점을 확정하지 않는다. |
| `values_only_fixed_text` | 지원 조건 아래 해당 SQL 후보만 제외한다. 값의 일반 taint를 SAFE로 바꾸지 않으며 다른 sink도 그대로 검사한다. |

여러 actual context의 outcome은 statement > unknown > values 순서다. 무입력 context는 inventory만
합치며, 다른 context의 입력과 합쳐 새 unknown 후보를 만들지 않는다. 실제 text 증거를 body/values
trace로 대체하지 않는다. Candidate의 verification은 `not_run`, 취약점·수정 확인은 false다.

Metrics `sqlRoleBoundUses`는 입력 없는 호출을 포함한 actual bound call 집합을 세고,
`sqlStatementInputUses`, `sqlRoleUnknownUses`, `sqlValuesOnlyExcluded`는 입력 관련 sink 집합만 센다.
무입력 호출을 제외 성공이나 안전성 검증으로 세지 않는다. 이 metrics와 합성 회귀 결과는 운영 환경의
정확도, 전체 앱 안전성 또는 유료 제품과의 동등성을 의미하지 않는다.

## `.6`: 고정 SQL 문자열의 선택

지원 pg query에서 두 고정 문자열 중 하나를 선택하는 text도 고정 text로 다룬다.
예를 들어 요청값으로 두 literal statement를 선택하고 별도 array 값을 bind하는 경우,
기본 dispatch와 statement/values proof가 모두 충족되면 해당 SQL 후보를 제외한다.
이는 선택 조건의 권한·업무 안전성이나 SQL 실행 성공을 검증한 결과가 아니다.

SQL 전용 private scalar qualifier는 최대 UTF-16 code-unit 길이만 기록한다.
문자열 literal과 no-substitution template에서 생성하며 빈 문자열도 허용한다.
Join은 모든 branch가 고정 문자열인 경우만 유지하고, 문자열 `+`/untagged template는
모든 구성값의 proof와 합산 길이 2048 이하를 요구한다. 최대 길이 2048은 inclusive다.
분기별 원문/문자열 집합을 저장하거나 SQL 문법을 파싱하지 않는다.

지원 scalar local/relative actual-return 및 닫힌 SQL config의 생성시 snapshot에 전달하고
summary cache key에서도 구분한다. 일반 container 저장·member 대입에서는 qualifier를 버린다.
숫자나 일반 SAFE 값, opaque 호출, 입력 text, async/generator 호출 반환, 길이 초과는
qualifier를 얻지 않는다. Await만으로 복구하지 않는다. 일반 taint와 실제 source trace는 유지한다.
실제 text input은 기존 statement-input 판정이 우선이며, fixed text라도 values/dispatch proof가
없으면 기존 unknown 후보가 남는다. 길이 초과 자체는 qualifier-only unknown이고,
기존 실제 phase budget 소진의 partial/CI exit 2와 구분한다.

이 변화는 ruleset `.6`으로 기록한다. 공개 schema·finding ID 생성 알고리즘·gate는 유지하지만,
후보 집합과 버전이 바뀌어도 모든 실제 finding ID가 같다는 보장은 아니다. SQL 원문과
qualifier는 보고서에 추가하지 않으며, 다른 sink의 입력 taint나 기존 URL qualifier를 변경하지 않는다.
