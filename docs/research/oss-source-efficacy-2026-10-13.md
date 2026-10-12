# 공개 취약 앱의 소스 전용 효능 기준표 (2026-10-13)

이 문서는 Wakeio의 **정적 소스 검사**를 평가하기 위한 사전 지정 기준이다. 공식 저장소의 고정 커밋을 읽고 요청 입력에서 위험한 sink까지 이어지는 경로 일곱 개를 독립적으로 확인했다. 아래 항목은 저자가 의도한 취약 앱의 **known-vulnerable source**이지 새 취약점 발견, 실행 중 악용 확인, 또는 Wakeio 검출 성공을 뜻하지 않는다. 대상 앱의 의존성 설치, 빌드, 테스트, 스크립트, 서버 및 DAST 요청은 실행하지 않았다.

## 원천과 고정 상태

| 대상 | 공식 설명과 라이선스 | 로컬 고정 상태 | GitHub stars 스냅샷 |
| --- | --- | --- | ---: |
| OWASP Juice Shop | [README](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/README.md#L27-L31)는 보안 도구 실습용 insecure 앱임을 명시한다. [LICENSE](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/LICENSE)와 [README 라이선스 표기](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/README.md#L238-L243)는 MIT다. | `artifacts/oss-efficacy-2026-10-13/juice-shop`; commit `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4`; tree `730757366a3564c5c7ca556cf5f59e6111eb635b` | 14,073 ([공식 API](https://api.github.com/repos/juice-shop/juice-shop)) |
| OWASP NodeGoat | [README](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/README.md#L1-L17)는 학습용 취약 Node.js 앱이라고 밝힌다. [README 라이선스 표기](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/README.md#L160-L162) 및 [LICENSE](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/LICENSE)는 Apache-2.0이다. | `artifacts/oss-efficacy-2026-10-13/nodegoat`; commit `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`; tree `839d7b6856ec6da992d649b2423d5f9fcefdcf1f` | 2,075 ([공식 API](https://api.github.com/repos/OWASP/NodeGoat)) |

Stars는 **2026-10-12 18:25 UTC (2026-10-13 03:25 KST)**에 공식 GitHub API에서 읽은 가변 값이다. 두 checkout은 `--depth=1 --filter=blob:none`으로 복제했고 로컬 `core.hooksPath=/dev/null`로 hook 실행을 막았다. `git status --porcelain`은 비어 있었다. 공개 [벤치마크 corpus](../../benchmarks/oss-corpus.json)에 원격 URL, commit/tree, 라이선스, 확인 파일의 SHA-256을 기록했다. 추가 로컬 조사 manifest와 checkout은 무시되는 `artifacts/oss-efficacy-2026-10-13/`에 보관한다. 외부 앱 소스는 제품에 복사하지 않았다.

## 독립 확인한 양성 기준: 일곱 경로

각 행은 취약 **흐름** 하나를 센다. NodeGoat의 `eval` 세 호출은 동일한 핸들러의 한 경로로 묶는다. 열의 SHA-256은 sink가 있는 **전체 파일**의 해시다. 위치는 `repo-relative path:line:column`이며 열은 표시한 sink 토큰의 시작 위치다. `ast:*` 값은 Wakeio의 후보 rule family 매핑이며 실제 검출 결과가 아니다.

| ID / 기대 family | 요청 source → sink 및 정적 근거 | sink 위치 / 파일 SHA-256 |
| --- | --- | --- |
| J1 / `ast:sql-input-sink` | [`GET /rest/products/search` 등록](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/server.ts#L624-L631) → [`req.query.q`가 `criteria`에 저장된 뒤 SQL template에 들어감](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/routes/search.ts#L18-L24). 길이 제한은 SQL 구조 분리를 하지 않는다. | `routes/search.ts:23:5`; `6e3272ef4065d080295d995a04964e8c5e6b1e06c4b4c8ebed3234286686ee5f` |
| J2 / `ast:sql-input-sink` | [`POST /rest/user/login` 등록](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/server.ts#L621-L625) → [`req.body.email`이 SQL template에 직접 삽입](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/routes/login.ts#L32-L35)된다. 비밀번호 해시 여부와 별개로 이메일 값이 SQL 구문을 구성한다. | `routes/login.ts:34:5`; `cf11d682edff6744bcb54339bce4b2dd6da5e80f9038facd7605df857b0a0b7b` |
| J3 / NoSQL selector injection, 현재 내장 AST의 별도 rule 없음 | [`PATCH /rest/products/reviews` 등록](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/server.ts#L659-L663) → [`req.body.id`가 Mongo selector `_id`에 그대로 들어가고 `multi: true`로 갱신](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/routes/updateProductReviews.ts#L13-L24)된다. 소스의 `noSqlReviewsChallenge` 표지도 이 경로를 가리킨다. | `routes/updateProductReviews.ts:17:5` (selector `:18:7`); `711928a6d6188c2413e3df62c85db1e77f8fe7ad04e5605e6588de42e9dd6ad2` |
| J4 / `ast:open-redirect` 관련, helper 간 흐름 | [`GET /redirect`의 `query.to`](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/routes/redirect.ts#L12-L21)가 [`isRedirectAllowed`에서 허용 URL의 부분 문자열 포함 여부](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/lib/insecurity.ts#L121-L139)만 확인된 후 `res.redirect`에 전달된다. 정확한 목적지 비교가 아니므로 이 검사는 신뢰 경계가 아니다. | `routes/redirect.ts:18:7`; `f1345c3bb3a276a4e80db74f5d1eee04cd62013e8d4d7730ef92153154484607`; helper `lib/insecurity.ts:136:26`, SHA `c3496760cac6a5fde403bf739a8ab5e2536d2bbc57a6e3b6a0ac50b01a6e8b8d` |
| N1 / `ast:dynamic-code` | [`POST /contributions` 등록](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L50-L52) → [세 `req.body` 값이 `eval`에 각각 전달](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/contributions.js#L28-L41)된다. 파일 스스로 insecure use라고 표기한다. Sink는 `:32:24`, `:33:26`, `:34:22`이지만 한 흐름으로 센다. | `app/routes/contributions.js:32:24`; `196bdeaa22da4cfe8a851b1b932710b2fcedd21f14ed75d70b739ba759a01003` |
| N2 / NoSQL `$where` expression injection, 현재 내장 AST의 별도 rule 없음 | [`/allocations/:userId`의 `req.query.threshold`](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/allocations.js#L11-L24)가 DAO에 전달되어 [`$where` JavaScript expression 문자열에 삽입](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/data/allocations-dao.js#L57-L86)되고 `find`가 받는다. 주석의 수정안도 현재 코드가 입력을 정규화하지 않는다고 명시한다. | `app/data/allocations-dao.js:78:21` (`find` `:86:9`); `c6aebc971ce7f9c8b2a8f0864a500497de25a3ea0318ef94ecd57cadf6e789ea`; source 파일 SHA `b5b7da1a6b595799cf6cca402756dd9a3f6e2a8b5d712c1989d23b7f01f349a6` |
| N3 / `ast:open-redirect` | [`GET /learn`이 `req.query.url`을 바로 `res.redirect`에 전달](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L69-L73)한다. 앱 주석도 insecure redirect라고 적는다. | `app/routes/index.js:72:16`; `3ab970b2888bc1501515db24a83cc7851ac9c09d00948c652300401515185eb5` |

## 같은 저장소의 음성 대조

아래 `data/static/codefixes`는 Juice Shop이 제공하는 **별도 정적 수정 예시**다. 실제 서버에 mount된 route가 아니며 설치·테스트로 기능을 검증하지 않았다. 따라서 “이 파일에서 해당 sink 패턴이 제거되었는가”의 소스 대조에만 쓸 수 있고, 실행 중 취약점이 고쳐졌다는 음성 결과로 세지 않는다.

| 양성 대응 | 같은 저장소의 수정 예시와 한정된 음성 기대 |
| --- | --- |
| J1 | [`unionSqlInjectionChallenge_2_correct.ts:3-7`](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/codefixes/unionSqlInjectionChallenge_2_correct.ts#L1-L8), SHA `1d9469f18d5c1f5bfc37312fa8f1e5f5db953c52860f65f7d0f21ca26eeb3de0`: 요청 값을 template에 직접 삽입하지 않고 `replacements` 인자로 보낸다. 인용된 SQL의 placeholder가 따옴표 안에 있어 검색 동작까지 올바른지는 실행하지 않아 **미확인**이다. |
| J2 | [`loginJimChallenge_1_correct.ts:14-16`](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/codefixes/loginJimChallenge_1_correct.ts#L14-L17), SHA `9d41f2879260f5ecc2662b16eef16e9bd5683ee47e11736e2c978275fd3a6847`: SQL text의 자리표시자와 별도 `bind` 값으로 이메일·비밀번호 해시를 전달한다. |
| J3 | [`noSqlReviewsChallenge_3_correct.ts:5-12`](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/codefixes/noSqlReviewsChallenge_3_correct.ts#L5-L13), SHA `91a37d919710a5661f42478955841489d417504a5802be3cb26c2d78412297a8`: ID 타입이 문자열이 아니면 거부하고 여러 문서 갱신 옵션을 없앤다. |
| J4 | [`redirectChallenge_4_correct.ts:12-17`](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/codefixes/redirectChallenge_4_correct.ts#L12-L17), SHA `9cd52c7b353ae8c08a439859ab88d8d5501f96c173279988ad0b95119b66794e`: 부분 문자열 포함 대신 정확한 URL 동등 비교를 한다. |

추가로 Juice Shop의 **실제 등록 경로** [`GET /api/Addresss/:id`](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/server.ts#L477-L480)는 [`AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })`](https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/routes/address.ts#L16-L24)를 쓴다. 이는 **SQL 문자열 보간 없음**이라는 한정된 활성 경로 대조이며 전체 인증·권한 안전성을 입증하지 않는다. NodeGoat에는 N1/N2의 대체 구현이 각각 [주석](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/contributions.js#L36-L41)과 [주석](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/data/allocations-dao.js#L63-L76)으로만 남아 있으므로 활성 음성 대조에 넣지 않는다.

## 이후 효능 판정 규칙

1. **분모**는 위 고정 커밋의 양성 흐름 7개만이다. N1의 세 `eval` sink를 세 개의 독립 취약점으로 부풀리지 않는다. NoSQL 두 경로는 현재 내장 AST에 해당 전용 규칙이 없어 `known unsupported`로 따로 표시한다. 이 둘을 제외한 **지원 범위 분모는 최대 5개**이며, 실제로는 파일 수·분석량 한도와 parser 오류 등으로 평가 가능성이 줄 수 있다.
2. 검출 일치는 rule family, 고정 커밋, 같은 파일의 sink 위치와 요청 source→sink 근거를 함께 확인한다. 같은 파일의 무관한 finding, challenge 정답 파일 또는 test fixture finding을 대체 검출로 세지 않는다.
3. 검사 전체가 `partial`이어도 해당 항목에서 고정된 요청 source→sink 근거가 실제 관찰되면 `matched`로 남기고, 별도로 전체 범위 미완료를 기록한다. 반면 미관찰 항목의 파일·함수에 수집/분석 한도나 파서 오류가 있으면 `unevaluable_scope`로 두며 `not_observed`나 “취약점 없음”으로 바꾸지 않는다. 전체 범위가 미완료인 동안 지원 범위 회수율은 산출하지 않는다. 기능 범위 밖 NoSQL은 `unsupported`, 근거 없는 후보는 `needs_review`다.
4. 정적 수정 예시는 paired negative-pattern 대조로만 다룬다. 실제 등록 경로의 안전 여부는 해당 위험 sink에 한해서만 평가한다. 소스 검출만으로 DAST 재현, 고침, 프로덕션 안전성, 전체 OWASP 취약점 coverage를 주장하지 않는다.

이 기준표는 공개 저장소의 의도된 학습용 취약 코드를 읽어 정한 **예상값**이다. Wakeio 결과·재현율·정밀도 숫자는 별도 고정 입력과 비교 영수증을 만든 뒤에만 보고한다.
