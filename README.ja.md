# Wakeio Security CI

[明示的な単一引用符 SQL プロファイル v3](docs/native-dast-quoted.md)は、所有する GET エンドポイントの文字列コンテキストを手動で選択します。未認証は8段階、認証付きは10段階です。数値型 v1/v2 は自動切り替えされません。ソース 0.5.0 プレビューであり、npm 0.5.0 の公開を意味しません。

**コードと公開 Web 応答にあるよくあるセキュリティ上のミスを、ローカルと CI で見つけ、未完了の検査も可視化します。**

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md) · [実装済みチェックリスト](docs/checklist.md) · [0.4 ガイド](docs/preview-0.4.md) · [検証記録](docs/verification-0.4.md)

Wakeio Security CI は、開発者が自分のコード、公開 URL、読み取り専用 API テストを同じ形式で確認できる無料の OSS CLI と GitHub Action です。Wakeio のアカウント、契約、ホスト型 Wakeio サービス、AI トークンは必要ありません。

GitHub のソースは **0.5.0**、npm で公開済みの最新版は **0.4.0** です。0.5.0 の新機能を使う場合は [`dusen0528/wakeio-security-ci`](https://github.com/dusen0528/wakeio-security-ci) のレビュー済み Git checkout を `npm run build` でビルドしてください。npm の 0.5.0 は未公開です。機能と配布状態の詳細は [英語版](README.md)・[韓国語版](README.ko.md)を参照してください。

別の[所有 PATCH state pilot](docs/api-write-state.md)は、固定した合成 loopback fixture の保存変更と正常 owner control を確認します。SDK・CLI・専用 Action は明示的同意を要求し、元の phase gate を保持します。外部 API は入力できません。


[収集コードの分析範囲](docs/source-code-coverage.md)は、ファイル収集と各言語の分析完了を区別します。`--require-code-analysis`で未分析コードをCI gateに含められますが、新しい解析器やプロジェクト全体のcoverageを保証しません。


明示的な[認証POST JSON numeric SQL profile](docs/native-dast-post-json.md)は、固定body fieldと異なる正常値のcontrolをconsented差分検査契約に追加します。別のv4 policyを使い、既存GET policyの範囲を保持します。

## 何を確認できるか

| 入力 | 確認する内容 | このプレビューで分からないこと |
| --- | --- | --- |
| `--source DIR` | JS/TS の入力値から SQL・HTML・プロセス実行・外部リクエスト・リダイレクトへ至る候補、動的評価、限定的な Next/React・Supabase の設定、lockfile と IaC の問題。Gitleaks、OSV-Scanner、Trivy、Bandit は別途準備して選択可能 | 一般的な全ファイル間・型認識データフロー、実行時の権限や DB の状態 |
| `--url URL` | 明示した同一 origin の GET ページ、静的 JavaScript モジュール、ヘッダー・Cookie・HTTPS/トランスポートの観察・混在コンテンツ・公開情報の候補 | ブラウザ実行、ログイン後の画面、フォーム送信、全サイトの自動巡回や API fuzzing |
| `--api-policy FILE` | 環境変数で渡すテスト actor の identity、owner のリソース、別 actor が読めない保護データを、指定した GET で確認 | 書き込み・決済・endpoint 探索、サービス全体の認証・認可を網羅した証明 |

ソース検査には JS/TS の組み込み検査と、別途用意した Gitleaks、OSV-Scanner、Trivy、Bandit を選択できます。外部エンジンは自動的に信頼したり、常に準備済みだと仮定したりしません。まず `--tools none` で組み込み検査だけを実行できます。

ソース preview は [6つの Node process API](docs/process-role.md) の command・executable・argv・shell フィールドを区別します。default/false argv の除外は Node のシェル解釈だけを対象とし、プログラムオプションの安全性や実行を検証しません。この ruleset 変更は npm 公開を意味しません。

## 最短で試す

Node.js 22 以上を用意し、対象プロジェクトとは別のディレクトリに checkout します。

```sh
git clone --branch main https://github.com/dusen0528/wakeio-security-ci.git
cd wakeio-security-ci
npm ci --ignore-scripts
npm run build

node build/src/cli.js doctor --source /path/to/your-project
node build/src/cli.js scan --source /path/to/your-project --tools none
```

`doctor` は対象の適用範囲と利用可能な外部実行ファイルを確認します。対象プロジェクトの install script、hook、build、test は実行しません。`scan` の既定出力は `wakeio-security-reports/` です。

### ローカルソース

組み込み JS/TS 検査だけを実行する例です。

```sh
node build/src/cli.js scan \
  --source /path/to/your-project \
  --tools none \
  --out wakeio-security-reports
```

Gitleaks、OSV-Scanner、Trivy を使う場合は、各実行ファイルを別途レビューして準備し、必要なら `--gitleaks`、`--osv`、`--trivy` で明示します。

```sh
node build/src/cli.js doctor \
  --source /path/to/your-project \
  --tools gitleaks,osv,trivy
node build/src/cli.js scan \
  --source /path/to/your-project \
  --tools gitleaks,osv,trivy \
  --out wakeio-security-reports
```

これらのエンジンは現在のファイル、対応する lockfile、Dockerfile・Kubernetes・Terraform 設定などを検査します。Git の全履歴、コンテナイメージの CVE、実際のクラウド状態や Secret の有効性を検証するものではありません。

### 公開 URL

URL は root と追加ページを明示します。追加ページは同一 origin に限られ、root もページ数に含まれます。

```sh
node build/src/cli.js scan \
  --url https://your-app.example \
  --page https://your-app.example/pricing \
  --page https://your-app.example/docs \
  --max-pages 3 \
  --tools none
```

ローカルまたは private URL には `--allow-private` が必要です。metadata 用アドレスへのアクセス制限は残ります。ページ取得は bounded GET で、ブラウザの JavaScript 実行、ログイン、リダイレクトを利用した探索は行いません。

### 読み取り専用 API の認可確認

次の例は、リポジトリに含まれる合成ローカル API を使います。実際のサービスを対象にする例ではありません。API policy は actor の identity と、owner だけが受け取れる保護データの期待値を宣言します。policy ファイルに token を書かず、名前付き環境変数だけを指定してください。テスト用 actor は互いに異なる principal を返し、owner の positive control も通る必要があります。

ターミナル 1 で、脆弱な合成 fixture を起動したままにします。

```sh
node examples/api-authorization-demo.mjs --vulnerable
```

ターミナル 2 で、合成 actor の credential を環境変数に渡して検査します。

```sh
export WAKEIO_OWNER_AUTH='Bearer demo-owner'
export WAKEIO_OTHER_AUTH='Bearer demo-other'

node build/src/cli.js scan \
  --api-policy examples/api-authorization-policy.json \
  --allow-private \
  --out wakeio-security-reports
```

詳しい policy 形式は [API プレビュー](docs/preview-0.4-api.md) と [サンプル policy](examples/api-authorization-policy.json) を参照してください。これは明示した GET の組み合わせだけを実行します。token の期限切れ、actor の区別不能、rate limit、timeout、異常な応答は未完了として残ります。

## GitHub Actions

公開 preview では `main` を参照する簡単な workflow を使えます。

```yaml
name: wakeio-security-ci

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Check out application
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
      - name: Run Wakeio Security CI built-in checks
        uses: dusen0528/wakeio-security-ci@main
        with:
          source: .
          tools: none
          fail-on: high
          out: wakeio-security-reports
      - name: Upload Wakeio reports
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: wakeio-security-ci-reports
          path: wakeio-security-reports
          if-no-files-found: error
```

この例は外部エンジンを使わず、組み込み検査だけを実行します。本番で継続利用する場合は、`@main` の代わりにレビュー済みの commit SHA を pin し、workflow と Action の変更を確認してください。外部エンジンを使う場合は、Action の `tools` と tool cache、Bandit の実行ファイル、API credential の扱いを CI の環境に合わせて別途設定します。詳しい形は [GitHub Actions の例](examples/github-action.yml) を参照してください。

## レポートと終了コード

既定の `wakeio-security-reports/` に次のファイルを書き出します。

| ファイル | 用途 |
| --- | --- |
| `report.md` | 人が読むための範囲、候補、制限、修正の手がかり |
| `report.json` | CI や比較処理で使う構造化結果 |
| `report.sarif` | SARIF 2.1.0 対応のコードスキャン連携 |
| `agent-report.json` | scan gate・finding/check・未検証の修正状態。[契約](docs/agent-report.md) |

| 終了コード | 意味 |
| --- | --- |
| `0` | 適用可能な検査が完了し、選択した threshold 以上の finding がない |
| `1` | 選択した threshold 以上の finding がある。既定 threshold は `high` |
| `2` | 設定エラー、検査の失敗・未完了、または適用可能な検査がない |

`--fail-on none` は finding による失敗だけを無効にします。未完了の検査や setup failure は引き続き exit `2` です。exit `0` はサービス全体の安全性や認証の完全性を証明しません。

ソースプレビューは、文書に明記したバージョンの[ファイル名から process argv へのフロー](docs/source-filesystem-flow.md)をサポートします。ファイル名 callback と共有配列の蓄積を argv へ接続し、条件付きの low-confidence 候補と未完了の検査を保持します。リンク先に対応範囲と公開 advisory の検証記録があります。新しい脆弱性の発見や修正ソース全体の安全判定ではありません。公開 npm は引き続き 0.4.0 です。

## ローカル source handoff

レビュー済みの 0.5.0 ソースプレビューでは、source candidate と現在の収集済み
ソースを結び付けた非公開パケットを作成できます。公開 npm 0.4.0 には含まれません。
`FINDING_ID` とゼロ始まりの `CHECK_INDEX` を agent report の実際の値に置き換え、
レポートとパケットはすべてソースディレクトリの外に置いてください。

```sh
wakeio-security-ci handoff create --report /path/outside/your-app/before --source /path/to/your-app --finding FINDING_ID --check-index CHECK_INDEX --out /path/outside/your-app/review
wakeio-security-ci handoff finish --handoff /path/outside/your-app/review --report /path/outside/your-app/after --source /path/to/your-app --out /path/outside/your-app/recheck
```

利用者が元の scan を同じオプションで別途実行し、`after` を用意します。
Handoff は scan、モデル呼び出し、argv の生成・実行、パッチ適用をしません。
Finish は比較と **after 全体の gate** を確認します。同じ high finding も失敗し、
partial は exit `2` のままです。`not_observed` は修正の検証ではありません。
[全体の流れ、snapshot と出力先](docs/source-handoff.md)を参照してください。

## 範囲と限界

- 収集上限は既定で 1,000 ファイル、合計 25 MiB、1 ファイル 2 MiB です。`.git`、`node_modules`、`vendor`、build/cache ディレクトリ、scanner の制御ファイルは除外します。上限超過や読み取り失敗は incomplete として報告します。
- JS/TS のデータフローは bounded same-function 分析です。未知の helper、一般的な cross-file 解決、型システム全体の意味は検証しません。
- URL 検査は明示した同一 origin の GET と静的 module 取得です。ブラウザ実行、ログイン、書き込み、支払い、一般的な penetration test は行いません。
- API policy はユーザーが準備した test actor、リソース、protected canary に対する読み取り確認です。全 endpoint、全 role、実運用の auth/session、cloud/database/image の状態を自動的に検証する turnkey pentest ではありません。
- Supabase migration の RLS・grant 候補は収集した SQL の履歴に基づくもので、live database の状態を証明しません。Trivy の IaC 検査もイメージ CVE や live cloud 検査ではありません。
- finding が次の実行で見えなくなっても、修正完了の証明とは限りません。比較機能は範囲、provenance、完了状態を確認できない場合に `unverified` として exit `2` を返します。

このプレビューは turnkey penetration test、クラウド設定の完全監査、コンテナイメージの脆弱性検査、完全な認証フローの検証を提供しません。詳細な実装範囲は [チェックリスト](docs/checklist.md) にあります。

## データ処理とネットワーク

scan モードでは、Wakeio はソースを Wakeio のサーバーへアップロードせず、LLM や telemetry も使いません。ソース検査はローカルで動きます。URL と API 検査では、ユーザーが明示した target に対してネットワーク GET を送ります。

実験的な別の [repair CLI](docs/repair-preview.md) は、明示的な同意と API 認証で Codex/Claude にコードを送信できます。モデル料金が発生する場合があります。固定した検証器と用意済み Docker image で private patch と検証記録のみを生成し、元の checkout を変更・commit しません。初期対応は宣言した SQL fixture に限定されます。

外部エンジンを選択した場合は、そのエンジン固有の通信が発生します。OSV のオンライン検査では package identifier が公開 OSV サービスへ送られることがあり、Trivy は policy data を取得することがあります。`--osv-offline` は準備済みのローカル DB を要求し、オンラインへ自動 fallback しません。API credential は名前付き環境変数から読み取り、report に token や raw secret を書きません。

レポートには raw source と secret の値を含めない一方、プロジェクトパス、package identifier、URL は含まれることがあります。CI artifact の公開範囲を確認してください。

## 参考リンク

- [実装済みチェックリスト](docs/checklist.md)
- [0.4 開発プレビュー](docs/preview-0.4.md)
- [配布と初回設定](docs/preview-0.4-distribution.md)
- [API 認可プレビュー](docs/preview-0.4-api.md)
- [検証記録](docs/verification-0.4.md)
- [GitHub Actions の例](examples/github-action.yml)
- [貢献ガイド](CONTRIBUTING.md) · [セキュリティ報告](SECURITY.md) · [第三者ライセンス](THIRD_PARTY_NOTICES.md) · [Apache-2.0](LICENSE)
