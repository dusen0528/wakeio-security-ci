# Wakeio Security CI

**コードと公開 Web 応答にあるよくあるセキュリティ上のミスを、ローカルと CI で見つけ、未完了の検査も可視化します。**

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md) · [実装済みチェックリスト](docs/checklist.md) · [0.4 ガイド](docs/preview-0.4.md) · [検証記録](docs/verification-0.4.md)

Wakeio Security CI は、開発者が自分のコード、公開 URL、読み取り専用 API テストを同じ形式で確認できる無料の OSS CLI と GitHub Action です。Wakeio のアカウント、契約、ホスト型 Wakeio サービス、AI トークンは必要ありません。

現在は **0.4.0-dev.1 の開発プレビュー**です。対象リポジトリは [`dusen0528/wakeio-security-ci`](https://github.com/dusen0528/wakeio-security-ci) の `main` ブランチです。npm にはまだ公開していないため、registry の `npx` や npm パッケージのインストールを前提にしないでください。まずレビュー済みの Git checkout を使います。

## 何を確認できるか

| 入力 | 確認する内容 | このプレビューで分からないこと |
| --- | --- | --- |
| `--source DIR` | JS/TS の入力値から SQL・HTML・プロセス実行・外部リクエスト・リダイレクトへ至る候補、動的評価、限定的な Next/React・Supabase の設定、lockfile と IaC の問題。Gitleaks、OSV-Scanner、Trivy、Bandit は別途準備して選択可能 | 一般的な全ファイル間・型認識データフロー、実行時の権限や DB の状態 |
| `--url URL` | 明示した同一 origin の GET ページ、静的 JavaScript モジュール、ヘッダー・Cookie・HTTPS/トランスポートの観察・混在コンテンツ・公開情報の候補 | ブラウザ実行、ログイン後の画面、フォーム送信、全サイトの自動巡回や API fuzzing |
| `--api-policy FILE` | 環境変数で渡すテスト actor の identity、owner のリソース、別 actor が読めない保護データを、指定した GET で確認 | 書き込み・決済・endpoint 探索、サービス全体の認証・認可を網羅した証明 |

ソース検査には JS/TS の組み込み検査と、別途用意した Gitleaks、OSV-Scanner、Trivy、Bandit を選択できます。外部エンジンは自動的に信頼したり、常に準備済みだと仮定したりしません。まず `--tools none` で組み込み検査だけを実行できます。

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

| 終了コード | 意味 |
| --- | --- |
| `0` | 適用可能な検査が完了し、選択した threshold 以上の finding がない |
| `1` | 選択した threshold 以上の finding がある。既定 threshold は `high` |
| `2` | 設定エラー、検査の失敗・未完了、または適用可能な検査がない |

`--fail-on none` は finding による失敗だけを無効にします。未完了の検査や setup failure は引き続き exit `2` です。exit `0` はサービス全体の安全性や認証の完全性を証明しません。

## 範囲と限界

- 収集上限は既定で 1,000 ファイル、合計 25 MiB、1 ファイル 2 MiB です。`.git`、`node_modules`、`vendor`、build/cache ディレクトリ、scanner の制御ファイルは除外します。上限超過や読み取り失敗は incomplete として報告します。
- JS/TS のデータフローは bounded same-function 分析です。未知の helper、一般的な cross-file 解決、型システム全体の意味は検証しません。
- URL 検査は明示した同一 origin の GET と静的 module 取得です。ブラウザ実行、ログイン、書き込み、支払い、一般的な penetration test は行いません。
- API policy はユーザーが準備した test actor、リソース、protected canary に対する読み取り確認です。全 endpoint、全 role、実運用の auth/session、cloud/database/image の状態を自動的に検証する turnkey pentest ではありません。
- Supabase migration の RLS・grant 候補は収集した SQL の履歴に基づくもので、live database の状態を証明しません。Trivy の IaC 検査もイメージ CVE や live cloud 検査ではありません。
- finding が次の実行で見えなくなっても、修正完了の証明とは限りません。比較機能は範囲、provenance、完了状態を確認できない場合に `unverified` として exit `2` を返します。

このプレビューは turnkey penetration test、クラウド設定の完全監査、コンテナイメージの脆弱性検査、完全な認証フローの検証を提供しません。詳細な実装範囲は [チェックリスト](docs/checklist.md) にあります。

## データ処理とネットワーク

Wakeio はソースを Wakeio のサーバーへアップロードせず、LLM や telemetry も使いません。ソース検査はローカルで動きます。URL と API 検査では、ユーザーが明示した target に対してネットワーク GET を送ります。

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
