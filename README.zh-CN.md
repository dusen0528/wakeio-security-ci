# Wakeio Security CI

**在本地和 CI 中发现代码与公开 Web 响应里的常见安全问题，并把未完成的检查也保留下来。**

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md) · [已实现的检查清单](docs/checklist.md) · [0.4 使用指南](docs/preview-0.4.md) · [验证记录](docs/verification-0.4.md)

Wakeio Security CI 是一个免费的开源 CLI 和 GitHub Action。它让开发者用同一套结果格式检查自己的代码、公开 URL 和只读 API 测试。使用时不需要 Wakeio 账号、订阅、托管 Wakeio 服务或 AI token。

当前版本是 **0.4.0-dev.1 开发预览版**。目标仓库是 [`dusen0528/wakeio-security-ci`](https://github.com/dusen0528/wakeio-security-ci) 的 `main` 分支。项目还没有发布到 npm，因此请不要假设可以从 registry 使用 `npx` 或安装 npm 包。请先使用经过审查的 Git checkout。

## 可以检查什么

| 输入 | 检查内容 | 这个预览版无法证明的内容 |
| --- | --- | --- |
| `--source DIR` | JS/TS 输入流向 SQL、HTML、进程执行、外部请求和重定向的候选问题、动态求值，以及范围有限的 Next/React、Supabase、lockfile 和 IaC 检查。Gitleaks、OSV-Scanner、Trivy 和 Bandit 可在另行准备后选择 | 通用的跨文件/类型感知数据流、运行时权限或数据库实际状态 |
| `--url URL` | 明确指定的同源 GET 页面、静态 JavaScript 模块、响应头、Cookie、HTTPS/传输层观察、混合内容和公开信息候选问题 | 浏览器执行、登录后的页面、表单提交、全站自动爬取或 API fuzzing |
| `--api-policy FILE` | 使用环境变量中的测试 actor，按 policy 检查 identity、owner 资源，以及其他 actor 不应读到的受保护数据 | 写操作、支付、endpoint 探索，以及对整个服务的认证和授权完整证明 |

源代码检查包含内置 JS/TS 规则，也可以选择单独准备的 Gitleaks、OSV-Scanner、Trivy 和 Bandit。外部引擎不会被默认视为可信或已安装；先用 `--tools none` 运行内置检查即可。

## 快速开始

准备 Node.js 22 或更高版本，在目标项目之外的目录中进行 checkout：

```sh
git clone --branch main https://github.com/dusen0528/wakeio-security-ci.git
cd wakeio-security-ci
npm ci --ignore-scripts
npm run build

node build/src/cli.js doctor --source /path/to/your-project
node build/src/cli.js scan --source /path/to/your-project --tools none
```

`doctor` 检查输入范围和可用的外部可执行文件。它不会运行目标项目的 install script、hook、build 或 test。`scan` 默认写入 `wakeio-security-reports/`。

### 本地源代码

只运行内置 JS/TS 检查：

```sh
node build/src/cli.js scan \
  --source /path/to/your-project \
  --tools none \
  --out wakeio-security-reports
```

如果要使用 Gitleaks、OSV-Scanner、Trivy，请先分别审查并准备好这些可执行文件，必要时用 `--gitleaks`、`--osv`、`--trivy` 明确指定路径。

```sh
node build/src/cli.js doctor \
  --source /path/to/your-project \
  --tools gitleaks,osv,trivy
node build/src/cli.js scan \
  --source /path/to/your-project \
  --tools gitleaks,osv,trivy \
  --out wakeio-security-reports
```

这些引擎分别检查当前文件、支持的 lockfile，以及 Dockerfile、Kubernetes、Terraform 等配置。它们不会检查完整 Git 历史、容器镜像 CVE、实际云环境状态或 Secret 是否仍然有效。

### 公开 URL

必须明确指定根页面和额外页面。额外页面必须属于同一 origin，根页面也计入页面总数。

```sh
node build/src/cli.js scan \
  --url https://your-app.example \
  --page https://your-app.example/pricing \
  --page https://your-app.example/docs \
  --max-pages 3 \
  --tools none
```

本地或 private URL 需要 `--allow-private`；metadata 地址限制仍然有效。页面检查使用有界的 GET 请求，不会执行浏览器 JavaScript、登录或借助重定向探索站点。

### 只读 API 授权检查

下面的示例使用仓库自带的合成本地 API，不针对真实服务。API policy 声明 actor 的 identity，以及只有 owner 才应收到的受保护数据值。不要把 token 写进 policy 文件，只填写命名的环境变量。测试 actor 必须返回彼此不同的 principal，并且 owner 的 positive control 也要通过。

在终端 1 中启动合成的易受攻击 fixture，并保持它运行：

```sh
node examples/api-authorization-demo.mjs --vulnerable
```

在终端 2 中，通过环境变量传入合成 actor 的 credential，然后运行检查：

```sh
export WAKEIO_OWNER_AUTH='Bearer demo-owner'
export WAKEIO_OTHER_AUTH='Bearer demo-other'

node build/src/cli.js scan \
  --api-policy examples/api-authorization-policy.json \
  --allow-private \
  --out wakeio-security-reports
```

完整的 policy 格式见 [API 预览](docs/preview-0.4-api.md) 和 [示例 policy](examples/api-authorization-policy.json)。工具只执行 policy 明确列出的 GET 组合。过期 token、无法区分的 actor、rate limit、timeout 或异常响应都会保留为未完成检查。

## GitHub Actions

公开预览可以使用下面这个引用 `main` 的 workflow：

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

这个示例只运行内置检查，不使用外部引擎。持续用于生产时，请用经过审查的 commit SHA 替换 `@main`，并审查 workflow 和 Action 的变更。需要外部引擎时，再根据 CI 环境配置 Action 的 `tools`、tool cache、Bandit 可执行文件和 API credential。更完整的示例见 [GitHub Actions 示例](examples/github-action.yml)。

## 报告和退出码

默认目录 `wakeio-security-reports/` 包含：

| 文件 | 用途 |
| --- | --- |
| `report.md` | 供人阅读的范围、候选问题、限制和修复线索 |
| `report.json` | CI 和比较流程使用的结构化结果 |
| `report.sarif` | 与 SARIF 2.1.0 工具链集成 |

| 退出码 | 含义 |
| --- | --- |
| `0` | 适用的检查已完成，且没有达到所选 threshold 的 finding |
| `1` | 存在达到所选 threshold 的 finding；默认 threshold 是 `high` |
| `2` | 配置错误、检查失败或未完成，或没有适用的安全检查 |

`--fail-on none` 只关闭由 finding 触发的失败。未完成检查和 setup failure 仍然返回 exit `2`。exit `0` 不代表整个服务安全，也不代表认证流程完整。

## 范围和限制

- 默认收集上限是 1,000 个文件、总计 25 MiB、单文件 2 MiB。`.git`、`node_modules`、`vendor`、build/cache 目录和 scanner 控制文件会被排除。超出上限或读取失败会记录为 incomplete。
- JS/TS 数据流使用有界的同函数分析。工具不会完成通用 helper 的跨文件解析，也不会进行完整类型系统分析。
- URL 检查只访问明确指定的同源 GET 页面和静态模块。不会执行浏览器、登录、写操作、支付或通用 penetration test。
- API policy 只验证用户准备的测试 actor、资源和 protected canary 的读取行为。这不是覆盖所有 endpoint、role、生产 auth/session、云环境、数据库或镜像状态的 turnkey pentest。
- Supabase migration 中的 RLS/grant 候选来自收集到的 SQL 历史，不能证明 live database 状态。Trivy 的 IaC 检查也不是容器镜像 CVE 或 live cloud 检查。
- 某个 finding 在下一次运行中消失，并不等于已修复。比较功能无法确认 scope、provenance 或完成状态时，会保留 `unverified` 并返回 exit `2`。

这个预览版不提供 turnkey penetration test、完整云配置审计、容器镜像漏洞检查或完整认证流程验证。具体规则和排除项见[检查清单](docs/checklist.md)。

## 数据处理和网络使用

Wakeio 不会把源代码上传到 Wakeio 服务器，也不调用 LLM，不发送 telemetry。源代码检查在本地运行。URL 和 API 检查会对用户明确指定的 target 发起网络 GET 请求。

选择外部引擎后，会产生该引擎自己的网络请求。OSV 在线检查可能把 package identifier 发送到公开 OSV 服务，Trivy 可能下载 policy data。`--osv-offline` 要求准备好的本地数据库，不会自动 fallback 到在线服务。API credential 只从命名环境变量读取，token 和 raw secret 不写入报告。

报告不包含 raw source 或 Secret 值，但可能包含项目路径、package identifier 和 URL。请按 CI artifact 的可见范围保存报告。

## 参考链接

- [已实现的检查清单](docs/checklist.md)
- [0.4 开发预览](docs/preview-0.4.md)
- [分发和首次配置](docs/preview-0.4-distribution.md)
- [API 授权预览](docs/preview-0.4-api.md)
- [验证记录](docs/verification-0.4.md)
- [GitHub Actions 示例](examples/github-action.yml)
- [贡献指南](CONTRIBUTING.md) · [安全报告](SECURITY.md) · [第三方许可证](THIRD_PARTY_NOTICES.md) · [Apache-2.0](LICENSE)
