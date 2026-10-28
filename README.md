# 华为码道 CPA 插件

面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）的华为码道插件。CPA 加载 `codearts.so` 之后，可以用码道账号做 OpenAI 兼容的对话。

## 原理

插件负责登录、发现模型和转发对话。

登录在 CPA 管理界面里选 `codearts`。插件用 PKCE 向华为要授权码，再用这个码换成刷新令牌和 STS 临时密钥。换票时带本会话的 DPoP 密钥。登录完成后，CPA 的 auth 目录里会有一份 `codearts-<用户 ID>.json`。

有这份证书之后，插件向码道查询当前账号能用的模型，并注册给 CPA。对话请求由插件用华为 `SDK-HMAC-SHA256` 签名，发到码道的对话接口。免费档模型会额外带 benefit 签名；账号没有对应免费档时，上游会拒绝这次调用。

华为跳回本机时，回调页给出一条带本次登录 `state` 和 `code` 的 URL。把这一条贴回管理界面。`state` 是插件注册进 CPA 的会话 ID。

## 编译

`.so` 按目标机器的架构编，并和 CPA 镜像使用同一套 glibc。用 Docker 里的 `golang:1.26-bookworm` 编译。

```bash
make test                         # 容器里跑单测
make plugin                       # 本机架构 → plugins/linux/<arch>/codearts.so
make plugin PLATFORM=linux/amd64  # 在 ARM 机器上编 x86
```

文件放进 CPA 的 `plugins/linux/arm64/` 或 `plugins/linux/amd64/`。替换后要重启 CPA 进程，新的 `.so` 才会被加载。

编好的文件在 [v0.1.0](https://github.com/dddwill8/codeartsPlugin/releases/tag/v0.1.0)：`codearts-linux-arm64.so`、`codearts-linux-amd64.so`。

## 证书

`codearts-<用户 ID>.json` 里是 STS 临时密钥、刷新令牌、`client_id`，以及签 DPoP 用的私钥。CPA 在过期前调插件用刷新令牌续期。这个文件留在 CPA 的 auth 目录里，不要提交到仓库。

本地试用时，`make compose-up` 会拉起 CPA 并挂上刚编好的插件。接口在 `http://127.0.0.1:8317`（API 密钥 `codearts-test-key`），管理页在 `http://127.0.0.1:8317/management.html`（管理密钥 `codearts-mgmt-key`）。回调端口默认 `18080`。
