# 华为码道 CPA 插件

面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）的华为码道插件。CPA 加载 `codearts.so` 之后，可以用码道账号做 OpenAI 兼容的对话。

## 原理

插件负责登录、发现模型和转发对话。

登录在插件菜单「码道登录」里完成。插件用 PKCE 向华为要授权码，再用这个码换成刷新令牌和 STS 临时密钥。换票时带本会话的 DPoP 密钥。登录完成后，CPA 的 auth 目录里会有一份 `codearts-<用户 ID>.json`。插件再用它向码道查询当前账号能用的模型，并注册给 CPA。对话请求由插件用华为 `SDK-HMAC-SHA256` 签名，发到码道的对话接口。免费档模型会额外带 benefit 签名；账号没有对应免费档时，上游会拒绝这次调用。

在认证文件里设置了 `prefix`（例如 `codearts`）时，客户端用 `codearts/GLM-5.3` 这样的名字调用。CPA 可能已经把请求里的模型名改成 `GLM-5.3`，但请求体里仍是 `codearts/GLM-5.3`。插件会把两处都改成裸名再发给码道。前缀没有随请求传过来时，单层的 `<前缀>/<模型>` 也会去掉；含多个斜杠的名字保持原样。解析、刷新和重新登录写回同一份 `codearts-<用户>.json` 时，插件保留 CPA 和 CPAMP 已经写上的字段（`prefix`、`disabled`、`priority`、`proxy_url`、`note` 等）。STS 刷新间隔是这张票寿命的一半（华为码道目前约 2 小时，所以大约每 60 分钟刷新一次）。已经进入后半段或已经过期时，下一次在 2 分钟后。算不出寿命则不排期。刷新失败不会报 401，避免 CPA 停止后续刷新。

华为跳回本机 `http://127.0.0.1:<端口>/oauth/callback?...`。本机能打开这个页面时，码道登录页上的状态查询会完成登录。如果地址栏停在这个地址上但连接被拒绝，把地址栏里的完整 URL 贴回码道登录页。不要把地址栏原文贴进 CPA 的 OAuth 回调框。

## 远程面板

CPAMP 和 CPA 不在同一台机器上时，华为仍把浏览器送到操作者自己的 `http://127.0.0.1:<端口>/oauth/callback?...`。Chrome 显示无法连接。

这时：

1. 打开插件菜单「码道登录」，点「登录」。
2. 完成华为授权。地址栏停在连不上的本机回调时，把完整 URL 贴回同一页并提交。
3. 不需要打开 CPAMP 的 OAuth 卡片。不要把这条 URL 贴进 CPA 的 OAuth 回调框。

本机浏览器能打开回调页时，不用粘贴。码道登录页会自己查询状态并完成登录。CPA 管理界面里原有的 codearts 登录仍然可以完成本机登录。

还没换上这个版本时，可以在打开授权链接之前，把操作者机器的 `18080` 转发到 CPA 那台机器的 `127.0.0.1:18080`，并且在登录完成前保持隧道。不要把地址栏原文提交给 CPA 的 `/oauth/callback`。

## 编译

`.so` 按目标机器的架构编，并和 CPA 镜像使用同一套 glibc。用 Docker 里的 `golang:1.26-bookworm` 编译。

```bash
make test                         # 容器里跑单测
make plugin                       # 本机架构 → plugins/linux/<arch>/codearts.so
make plugin PLATFORM=linux/amd64  # 在 ARM 机器上编 x86
```

文件放进 CPA 的 `plugins/linux/arm64/` 或 `plugins/linux/amd64/`。替换后要重启 CPA 进程，新的 `.so` 才会被加载。

编好的文件在 [v0.1.12](https://github.com/dddwill8/codeartsPlugin/releases/tag/v0.1.12)：`codearts-linux-arm64.so`、`codearts-linux-amd64.so`。

码道登录页可以开关推理强度透传，并按模型把 `none`、`minimal`、`low`、`medium`、`high`、`xhigh` 以及未列出的强度改成原样、丢掉或另一档。默认开启透传，只把 `glm-5.3` 的 `none` 和 `minimal` 改成 `low`。配置写在该账号的 auth 文件里，刷新凭证时保留。

本地试用时，`make compose-up` 会拉起 CPA 并挂上刚编好的插件。接口在 `http://127.0.0.1:8317`（API 密钥 `codearts-test-key`），管理页在 `http://127.0.0.1:8317/management.html`（管理密钥 `codearts-mgmt-key`）。回调端口默认 `18080`。

## 许可证

本项目使用 MIT 许可证，详见 [LICENSE](LICENSE)。
