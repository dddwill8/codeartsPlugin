# 华为码道 CPA 插件

面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）的华为码道插件。CPA 加载 `codearts.so` 之后，可以用码道账号做 OpenAI 兼容的对话。

## 原理

插件负责登录、发现模型和转发对话。

登录在 CPA 管理界面里选 `codearts`。插件用 PKCE 向华为要授权码，再用这个码换成刷新令牌和 STS 临时密钥。换票时带本会话的 DPoP 密钥。登录完成后，CPA 的 auth 目录里会有一份 `codearts-<用户 ID>.json`。插件再用它向码道查询当前账号能用的模型，并注册给 CPA。对话请求由插件用华为 `SDK-HMAC-SHA256` 签名，发到码道的对话接口。免费档模型会额外带 benefit 签名；账号没有对应免费档时，上游会拒绝这次调用。

华为跳回本机时，回调页给出一条带本次登录 `state` 和 `code` 的 URL。把这一条贴回管理界面。`state` 是插件注册进 CPA 的会话 ID。如果地址栏停在本机回调上但连接被拒绝，改走下面的远程面板，不要把地址栏原文贴进 CPA 的 OAuth 回调框。

## 远程面板

CPAMP 和 CPA 不在同一台机器上时，华为仍把浏览器送到操作者自己的 `http://127.0.0.1:<端口>/oauth/callback?...`。Chrome 显示无法连接，插件收不到授权码，登录卡片会停在「等待插件认证中」。

这时：

1. 不要取消 CPAMP 里的 codearts 登录，让卡片继续轮询。
2. 打开插件菜单「提交华为回调」。
3. 把地址栏里的完整 URL 贴进去并提交。不要把这条 URL 贴进 CPA 的 OAuth 回调框。
4. 回到 CPAMP，等这一轮轮询结束。认证文件写好后，卡片会变成成功。

本机浏览器能打开回调页时，不用这一步。监听器会自己收下授权码。

还没换上这个版本时，可以在打开授权链接之前，把操作者机器的 `18080` 转发到 CPA 那台机器的 `127.0.0.1:18080`，并且在登录完成前保持隧道。不要把地址栏原文提交给 CPA 的 `/oauth/callback`。

## 编译

`.so` 按目标机器的架构编，并和 CPA 镜像使用同一套 glibc。用 Docker 里的 `golang:1.26-bookworm` 编译。

```bash
make test                         # 容器里跑单测
make plugin                       # 本机架构 → plugins/linux/<arch>/codearts.so
make plugin PLATFORM=linux/amd64  # 在 ARM 机器上编 x86
```

文件放进 CPA 的 `plugins/linux/arm64/` 或 `plugins/linux/amd64/`。替换后要重启 CPA 进程，新的 `.so` 才会被加载。

编好的文件在 [v0.1.1](https://github.com/dddwill8/codeartsPlugin/releases/tag/v0.1.1)：`codearts-linux-arm64.so`、`codearts-linux-amd64.so`。

本地试用时，`make compose-up` 会拉起 CPA 并挂上刚编好的插件。接口在 `http://127.0.0.1:8317`（API 密钥 `codearts-test-key`），管理页在 `http://127.0.0.1:8317/management.html`（管理密钥 `codearts-mgmt-key`）。回调端口默认 `18080`。

## 许可证

本项目使用 MIT 许可证，详见 [LICENSE](LICENSE)。
