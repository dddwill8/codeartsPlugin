# CodeArts CPA 插件

面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的华为码道 / CodeArts 原生 C ABI 插件。协议参考 [HITZY2002/codearts2api](https://github.com/HITZY2002/codearts2api) 与 [Johnsheng1/codearts2api](https://github.com/Johnsheng1/codearts2api)。

插件 ID（`.so` 文件名）为 `codearts`。能力：`model_registrar`、`model_provider`、`auth_provider`、`executor`。登录走 CPA 管理界面的 OAuth，不提供插件自己的 WebUI。

## 约束

本机不安装 Go / CPA。构建、单测、CPA 启动一律在 Docker（OrbStack）中完成。

## 功能

- OAuth PKCE 登录：`https://codearts.huaweicloud.com/portal/authorize`（`client_id=codearts-agent`、`code_challenge`、`ticket_id`）
- 登录只在 `grant_type=authorization_code` + 会话 DPoP 换到 `refresh_token` 后完成；ticket 轮询只作进度，不会用无 DPoP 的 STS 落盘。回调页在绑上 `code` 后给出带本会话 `state` 和 `code` 的 URL，把这一条贴进 CPA。第一跳不要贴，地址栏原文不再作为步骤
- STS `grant_type=refresh_token` + DPoP ES256；持久化 `client_id`、DPoP 私钥 `d`、一次性 `refresh_token`、STS AK/SK/token
- `POST /api/v2/chat/completions`，华为 `SDK-HMAC-SHA256`（CanonicalURI 以 `/` 结尾）。免费档模型带已签名的 `maas_type=benefit`、`model-id`、`model-name`
- 有凭证时从 agent-center / builtin / benefit 发现模型；无凭证或发现失败时不注册离线种子
- CPA WebUI：`http://127.0.0.1:8317/management.html`，管理密钥 `codearts-mgmt-key`

## 构建与测试

`.so` 是 CGO 产物，必须按目标机器的 `GOARCH` 现编，不能把 arm64 的文件拷到 x86。

```bash
# 容器内 go test
make test

# 当前机器架构：Apple Silicon → plugins/linux/arm64/codearts.so
# x86_64 服务器 → plugins/linux/amd64/codearts.so
make plugin

# 交叉编 x86（在 ARM 机器上，走 QEMU）：
# make plugin PLATFORM=linux/amd64

# 启动 CPA（插件能力镜像，默认 eceasy/cli-proxy-api:v8.0.44，amd64/arm64 都有）
make compose-up
curl -H 'Authorization: Bearer codearts-test-key' http://127.0.0.1:8317/v1/models
# WebUI: http://127.0.0.1:8317/management.html  管理密钥 codearts-mgmt-key
```

服务器上建议仍用这份 Makefile 在 Docker `golang:1.26-bookworm` 里编，这样 glibc 和 CPA 镜像一致。不要用比 CPA 容器更新的宿主 glibc 直接 `go build` 再挂进容器。

配置在 `deploy/cpa/config.yaml` 的 `plugins.configs.codearts`：

| 字段 | 含义 |
|---|---|
| `oauth_callback_host` | 回调监听地址，容器内用 `0.0.0.0` |
| `oauth_callback_port` | 回调端口，redirect_uri 固定为 `http://127.0.0.1:<port>/oauth/callback` |
| `oauth_callback_path` | 回调路径 |
| `benefit_auto_claim` | 发现模型时尝试领取免费档 |

## OAuth

1. 打开 `http://127.0.0.1:8317/management.html`（管理密钥 `codearts-mgmt-key`），在「OAuth 登录」选择 provider `codearts`。
2. 华为第一跳只有 `secret` 和门户 `redirect`（没有 code）。回调页说明 secret 已记在本地、登录未完成，继续华为授权；不要把第一跳贴进管理界面。第二跳回调页给出 `http://127.0.0.1:<端口>/oauth/callback?code=<code>&state=<本会话 state>`，把这一条贴进 CPA。`state` 是插件注册进 CPA 的会话 ID。不要贴地址栏原文。
3. 失败、过期或贴错时在 CPA OAuth 页取消会话后重新点 `codearts`。
4. 成功后 host auth store 写入 `codearts-<user_id>.json`（STS + refresh_token + client_id + DPoP JWK）。

码道 Web：https://devcloud.cn-north-4.huaweicloud.com/chat/home （与 snap-access / STS 共用协议；直播抓包需用户会话）。
