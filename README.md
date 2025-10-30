# 自由乌托邦 · Free Utopia

一个使用 Cloudflare 开发者平台构建的多人在线聊天应用。

## 组件功能

### Workers（应用入口与 API 网关）
- 托管静态资源：通过 `wrangler.toml` 的 `[assets]` 将 `web/` 目录直接对外提供（登录、注册、聊天、账号管理等页面）。
- API 路由：见 `worker/src/index.ts`，主要包括：
   - 健康检查：`GET /health`
   - 静态媒体读取（免鉴权）：`GET /media/:key{.+}`（从 R2 读取并透传 Content-Type）
   - 认证与账户：`POST /api/register`、`POST /api/login`、`GET /api/me`、`POST /api/me/password`
   - 消息历史：`GET /api/me/messages`（支持类型筛选、关键词搜索、分页）
   - 媒体上传：`POST /api/upload`（接收 multipart/form-data，将文件写入 R2，返回 `key` 与推断的 `kind`）
   - AI 辅助：`POST /api/ai/chat`（REST 方式调用 Workers AI）
   - WebSocket 入口：`GET /ws/public`（将连接转发给 Durable Object）
- 鉴权中间件：对 `/api/*` 路由验证 `Authorization: Bearer <token>`，从 KV 恢复会话。

### Durable Objects（ChatRoom：长连接与房间状态）
- 单实例房间：通过 `ROOM.idFromName('public')` 确保公共聊天室在全局仅有一个实例，天然单线程，保证消息顺序与状态一致性。
- WebSocket 管理：在 DO 内完成 WS 升级，维护在线连接 `clients` 与用户名映射 `users`，在加入/离开时广播在线人数与列表（presence）。
- 消息路由：
   - 公共消息：广播给所有在线客户端。
   - 私聊消息：仅发送给发送者与目标用户两端。
   - AI 消息：将用户提问与 AI 回复分别以 `room='ai'`、`to_user_id=自己` 形式写入 D1，并只回发给请求者（不广播）。
- 持久化：所有消息在接收后立即写入 D1（`messages` 表），DO 仅保存短期内存状态。
- 在线查询：DO 暴露 `/presence`，Worker 的 `GET /api/online` 转发该信息。

### KV（SESSIONS_KV：会话存储）
- 存储会话 Token：`session:<token>`，默认 7 天过期。
- Worker 侧在中间件中读取，DO 侧在 WS 握手时验证，阻止未授权连接。

### D1（关系型存储：用户/消息）
- 表结构（见 `worker/migrations`）：
   - `users`：`id, username, password_hash, created_at`。
   - `messages`：`id, from_user_id, to_user_id, room, content_type('text'|'emoji'|'image'|'video'|'ai'), content, created_at`。
- 读写路径：
   - 注册/登录/改密：对 `users` 进行插入/查询/更新；密码采用带随机盐的 SHA-256 摘要存储与校验。
   - 聊天消息：DO 写入 `messages`；账号页 `GET /api/me/messages` 提供类型筛选（all/public/private/ai）、关键词搜索 `q`、分页 `page/pageSize`，并联表查询用户名。

### R2（对象存储：图片/视频/文件）
- 上传：`POST /api/upload` 接收文件，推断 `kind`（image/video/file），将对象写入 R2，并设置 `httpMetadata.contentType`，返回 R2 `key`。
- 公开读取：`GET /media/:key{.+}` 直接回源 R2，便于聊天消息中的媒体 URL 无需鉴权即可加载。

### Workers AI（内置 AI 助手）
- 使用模型：`@cf/meta/llama-3.1-8b-instruct`。
- 两种调用方式：
   - DO 内处理 `kind:'ai'` 的消息：写入用户提问与 AI 回复到 D1，并仅向请求者回发。
   - REST：`POST /api/ai/chat` 直接返回模型文本输出。

### Turnstile（人机验证）

在注册与登录页面集成了 Turnstile，用于减少自动化滥用。

- 前端（`web/register.html`、`web/login.html`）使用 sitekey：`0x4AAAAAAB9qtKMd4sjQ2fFD`。该 sitekey 写在页面上并由 Turnstile widget 获取 token 后随请求提交，部署时按实际 sitekey 修改 html。
- 后端（Worker）需要一个 secret 用于服务器端验证。请不要把 secret 写到前端或仓库中，而应在 Cloudflare Worker 环境中以 secret 保存，例如使用 Wrangler：

```cmd
:: 在 worker 目录下运行（会要求你粘贴/输入 secret）
npx wrangler secret put TURNSTILE_SECRET
```

当你部署或本地运行时，Worker 将通过 `TURNSTILE_SECRET` 与 Cloudflare 的验证接口（https://challenges.cloudflare.com/turnstile/v0/siteverify）验证 token，验证通过后才继续注册/登录流程。

## 开发/部署

### 1. 预备
- 安装 Node 18+、Wrangler 3
- Cloudflare 里创建：
   - KV 命名空间：SESSIONS_KV（保存 token）
   - D1 数据库：cf_chat_db
   - R2 桶：cf-chat-media
   - 开启 Workers AI（账户层）
- 将以下变量填入 `wrangler.toml` 或使用环境变量：
   - SESSIONS_KV_ID / SESSIONS_KV_PREVIEW_ID
   - D1_DB_ID

### 2. 安装依赖
在 `worker` 下安装依赖。如果你的系统未配置 npm，可使用 corepack 启用 pnpm 或 yarn。

可选命令（任选一种包管理器）：

```cmd
:: 如果已安装 npm
npm i
:: 或使用 pnpm（需要 corepack enable）
pnpm i
:: 或使用 yarn
yarn
```

### 3. 本地开发
- 运行 D1 迁移
- 本地开发 Worker

```cmd
:: 登录 Cloudflare
npx wrangler login

:: 预览/本地 D1 数据库并应用迁移
npx wrangler d1 migrations apply cf_chat_db --local --persist-to .wrangler/state

:: 本地开发
npx wrangler dev --local --persist-to .wrangler/state
```

### 4. 首次部署
- 远端迁移
- 部署 Worker

```cmd
npx wrangler d1 migrations apply cf_chat_db --remote
npx wrangler secret put TURNSTILE_SECRET
npx wrangler deploy
```

### 5. 使用说明
- 打开 Worker 预览域名，注册/登录