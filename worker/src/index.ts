// @ts-nocheck
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { z } from 'zod'
import { nanoid } from 'nanoid'
import type { Env, SessionData } from './types'

// Durable Object: ChatRoom
export class ChatRoom {
  state: any
  env: Env
  clients: Map<string, any>
  users: Map<string, { username: string }>

  constructor(state: any, env: Env) {
    this.state = state
    this.env = env
    this.clients = new Map()
    this.users = new Map()
  }

  async fetch(req: Request) {
    const url = new URL(req.url)
    // administrative kick: notify and close sockets for target username
    if (url.pathname.endsWith('/kick')) {
      const target = url.searchParams.get('username') || ''
      if (!target) return new Response('bad request', { status: 400 })
      for (const [cid, ws] of this.clients.entries()) {
        const u = this.users.get(cid)
        if (u && u.username === target) {
          try { ws.send(JSON.stringify({ type: 'auth_error', code:'KICKED', message: '您的账号已在其他设备登录，被迫下线' })) } catch {}
          try { ws.close() } catch {}
          this.clients.delete(cid)
          this.users.delete(cid)
        }
      }
      return new Response(JSON.stringify({ ok: true }), { headers: { 'content-type': 'application/json' } })
    }
    if (url.pathname.endsWith('/presence')) {
      const users = Array.from(this.users.values()).map((u) => u.username)
      return new Response(
        JSON.stringify({ online: this.clients.size, users }),
        { headers: { 'content-type': 'application/json' } }
      )
    }

    // WebSocket upgrade
    if (req.headers.get('upgrade') !== 'websocket') {
      return new Response('Expected websocket', { status: 426 })
    }

  const token = new URL(req.url).searchParams.get('token') || ''
    const sessionRaw = token ? await this.env.SESSIONS_KV.get(`session:${token}`) : null
    if (!sessionRaw) return new Response('Unauthorized', { status: 401 })
    const session = JSON.parse(sessionRaw) as SessionData

  const pair = new (globalThis as any).WebSocketPair()
    const client = pair[0]
    const server = pair[1]

    const id = crypto.randomUUID()
    this.clients.set(id, server)
    this.users.set(id, { username: session.username })

    server.accept()

    const broadcastPresence = () => {
      const payload = JSON.stringify({ type: 'presence', online: this.clients.size, users: Array.from(this.users.values()).map(u => u.username) })
      for (const ws of this.clients.values()) {
        try { ws.send(payload) } catch {}
      }
    }

    server.addEventListener('message', async (ev: MessageEvent) => {
      try {
        // 单会话保障：若用户的当前有效 token 与本连接 token 不一致，则提示并断开
        try {
          const latest = await this.env.SESSIONS_KV.get(`user_session:${session.userId}`)
          if (latest && latest !== token) {
            try { server.send(JSON.stringify({ type: 'error', message: '当前账号已在其他设备登录，本连接将断开。' })) } catch {}
            try { server.close() } catch {}
            this.clients.delete(id)
            this.users.delete(id)
            broadcastPresence()
            return
          }
        } catch {}
        const data = JSON.parse(ev.data as string)
        const now = new Date().toISOString()
        // message schema
        const schema = z.object({
          kind: z.enum(['text','emoji','image','video','file','ai']).default('text'),
          room: z.string().default('public'),
          to: z.string().optional(),
          content: z.string().min(1)
        })
        const m = schema.parse(data)

        if (m.kind === 'ai') {
          // Persist user's prompt as a private AI item (room 'ai', to self)
          const idPrompt = nanoid()
          await this.env.DB.prepare(
            'INSERT INTO messages (id, from_user_id, to_user_id, room, content_type, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)'
          ).bind(idPrompt, session.userId, session.userId, 'ai', 'ai', m.content, now).run()

          // ask AI and send back reply only to requester
          try {
            const aiRes = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
              messages: [
                { role: 'system', content: 'You are a concise helpful chat assistant for a group chat app.' },
                { role: 'user', content: m.content }
              ]
            } as any)
            const text = (aiRes as any).response ?? (aiRes as any).text ?? JSON.stringify(aiRes)
            const idAi = nanoid()
            await this.env.DB.prepare(
              'INSERT INTO messages (id, from_user_id, to_user_id, room, content_type, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)'
            ).bind(idAi, 'ai', session.userId, 'ai', 'ai', text, new Date().toISOString()).run()
            server.send(JSON.stringify({ type: 'message', id: idAi, from: 'AI', to: session.username, room: 'ai', kind: 'ai', content: text, created_at: new Date().toISOString() }))
          } catch (e) {
            server.send(JSON.stringify({ type: 'error', message: 'AI 调用失败' }))
          }
          return
        }

        // Non-AI: insert then dispatch
        const toUserId = m.to ? await this.lookupUserId(m.to) : null
        const idMsg = nanoid()
        await this.env.DB.prepare(
          'INSERT INTO messages (id, from_user_id, to_user_id, room, content_type, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)'
        ).bind(idMsg, session.userId, toUserId, m.room, m.kind, m.content, now).run()

        const getFilename = (url: string): string | undefined => {
          try {
            const u = new URL(url, 'https://x')
            const last = decodeURIComponent((u.pathname.split('/').pop() || ''))
            const idx = last.indexOf('_')
            const name = idx >= 0 ? last.slice(idx + 1) : last
            return name || undefined
          } catch {
            return undefined
          }
        }

        const envelope = {
          type: 'message',
          id: idMsg,
          from: session.username,
          to: m.to ?? null,
          room: m.room,
          kind: m.kind,
          content: m.content,
          name: m.kind === 'file' ? getFilename(m.content) : undefined,
          created_at: now
        }

        if (m.to) {
          // DM: send to sender + target if online
          for (const [cid, ws] of this.clients.entries()) {
            const user = this.users.get(cid)
            if (!user) continue
            if (user.username === m.to || user.username === session.username) {
              try { ws.send(JSON.stringify(envelope)) } catch {}
            }
          }
        } else {
          // broadcast to all
          const payload = JSON.stringify(envelope)
          for (const ws of this.clients.values()) {
            try { ws.send(payload) } catch {}
          }
        }
      } catch (e) {
        try { server.send(JSON.stringify({ type: 'error', message: 'invalid message' })) } catch {}
      }
    })

    server.addEventListener('close', () => {
      this.clients.delete(id)
      this.users.delete(id)
      broadcastPresence()
    })

    // greet and presence
    server.send(JSON.stringify({ type: 'welcome', username: session.username }))
    ;(() => broadcastPresence())()
  return new Response(null, { status: 101, webSocket: client } as any)
  }

  private async lookupUserId(username: string): Promise<string | null> {
    const row = await this.env.DB.prepare('SELECT id FROM users WHERE username = ?1')
      .bind(username).first()
    return (row && (row as any).id) ? (row as any).id : null
  }
}

// App
const app = new Hono<{ Bindings: Env; Variables: { session?: SessionData } }>()

app.use('*', cors())

// Public media fetch (no auth) so chat recipients can view files
app.get('/media/:key{.+}', async (c) => {
  const key = c.req.param('key')
  const obj = await c.env.MEDIA.get(key)
  if (!obj) return c.notFound()
  const headers: Record<string, string> = { 'cache-control': 'public, max-age=3600' }
  if (obj.httpMetadata?.contentType) headers['content-type'] = obj.httpMetadata.contentType
  return new Response(obj.body, { headers })
})

// health
app.get('/health', (c) => c.json({ ok: true }))

// Auth helpers
const registerSchema = z.object({ username: z.string().min(3).max(32), password: z.string().min(6).max(100) })
const loginSchema = registerSchema

async function hashPassword(password: string, salt?: string): Promise<string> {
  const enc = new TextEncoder()
  const s = salt || crypto.randomUUID().replace(/-/g,'')
  const data = enc.encode(s + ':' + password)
  const buf = await crypto.subtle.digest('SHA-256', data)
  const hex = Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('')
  return `${s}:${hex}`
}
async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [s, _h] = stored.split(':')
  const calc = await hashPassword(password, s)
  return calc === stored
}

// Verify Cloudflare Turnstile token server-side
async function verifyTurnstile(token: string, env: Env, remoteAddr?: string): Promise<boolean> {
  try {
    if (!env.TURNSTILE_SECRET) return false
    const body = new URLSearchParams()
    body.set('secret', env.TURNSTILE_SECRET)
    body.set('response', token)
    if (remoteAddr) body.set('remoteip', remoteAddr)
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    })

    const j = await res.json()
    return Boolean(j && j.success)
  } catch (e) {
    return false
  }
}

app.post('/api/register', async (c) => {
  const raw = await c.req.json().catch(() => ({}))
  // turnstile token required
  const turnstileToken = (raw as any).turnstileToken || (raw as any).turnstile_token || ''
  if (!turnstileToken) return c.json({ error: '缺少人机验证 token' }, 400)
  const okTs = await verifyTurnstile(turnstileToken, c.env, c.req.header('cf-connecting-ip') || undefined)
  if (!okTs) return c.json({ error: '人机验证失败' }, 400)
  let username: string, password: string
  try {
    ;({ username, password } = registerSchema.parse(raw))
  } catch (e: any) {
    const msg = e?.issues?.[0]?.message || '用户名或密码不符合规则'
    return c.json({ error: msg }, 400)
  }
  const exists = await c.env.DB.prepare('SELECT id FROM users WHERE username = ?1').bind(username).first()
  if (exists) return c.json({ error: '用户名已存在' }, 400)
  const id = nanoid()
  const hash = await hashPassword(password)
  await c.env.DB.prepare('INSERT INTO users (id, username, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)')
    .bind(id, username, hash, new Date().toISOString()).run()
  return c.json({ ok: true })
})

app.post('/api/login', async (c) => {
  const raw = await c.req.json().catch(() => ({}))
  // turnstile token required
  const turnstileToken = (raw as any).turnstileToken || (raw as any).turnstile_token || ''
  if (!turnstileToken) return c.json({ error: '缺少人机验证 token' }, 400)
  const okTs = await verifyTurnstile(turnstileToken, c.env, c.req.header('cf-connecting-ip') || undefined)
  if (!okTs) return c.json({ error: '人机验证失败' }, 400)
  let username: string, password: string
  try {
    ;({ username, password } = loginSchema.parse(raw))
  } catch (e: any) {
    const msg = e?.issues?.[0]?.message || '用户名或密码格式不正确'
    return c.json({ error: msg }, 400)
  }
  const user = await c.env.DB.prepare('SELECT id, password_hash FROM users WHERE username = ?1').bind(username).first()
  if (!user) return c.json({ error: '用户名或密码错误' }, 400)
  const ok = await verifyPassword(password, (user as any).password_hash)
  if (!ok) return c.json({ error: '用户名或密码错误' }, 400)
  const ttl = 60 * 60 * 24 * 7
  const session: SessionData = { userId: (user as any).id, username, issuedAt: Date.now() }
  // 检测是否已有有效会话
  const oldToken = await c.env.SESSIONS_KV.get(`user_session:${session.userId}`)
  const force = String((raw as any).force || '').toLowerCase() === 'true'
  if (oldToken && !force) {
    return c.json({ error: '检测到已有在线会话，是否挤掉旧会话？', code: 'SESSION_EXISTS' }, 409)
  }
  if (oldToken && force) {
    await c.env.SESSIONS_KV.delete(`session:${oldToken}`)
    // 主动踢下旧 WebSocket 连接
    try {
      const id = c.env.ROOM.idFromName('public')
      const stub = c.env.ROOM.get(id)
      await stub.fetch(new URL('/kick?username=' + encodeURIComponent(username), c.req.url).toString())
    } catch {}
  }
  const token = nanoid()
  await c.env.SESSIONS_KV.put(`session:${token}`, JSON.stringify(session), { expirationTtl: ttl })
  await c.env.SESSIONS_KV.put(`user_session:${session.userId}`, token, { expirationTtl: ttl })
  return c.json({ token })
})

// auth middleware
app.use('/api/*', async (c, next) => {
  const auth = c.req.header('authorization') || ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null
  if (!token) return c.json({ error: '未授权' }, 401)
  const raw = await c.env.SESSIONS_KV.get(`session:${token}`)
  if (!raw) return c.json({ error: '会话过期' }, 401)
  c.set('session', JSON.parse(raw) as SessionData)
  await next()
})

app.get('/api/me', (c) => {
  return c.json(c.get('session'))
})

// 退出登录：作废当前 token，并清理 user_session 映射
app.post('/api/logout', async (c) => {
  const auth = c.req.header('authorization') || ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null
  if (!token) return c.json({ ok: true })
  const raw = await c.env.SESSIONS_KV.get(`session:${token}`)
  if (raw) {
    const session = JSON.parse(raw) as SessionData
    await c.env.SESSIONS_KV.delete(`session:${token}`)
    const cur = await c.env.SESSIONS_KV.get(`user_session:${session.userId}`)
    if (cur === token) {
      await c.env.SESSIONS_KV.delete(`user_session:${session.userId}`)
    }
  }
  return c.json({ ok: true })
})

app.post('/api/me/password', async (c) => {
  const schema = z.object({ currentPassword: z.string().min(6, '当前密码长度不足'), newPassword: z.string().min(6, '新密码长度不足') })
  const raw = await c.req.json().catch(() => ({}))
  let body: any
  try { body = schema.parse(raw) } catch (e: any) {
    const msg = e?.issues?.[0]?.message || '参数错误'
    return c.json({ error: msg }, 400)
  }
  const session = c.get('session')!
  const row = await c.env.DB.prepare('SELECT password_hash FROM users WHERE id = ?1').bind(session.userId).first()
  if (!row) return c.json({ error: '用户不存在' }, 400)
  const ok = await verifyPassword(body.currentPassword, (row as any).password_hash)
  if (!ok) return c.json({ error: '当前密码错误' }, 400)
  const newHash = await hashPassword(body.newPassword)
  await c.env.DB.prepare('UPDATE users SET password_hash = ?1 WHERE id = ?2').bind(newHash, session.userId).run()
  return c.json({ ok: true })
})

app.get('/api/me/messages', async (c) => {
  const session = c.get('session')!
  const type = (c.req.query('type') || 'all').toLowerCase()
  const q = (c.req.query('q') || '').trim()
  const page = Math.max(1, Number(c.req.query('page') || 1) || 1)
  const pageSize = Math.min(100, Math.max(1, Number(c.req.query('pageSize') || c.req.query('limit') || 20) || 20))
  const offset = (page - 1) * pageSize

  // Base filters
  const where: string[] = []
  const params: any[] = []

  if (type === 'public') {
    where.push("(m.to_user_id IS NULL AND m.room = 'public')")
  } else if (type === 'private') {
    where.push('(m.to_user_id = ?1 OR m.from_user_id = ?1)')
    params.push(session.userId)
  } else if (type === 'ai') {
    where.push('(m.content_type = \"ai\" AND (m.to_user_id = ?1 OR m.from_user_id = ?1))')
    params.push(session.userId)
  } else {
    // all: public or direct with me
    where.push('((m.to_user_id = ?1 OR m.from_user_id = ?1) OR (m.to_user_id IS NULL AND m.room = \"public\"))')
    params.push(session.userId)
  }

  if (q) {
    where.push('(m.content LIKE ? OR u.username LIKE ? OR v.username LIKE ?)')
    const like = `%${q}%`
    params.push(like, like, like)
  }

  const sql = `SELECT m.id, u.username as from_username, v.username as to_username, m.room, m.content_type, m.content, m.created_at
    FROM messages m
    LEFT JOIN users u ON u.id = m.from_user_id
    LEFT JOIN users v ON v.id = m.to_user_id
    WHERE ${where.join(' AND ')}
    ORDER BY m.created_at DESC
    LIMIT ? OFFSET ?`
  const rows = await c.env.DB.prepare(sql)
    .bind(...params, pageSize, offset).all()

  return c.json({ items: rows.results, page, pageSize })
})

app.get('/api/online', async (c) => {
  const id = c.env.ROOM.idFromName('public')
  const stub = c.env.ROOM.get(id)
  const res = await stub.fetch(new URL('/presence', c.req.url).toString())
  return new Response(res.body, res)
})

// R2 upload
app.post('/api/upload', async (c) => {
  const session = c.get('session')!
  const contentType = c.req.header('content-type') || ''
  if (!contentType.includes('multipart/form-data')) return c.json({ error: '需要 multipart/form-data' }, 400)
  const form = await c.req.formData()
  const file = form.get('file') as unknown as File
  if (!file || typeof file === 'string') return c.json({ error: '缺少文件' }, 400)
  let kind = (form.get('kind') as string) || ''
  if (!kind) {
    const t = (file as any).type || ''
    if (t.startsWith('image/')) kind = 'image'
    else if (t.startsWith('video/')) kind = 'video'
    else kind = 'file'
  }
  const key = `${session.userId}/${Date.now()}_${file.name}`
  await c.env.MEDIA.put(key, await file.stream(), { httpMetadata: { contentType: (file as any).type || undefined } })

  // 返回上传的 R2 键与推测的类型（去除 size）
  return c.json({ key, kind, name: (file as any).name ?? undefined })
})

// R2 get (authenticated variant retained for backwards compatibility)
app.get('/api/media/:key{.+}', async (c) => {
  const key = c.req.param('key')
  const obj = await c.env.MEDIA.get(key)
  if (!obj) return c.notFound()
  const headers: Record<string, string> = { 'cache-control': 'public, max-age=3600' }
  if (obj.httpMetadata?.contentType) headers['content-type'] = obj.httpMetadata.contentType
  return new Response(obj.body, { headers })
})

// （已移除：/media/meta 用于获取 size 的元数据接口）

// AI chat endpoint
app.post('/api/ai/chat', async (c) => {
  const schema = z.object({ prompt: z.string().optional(), messages: z.array(z.object({ role: z.enum(['system','user','assistant']), content: z.string() })).optional() })
  const body = schema.parse(await c.req.json())
  const messages = body.messages ?? [{ role: 'user', content: body.prompt ?? '' }]
  const resp = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct', { messages } as any)
  const text = (resp as any).response ?? (resp as any).text ?? JSON.stringify(resp)
  return c.json({ text })
})

// WebSocket entry to DO
app.get('/ws/public', async (c) => {
  const token = c.req.query('token')
  if (!token) return c.text('missing token', 400)
  const id = c.env.ROOM.idFromName('public')
  const stub = c.env.ROOM.get(id)
  const url = new URL(`/ws?token=${encodeURIComponent(token)}`, c.req.url)
  const res = await stub.fetch(url.toString(), { headers: { upgrade: 'websocket' } })
  return new Response(res.body, res)
})

export default app
