export interface Env {
  DB: any
  MEDIA: any
  SESSIONS_KV: any
  AI: any
  ROOM: any
}

export type User = {
  id: string
  username: string
  password_hash: string
  created_at: string
}

export type Message = {
  id: string
  from_user_id: string
  to_user_id: string | null // null for public channel
  room: string // "public" or username for DM
  content_type: "text" | "emoji" | "image" | "video" | "ai"
  content: string // text or R2 object key
  created_at: string
}

export type SessionData = {
  userId: string
  username: string
  issuedAt: number
}
