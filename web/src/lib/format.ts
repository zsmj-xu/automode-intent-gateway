import type { Capability, Json, Risk } from '../types'

export function formatTime(value?: string | null): string {
  return value ? new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value)) : '—'
}

export function friendlyError(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error)
  try {
    const parsed = JSON.parse(raw)
    const item = parsed.errors?.[0]
    if (item) return `${item.field || '输入'}：${item.message}${item.suggestion ? `。建议：${item.suggestion}` : ''}`
    return parsed.message || raw
  } catch {
    return raw
  }
}

export const RISK_LABEL: Record<Risk, string> = {
  low: '低', medium: '中', high: '高', critical: '严重',
}

export const CAPABILITY_LABEL: Record<Capability, string> = {
  read: '读', write: '写', execute: '执行', delete: '删除', publish: '发布', unknown: '未知',
}

export const ALIGNMENT_LABEL: Record<string, string> = {
  aligned: '对齐（在授权范围内）',
  out_of_scope: '越权（超出授权范围）',
  contradicted: '违背约束（与用户禁令冲突）',
  ambiguous: '不确定（无法判断）',
  high_impact: '高影响（需复核）',
  no_action: '无动作（纯文本）',
  pending_action: '待执行动作',
  unsafe: '不安全',
}

export function sessionTitle(value?: string | null): string {
  return value?.startsWith('trace:') ? '未绑定工作上下文' : value || '未知会话'
}

export function contentText(content: unknown): string {
  if (typeof content === 'string') return content
  if (Array.isArray(content)) {
    return content
      .map(item => (typeof item === 'string' ? item : item?.text || item?.input_text || item?.content || `[${item?.type || 'content'}]`))
      .join('')
  }
  if (content == null) return ''
  return JSON.stringify(content, null, 2)
}

export function conversationMessages(body: Json | null | undefined): Array<{ role: string; text: string }> {
  const messages = body?.messages
  if (!Array.isArray(messages)) return []
  return messages.filter(Boolean).map((message: Json) => ({
    role: message.role || 'unknown',
    text: contentText(message.content),
  }))
}

export function responseOutput(body: Json | null | undefined): { kind: 'text' | 'tool' | 'raw'; text: string; toolCalls: string[] } {
  const data = body?.data
  if (data?.choices?.[0]?.message) {
    const message = data.choices[0].message
    return {
      kind: message.tool_calls?.length ? 'tool' : 'text',
      text: contentText(message.content),
      toolCalls: (message.tool_calls || []).map((item: Json) => item.function?.name || item.name).filter(Boolean),
    }
  }
  if (typeof data?.raw === 'string') {
    const chunks: string[] = []
    const tools: string[] = []
    for (const line of data.raw.split('\n')) {
      if (!line.trim().startsWith('data:') || line.includes('[DONE]')) continue
      try {
        const event = JSON.parse(line.replace(/^data:\s*/, ''))
        const delta = event.choices?.[0]?.delta
        if (delta?.content) chunks.push(delta.content)
        for (const item of delta?.tool_calls || []) if (item.function?.name) tools.push(item.function.name)
      } catch {
        /* keep raw response available below */
      }
    }
    if (chunks.length || tools.length) return { kind: tools.length ? 'tool' : 'text', text: chunks.join(''), toolCalls: [...new Set(tools)] }
  }
  return { kind: 'raw', text: data?.raw || '', toolCalls: [] }
}

export function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}…` : value
}

export function stageLabel(stage: string): string {
  return stage === 'rules' ? 'Rules' : stage === 'fast_llm' ? 'Fast' : stage === 'deep_llm' ? 'Deep' : stage
}

export function isCapability(value: string): value is Capability {
  return ['read', 'write', 'execute', 'delete', 'publish', 'unknown'].includes(value)
}
