import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { api } from '../api'
import type { Alert, DLPPolicy, Session } from '../types'

export interface Command {
  id: string
  label: ReactNode
  hint?: string
  run: () => void
}

export function CommandPalette({ commands, open, onClose, onOpenSession, onOpenAlert }: {
  commands: Command[]
  open: boolean
  onClose: () => void
  onOpenSession?: (id: string) => void
  onOpenAlert?: (id: string) => void
}) {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const [searchResults, setSearchResults] = useState<Command[]>([])
  const inputRef = useRef<HTMLInputElement>(null)

  const staticFiltered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return commands
    return commands.filter(command => {
      const id = String(command.id).toLowerCase()
      const hint = String(command.hint || '').toLowerCase()
      return id.includes(q) || hint.includes(q)
    })
  }, [commands, query])

  useEffect(() => {
    const q = query.trim()
    if (!q || q.length < 2) {
      setSearchResults([])
      return
    }

    let live = true
    const timer = setTimeout(async () => {
      try {
        const [sessionsRes, alertsRes, policiesRes] = await Promise.allSettled([
          api<{ data: Session[] }>(`/api/sessions?limit=5&q=${encodeURIComponent(q)}`),
          api<{ data: Alert[] }>(`/api/alerts?limit=5`),
          api<{ data: DLPPolicy[] }>(`/api/dlp-policies?limit=5`),
        ])

        if (!live) return
        const extra: Command[] = []

        if (sessionsRes.status === 'fulfilled' && sessionsRes.value.data) {
          sessionsRes.value.data.forEach(s => {
            if (s.id.includes(q) || (s.external_session_id && s.external_session_id.includes(q)) || (s.models || []).some(m => m.includes(q))) {
              extra.push({
                id: `session-${s.id}`,
                label: `会话: ${s.external_session_id || s.id.slice(0, 8)} (${s.models?.join(', ') || 'model'})`,
                hint: '会话审计',
                run: () => onOpenSession?.(s.id),
              })
            }
          })
        }

        if (alertsRes.status === 'fulfilled' && alertsRes.value.data) {
          alertsRes.value.data.forEach(a => {
            if (a.title.includes(q) || a.reason_code.includes(q) || a.id.includes(q)) {
              extra.push({
                id: `alert-${a.id}`,
                label: `告警: ${a.title} [${a.reason_code}]`,
                hint: a.status,
                run: () => onOpenAlert?.(a.id),
              })
            }
          })
        }

        if (policiesRes.status === 'fulfilled' && policiesRes.value.data) {
          policiesRes.value.data.forEach(p => {
            if (p.name.includes(q) || p.original_text.includes(q)) {
              extra.push({
                id: `policy-${p.id}`,
                label: `策略: ${p.name}`,
                hint: p.effect,
                run: () => { window.location.hash = '/rules' },
              })
            }
          })
        }

        setSearchResults(extra)
      } catch {
        /* ignore search errors */
      }
    }, 200)

    return () => {
      live = false
      clearTimeout(timer)
    }
  }, [query, onOpenSession, onOpenAlert])

  const allItems = useMemo(() => [...searchResults, ...staticFiltered], [searchResults, staticFiltered])

  useEffect(() => {
    if (open) {
      setQuery('')
      setSelected(0)
      setSearchResults([])
      setTimeout(() => inputRef.current?.focus(), 0)
    }
  }, [open])

  useEffect(() => setSelected(0), [allItems.length])

  if (!open) return null

  function run(command: Command | undefined) {
    if (!command) return
    onClose()
    command.run()
  }

  return (
    <div className="palette" role="dialog" aria-label="命令面板" onClick={onClose}>
      <div className="palette-box" onClick={event => event.stopPropagation()}>
        <input
          ref={inputRef}
          placeholder="输入页面命令，或搜索 Trace / 会话 / 告警 / 策略…"
          value={query}
          onChange={event => setQuery(event.target.value)}
          onKeyDown={event => {
            if (event.key === 'ArrowDown') { event.preventDefault(); setSelected(value => Math.min(value + 1, allItems.length - 1)) }
            if (event.key === 'ArrowUp') { event.preventDefault(); setSelected(value => Math.max(value - 1, 0)) }
            if (event.key === 'Enter') run(allItems[selected])
            if (event.key === 'Escape') onClose()
          }}
        />
        <div className="palette-list">
          {allItems.map((command, index) => (
            <div key={command.id} className={`palette-item ${index === selected ? 'sel' : ''}`} onMouseEnter={() => setSelected(index)} onClick={() => run(command)}>
              <span>{command.label}</span>
              {command.hint && <span className="palette-hint">{command.hint}</span>}
            </div>
          ))}
          {!allItems.length && <div className="palette-empty">无匹配命令或搜索结果</div>}
        </div>
        <div className="palette-foot">↑↓ 选择 · ↵ 执行 · Esc 关闭</div>
      </div>
    </div>
  )
}
