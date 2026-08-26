import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'

export interface Command {
  id: string
  label: ReactNode
  hint?: string
  run: () => void
}

export function CommandPalette({ commands, open, onClose }: { commands: Command[]; open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return commands
    return commands.filter(command => String(command.id).toLowerCase().includes(q))
  }, [commands, query])

  useEffect(() => {
    if (open) {
      setQuery('')
      setSelected(0)
      setTimeout(() => inputRef.current?.focus(), 0)
    }
  }, [open])

  useEffect(() => setSelected(0), [filtered.length])

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
          placeholder="输入命令或搜索 trace / session / 规则…"
          value={query}
          onChange={event => setQuery(event.target.value)}
          onKeyDown={event => {
            if (event.key === 'ArrowDown') { event.preventDefault(); setSelected(value => Math.min(value + 1, filtered.length - 1)) }
            if (event.key === 'ArrowUp') { event.preventDefault(); setSelected(value => Math.max(value - 1, 0)) }
            if (event.key === 'Enter') run(filtered[selected])
            if (event.key === 'Escape') onClose()
          }}
        />
        <div className="palette-list">
          {filtered.map((command, index) => (
            <div key={command.id} className={`palette-item ${index === selected ? 'sel' : ''}`} onMouseEnter={() => setSelected(index)} onClick={() => run(command)}>
              <span>{command.label}</span>
              {command.hint && <span className="palette-hint">{command.hint}</span>}
            </div>
          ))}
          {!filtered.length && <div className="palette-empty">无匹配命令</div>}
        </div>
        <div className="palette-foot">↑↓ 选择 · ↵ 执行 · Esc 关闭</div>
      </div>
    </div>
  )
}
