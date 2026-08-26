import { useEffect, useState } from 'react'
import { api } from '../api'

export function useLoad<T>(path: string, refresh = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let live = true
    api<T>(path)
      .then(value => live && setData(value))
      .catch(err => live && setError(err.message))
    return () => { live = false }
  }, [path, refresh])
  return { data, error, setData }
}

export function sseEventName(block: string): string {
  let name = ''
  for (const line of block.split('\n')) {
    if (line.startsWith('event:')) name = line.slice(6).trim()
  }
  return name
}

export function useEventStream(token: string, onEvent: (name: string, live: boolean) => void) {
  useEffect(() => {
    let cancelled = false
    let timer: number | undefined
    let live = false
    const setLive = (value: boolean) => { if (live !== value) { live = value; onEvent('', value) } }
    const scheduleRetry = () => { if (!cancelled) timer = window.setTimeout(connect, 3000) }
    async function connect() {
      setLive(false)
      try {
        const response = await fetch('/api/events', { headers: token ? { 'x-automode-admin-token': token } : {} })
        if (!response.ok || !response.body) { scheduleRetry(); return }
        setLive(true)
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''
        try {
          for (;;) {
            const { done, value } = await reader.read()
            if (done) break
            buffer += decoder.decode(value, { stream: true })
            let sep = buffer.indexOf('\n\n')
            while (sep !== -1) {
              const block = buffer.slice(0, sep)
              buffer = buffer.slice(sep + 2)
              const name = sseEventName(block)
              if (name) onEvent(name, true)
              sep = buffer.indexOf('\n\n')
            }
          }
        } finally { reader.releaseLock() }
      } catch { /* connection dropped: retry below */ }
      scheduleRetry()
    }
    connect()
    return () => { cancelled = true; if (timer !== undefined) clearTimeout(timer) }
  }, [token])
}
