import { useEffect, useMemo, useState } from 'react'
import { Activity, AlertTriangle, Beaker, BookOpenCheck, Gauge, Layers, Menu, RefreshCw, Settings, ShieldCheck, X } from 'lucide-react'
import { getAdminToken, onUnauthorized, setAdminToken } from './api'
import { useEventStream } from './lib/hooks'
import { CommandPalette } from './components/CommandPalette'
import { Dashboard } from './pages/Dashboard'
import { Events } from './pages/Events'
import { Sessions } from './pages/Sessions'
import { Alerts } from './pages/Alerts'
import { Governance } from './pages/Governance'
import { Playground } from './pages/Playground'
import { SettingsPage } from './pages/Settings'

type Page = 'dashboard' | 'events' | 'sessions' | 'alerts' | 'rules' | 'playground' | 'settings'
const pages: Array<{ id: Page; label: string; icon: typeof Gauge }> = [
  { id: 'dashboard', label: '总览', icon: Gauge },
  { id: 'events', label: '事件', icon: Layers },
  { id: 'sessions', label: '会话', icon: Activity },
  { id: 'alerts', label: '告警', icon: AlertTriangle },
  { id: 'rules', label: '策略', icon: BookOpenCheck },
  { id: 'playground', label: '测试实验室', icon: Beaker },
  { id: 'settings', label: '设置', icon: Settings },
]

function pageFromHash(): Page {
  const hash = window.location.hash.replace(/^#\/?/, '') as Page
  return pages.some(item => item.id === hash) ? hash : 'dashboard'
}

interface Notice { id: number; text: string; time: number }

export function App() {
  const [page, setPage] = useState<Page>(pageFromHash)
  const [menuOpen, setMenuOpen] = useState(false)
  const [refresh, setRefresh] = useState(0)
  const [connected, setConnected] = useState(false)
  const [token, setToken] = useState(getAdminToken)
  const [authNeeded, setAuthNeeded] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [notices, setNotices] = useState<Notice[]>([])
  const [alertUnread, setAlertUnread] = useState(0)

  useEffect(() => {
    const handler = () => setAuthNeeded(true)
    onUnauthorized(handler)
    return () => onUnauthorized(null)
  }, [])

  useEffect(() => {
    const onHash = () => setPage(pageFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setMenuOpen(false) }
    const onKey = (event: KeyboardEvent) => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setPaletteOpen(value => !value) } }
    window.addEventListener('keydown', closeOnEscape)
    window.addEventListener('keydown', onKey)
    return () => { window.removeEventListener('keydown', closeOnEscape); window.removeEventListener('keydown', onKey) }
  }, [])

  useEventStream(token, (name, live) => {
    setConnected(live)
    if (name && ['trace.created', 'trace.completed', 'classification.completed', 'alert.created', 'alert.updated', 'rule.updated', 'event.received', 'event.completed', 'event.failed', 'event.retried'].includes(name)) {
      setRefresh(value => value + 1)
    }
    if (name === 'alert.created') {
      setAlertUnread(value => value + 1)
      pushNotice(`新告警产生`, setNotices)
    } else if (name === 'alert.updated') {
      pushNotice('告警状态已更新', setNotices)
    } else if (name === 'rule.updated') {
      pushNotice('规则已更新', setNotices)
    }
  })

  const title = pages.find(item => item.id === page)?.label

  const commands = useMemo(() => pages.map(item => ({
    id: `go-${item.id}`,
    label: `跳转：${item.label}`,
    hint: `#/${item.id}`,
    run: () => navigate(item.id),
  })).concat([{
    id: 'refresh',
    label: '刷新数据',
    hint: 'r',
    run: () => setRefresh(value => value + 1),
  }]), [])

  function navigate(target: Page) {
    if (target === 'alerts') setAlertUnread(0)
    setPage(target)
    setMenuOpen(false)
    window.location.hash = `/${target}`
  }

  function openTrace(sessionId: string | null, traceId: string) {
    const params = new URLSearchParams()
    if (sessionId) params.set('session', sessionId)
    params.set('trace', traceId)
    window.history.replaceState(null, '', `${window.location.pathname}?${params.toString()}`)
    navigate('sessions')
  }

  function openSession(sessionId: string) {
    const params = new URLSearchParams()
    params.set('session', sessionId)
    window.history.replaceState(null, '', `${window.location.pathname}?${params.toString()}`)
    navigate('sessions')
  }

  function openAlert(alertId: string) {
    navigate('alerts')
  }

  return (
    <div className="shell">
      <aside className={menuOpen ? 'sidebar open' : 'sidebar'}>
        <div className="brand"><span className="brand-mark"><ShieldCheck size={21} /></span><span>AutoMode</span></div>
        <nav aria-label="主导航">
          {pages.map(item => (
            <button key={item.id} className={page === item.id ? 'nav active' : 'nav'} onClick={() => navigate(item.id)}>
              <item.icon size={18} /><span>{item.label}</span>
              {item.id === 'alerts' && alertUnread > 0 && <span className="nav-badge">{alertUnread}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot"><span className={connected ? 'status-dot live' : 'status-dot'} /><span>{connected ? '实时连接' : '正在重连'}</span></div>
      </aside>
      {menuOpen && <button className="backdrop" aria-label="关闭导航" onClick={() => setMenuOpen(false)} />}
      <main>
        <header>
          <div className="header-main">
            <button className="icon-button mobile-menu" aria-label="打开导航" onClick={() => setMenuOpen(true)}><Menu /></button>
            <div><p className="eyebrow">ENTERPRISE AI SHADOW DLP</p><h1>{title}</h1></div>
          </div>
          <div className="header-actions">
            <button className="secondary compact" onClick={() => setPaletteOpen(true)}><span className="kbd">⌘K</span>命令</button>
            <button className="secondary compact" onClick={() => setRefresh(value => value + 1)}><RefreshCw size={16} />刷新</button>
          </div>
        </header>
        {authNeeded
          ? <AuthGate token={token} onSave={value => { setAdminToken(value); setToken(value); setAuthNeeded(false); setRefresh(r => r + 1) }} onClear={() => { setAdminToken(''); setToken(''); setAuthNeeded(false); setRefresh(r => r + 1) }} />
          : <div className="content">
            {page === 'dashboard' && <Dashboard refresh={refresh} onOpenTrace={openTrace} onOpenAlerts={() => navigate('alerts')} />}
            {page === 'sessions' && <Sessions refresh={refresh} />}
            {page === 'events' && <Events refresh={refresh} />}
            {page === 'alerts' && <Alerts refresh={refresh} onOpenTrace={openTrace} />}
            {page === 'rules' && <Governance refresh={refresh} />}
            {page === 'playground' && <Playground />}
            {page === 'settings' && <SettingsPage />}
          </div>}
      </main>
      <CommandPalette
        commands={commands}
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onOpenSession={openSession}
        onOpenAlert={openAlert}
      />
      <ToastStack notices={notices} onDismiss={id => setNotices(value => value.filter(item => item.id !== id))} />
    </div>
  )
}

let noticeId = 0
function pushNotice(text: string, setter: (updater: (value: Notice[]) => Notice[]) => void) {
  const id = ++noticeId
  setter(value => [...value, { id, text, time: Date.now() }])
  setTimeout(() => setter(value => value.filter(item => item.id !== id)), 6000)
}

function ToastStack({ notices, onDismiss }: { notices: Notice[]; onDismiss: (id: number) => void }) {
  if (!notices.length) return null
  return (
    <div className="toast-stack">
      {notices.map(notice => (
        <div className="toast" key={notice.id} role="status">
          <span>{notice.text}</span>
          <button onClick={() => onDismiss(notice.id)} aria-label="关闭通知"><X size={14} /></button>
        </div>
      ))}
    </div>
  )
}

function AuthGate({ token, onSave, onClear }: { token: string; onSave: (value: string) => void; onClear: () => void }) {
  const [draft, setDraft] = useState(token)
  return (
    <div className="content auth-wrap">
      <section className="panel auth-card" role="dialog" aria-label="管理端认证">
        <div className="panel-title"><div><h2>管理端认证</h2><p>网关启用了 <code>AUTOMODE_ADMIN_TOKEN</code>，访问控制台需要管理 Token。</p></div></div>
        <label>管理 Token<input type="password" aria-label="管理 Token" autoComplete="new-password" value={draft} onChange={event => setDraft(event.target.value)} placeholder="粘贴 AUTOMODE_ADMIN_TOKEN 的值" /></label>
        <div className="auth-actions">
          <button className="primary" disabled={!draft.trim()} onClick={() => onSave(draft.trim())}><ShieldCheck size={17} />保存并连接</button>
          {token && <button className="secondary" onClick={onClear}>清除 Token</button>}
        </div>
        <p className="auth-hint">Token 只保存在当前浏览器的本地存储中，仅用于访问本网关的管理 API。</p>
      </section>
    </div>
  )
}
