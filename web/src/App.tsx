import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, Beaker, BookOpenCheck, ChevronRight, CircleCheck,
  CircleHelp, Gauge, History, Menu, RefreshCw, RotateCcw, Save, Settings,
  ShieldAlert, ShieldCheck, SlidersHorizontal, X,
} from 'lucide-react'
import { api, formatTime, getAdminToken, onUnauthorized, patch, post, setAdminToken } from './api'

type Page = 'dashboard' | 'sessions' | 'alerts' | 'rules' | 'playground' | 'settings'
type Json = Record<string, any>
function friendlyError(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error)
  try {
    const parsed = JSON.parse(raw)
    const item = parsed.errors?.[0]
    if (item) return `${item.field || '输入'}：${item.message}${item.suggestion ? `。建议：${item.suggestion}` : ''}`
    return parsed.message || raw
  } catch { return raw }
}
const pages: Array<{ id: Page; label: string; icon: typeof Gauge }> = [
  { id: 'dashboard', label: '总览', icon: Gauge },
  { id: 'sessions', label: '会话', icon: Activity },
  { id: 'alerts', label: '告警', icon: AlertTriangle },
  { id: 'rules', label: '规则', icon: BookOpenCheck },
  { id: 'playground', label: '测试实验室', icon: Beaker },
  { id: 'settings', label: '设置', icon: Settings },
]

export function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const [menuOpen, setMenuOpen] = useState(false)
  const [refresh, setRefresh] = useState(0)
  const [connected, setConnected] = useState(false)
  const [token, setToken] = useState(getAdminToken)
  const [authNeeded, setAuthNeeded] = useState(false)
  useEffect(() => {
    const handler = () => setAuthNeeded(true)
    onUnauthorized(handler)
    return () => onUnauthorized(null)
  }, [])
  useEventStream(token, (name, live) => {
    setConnected(live)
    if (name && ['trace.created', 'trace.completed', 'classification.completed', 'alert.created', 'alert.updated', 'rule.updated'].includes(name)) {
      setRefresh(value => value + 1)
    }
  })
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setMenuOpen(false) }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [])
  const title = pages.find(item => item.id === page)?.label
  return <div className="shell">
    <aside className={menuOpen ? 'sidebar open' : 'sidebar'}>
      <div className="brand"><span className="brand-mark"><ShieldCheck size={21}/></span><span>AutoMode</span></div>
      <nav aria-label="主导航">{pages.map(item => <button key={item.id} className={page === item.id ? 'nav active' : 'nav'} onClick={() => { setPage(item.id); setMenuOpen(false) }}>
        <item.icon size={18}/><span>{item.label}</span>
      </button>)}</nav>
      <div className="sidebar-foot"><span className={connected ? 'status-dot live' : 'status-dot'}/><span>{connected ? '实时连接' : '正在重连'}</span></div>
    </aside>
    {menuOpen && <button className="backdrop" aria-label="关闭导航" onClick={() => setMenuOpen(false)}/>} 
    <main>
      <header><button className="icon-button mobile-menu" aria-label="打开导航" onClick={() => setMenuOpen(true)}><Menu/></button><div><p className="eyebrow">INTENT SECURITY CONSOLE</p><h1>{title}</h1></div><button className="secondary compact" onClick={() => setRefresh(value => value + 1)}><RefreshCw size={16}/>刷新</button></header>
      {authNeeded
        ? <AuthGate token={token} onSave={value => { setAdminToken(value); setToken(value); setAuthNeeded(false); setRefresh(r => r + 1) }} onClear={() => { setAdminToken(''); setToken(''); setAuthNeeded(false); setRefresh(r => r + 1) }}/>
        : <div className="content">
          {page === 'dashboard' && <Dashboard refresh={refresh}/>} 
          {page === 'sessions' && <Sessions refresh={refresh}/>} 
          {page === 'alerts' && <Alerts refresh={refresh}/>} 
          {page === 'rules' && <Rules refresh={refresh}/>} 
          {page === 'playground' && <Playground/>} 
          {page === 'settings' && <SettingsPage/>} 
        </div>}
    </main>
  </div>
}

function AuthGate({ token, onSave, onClear }: { token: string; onSave: (value: string) => void; onClear: () => void }) {
  const [draft, setDraft] = useState(token)
  return <div className="content auth-wrap">
    <section className="panel auth-card" role="dialog" aria-label="管理端认证">
      <div className="panel-title"><div><h2>管理端认证</h2><p>网关启用了 <code>AUTOMODE_ADMIN_TOKEN</code>，访问控制台需要管理 Token。</p></div></div>
      <label>管理 Token<input type="password" aria-label="管理 Token" autoComplete="new-password" value={draft} onChange={event => setDraft(event.target.value)} placeholder="粘贴 AUTOMODE_ADMIN_TOKEN 的值"/></label>
      <div className="auth-actions">
        <button className="primary" disabled={!draft.trim()} onClick={() => onSave(draft.trim())}><ShieldCheck size={17}/>保存并连接</button>
        {token && <button className="secondary" onClick={onClear}>清除 Token</button>}
      </div>
      <p className="auth-hint">Token 只保存在当前浏览器的本地存储中，仅用于访问本网关的管理 API。</p>
    </section>
  </div>
}

function useEventStream(token: string, onEvent: (name: string, live: boolean) => void) {
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

function sseEventName(block: string): string {
  let name = ''
  for (const line of block.split('\n')) {
    if (line.startsWith('event:')) name = line.slice(6).trim()
  }
  return name
}

function useLoad<T>(path: string, refresh = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  useEffect(() => { let live = true; api<T>(path).then(value => live && setData(value)).catch(err => live && setError(err.message)); return () => { live = false } }, [path, refresh])
  return { data, error }
}

function Dashboard({ refresh }: { refresh: number }) {
  const { data, error } = useLoad<Json>('/api/dashboard', refresh)
  const alerts = useLoad<{data: Json[]}>('/api/alerts?limit=5&status=open', refresh).data?.data || []
  if (error) return <ErrorState message={error}/>
  if (!data) return <Loading/>
  const total = Math.max(data.trace_count || 1, 1)
  const allow = data.decisions?.allow || 0
  const alerted = data.decisions?.alert || 0
  const latency = data.classification_latency_ms || {}
  return <>
    <section className="health-grid" aria-label="服务健康状态">
      {(['gateway', 'upstream', 'fast', 'deep'] as const).map(key => <article className="health-card" key={key}><span>{({gateway: 'Gateway', upstream: '上游模型', fast: 'Fast LLM', deep: 'Deep LLM'})[key]}</span><Health status={data.health?.[key] || 'unknown'}/></article>)}
    </section>
    <section className="metric-grid">
      <Metric label="模型调用" value={data.trace_count} detail="已记录 Trace"/>
      <Metric label="活跃会话" value={data.session_count} detail="按 Agent 会话聚合"/>
      <Metric label="允许率" value={`${Math.round(allow / total * 100)}%`} detail={`${allow} 次直接或复核允许`}/>
      <Metric label="告警率" value={`${Math.round((data.alert_rate || 0) * 100)}%`} detail={`${data.open_alert_count} 个开放 / ${alerted} 次累计`} tone="danger"/>
    </section>
    <div className="two-column">
      <section className="panel"><PanelTitle title="判定分布" subtitle="Rules / Fast / Deep 实际调用量"/><div className="bars">
        {['rules', 'fast_llm', 'deep_llm'].map((stage, index) => <div className="bar-row" key={stage}><span>{['Rules', 'Fast LLM', 'Deep LLM'][index]}</span><div className="bar-track"><i style={{width: `${Math.max(3, ((data.stage_counts?.[stage] || 0) / total) * 100)}%`}}/></div><b>{data.stage_counts?.[stage] || 0}</b></div>)}
      </div></section>
      <section className="panel"><PanelTitle title="分类延迟" subtitle="完整判定管线耗时"/><div className="latency-grid"><Metric label="P50" value={`${Number(latency.p50 || 0).toFixed(1)} ms`} detail="中位数"/><Metric label="P95" value={`${Number(latency.p95 || 0).toFixed(1)} ms`} detail="尾部延迟"/></div><div className="reason-list"><b>高频原因</b>{data.top_reasons?.length ? <ul className="rank-list">{data.top_reasons.slice(0, 3).map((item: Json) => <li key={item.reason_code}><code>{item.reason_code}</code><b>{item.count}</b></li>)}</ul> : <span>暂无告警原因</span>}</div></section>
    </div>
    <section className="panel"><PanelTitle title="最新开放告警" subtitle="需要操作员关注的工具动作"/>{alerts.length ? <AlertTable rows={alerts}/> : <Empty text="当前没有开放告警"/>}</section>
  </>
}

function Sessions({ refresh }: { refresh: number }) {
  const initial = useMemo(() => new URLSearchParams(window.location.search), [])
  const [filters, setFilters] = useState({
    since: initial.get('since') || '', protocol: initial.get('protocol') || '', model: initial.get('model') || '',
    risk: initial.get('risk') || '', decision: initial.get('decision') || '', capability: initial.get('capability') || '',
  })
  const query = useMemo(() => {
    const value = new URLSearchParams({ limit: '100' })
    Object.entries(filters).forEach(([key, item]) => item && value.set(key, item))
    return value.toString()
  }, [filters])
  useEffect(() => { window.history.replaceState(null, '', `${window.location.pathname}?${query}`) }, [query])
  const { data, error } = useLoad<{data: Json[]}>(`/api/sessions?${query}`, refresh)
  const [selected, setSelected] = useState<string | null>(null)
  const update = (key: keyof typeof filters, value: string) => setFilters(current => ({ ...current, [key]: value }))
  if (error) return <ErrorState message={error}/>
  const rows = data?.data || []
  return <div className="master-detail">
    <section className="panel list-panel"><PanelTitle title="Agent 会话" subtitle={`${rows.length} 个匹配会话`}/><div className="session-filters" aria-label="会话筛选">
      <label>开始日期<input type="date" value={filters.since} onChange={event => update('since', event.target.value)}/></label>
      <label>协议<select value={filters.protocol} onChange={event => update('protocol', event.target.value)}><option value="">全部</option><option value="anthropic_messages">Anthropic</option><option value="openai_chat_completions">OpenAI Chat</option><option value="openai_responses">OpenAI Responses</option></select></label>
      <label>模型<input placeholder="模型精确名称" value={filters.model} onChange={event => update('model', event.target.value)}/></label>
      <label>风险<select value={filters.risk} onChange={event => update('risk', event.target.value)}><option value="">全部</option>{['low','medium','high','critical'].map(v => <option key={v}>{v}</option>)}</select></label>
      <label>判定<select value={filters.decision} onChange={event => update('decision', event.target.value)}><option value="">全部</option><option value="allow">allow</option><option value="alert">alert</option></select></label>
      <label>能力<select value={filters.capability} onChange={event => update('capability', event.target.value)}><option value="">全部</option>{['read','write','execute','delete','publish','unknown'].map(v => <option key={v}>{v}</option>)}</select></label>
      <button className="secondary clear-filter" onClick={() => setFilters({ since: '', protocol: '', model: '', risk: '', decision: '', capability: '' })}>清空</button>
    </div>{rows.length ? <div className="session-list">{rows.map(row => <button key={row.id} className={selected === row.id ? 'session-row selected' : 'session-row'} onClick={() => setSelected(row.id)}><div><b>{row.external_session_id}</b><span>{row.models?.join(', ') || '未知模型'}</span></div><Risk level={row.max_risk}/><span>{row.call_count} 次</span><span>{formatTime(row.last_seen_at)}</span><ChevronRight size={17}/></button>)}</div> : <Empty text="当前筛选条件下没有会话"/>}</section>
    {selected ? <SessionDetail id={selected} refresh={refresh} onClose={() => setSelected(null)}/> : <section className="panel detail-empty"><Activity size={30}/><h2>选择一个会话</h2><p>查看用户输入、工具动作与三级判定瀑布。</p></section>}
  </div>
}

function SessionDetail({ id, refresh, onClose }: { id: string; refresh: number; onClose: () => void }) {
  const session = useLoad<Json>(`/api/sessions/${id}`, refresh).data
  const timeline = useLoad<{data: Json[]}>(`/api/sessions/${id}/timeline`, refresh).data?.data || []
  const grouped = useMemo(() => timeline.reduce((acc: Record<string, Json[]>, item) => ((acc[item.trace_id] ||= []).push(item), acc), {}), [timeline])
  return <section className="panel detail-panel"><div className="panel-heading"><div><p className="eyebrow">SESSION DETAIL</p><h2>{session?.external_session_id || '加载中'}</h2></div><button className="icon-button" aria-label="关闭详情" onClick={onClose}><X/></button></div>
    {Object.entries(grouped).map(([trace, items]) => <TraceWaterfall key={trace} trace={trace} items={items}/>)}</section>
}

function TraceWaterfall({ trace, items }: { trace: string; items: Json[] }) {
  const user = items.find(item => item.type === 'user_message')
  const action = items.find(item => item.type === 'tool_action')
  const stages = items.filter(item => item.type === 'classification_stage')
  const final = items.find(item => item.type === 'final_decision')
  return <article className="trace-card"><div className="trace-meta"><code>{trace.slice(0, 8)}</code><span>{formatTime(user?.at)}</span></div><blockquote>{user?.text || '无文本用户输入'}</blockquote>{action && <div className="action-line"><b>{action.tool_name}</b><span>{action.capability}</span><code>{action.target || '—'}</code></div>}
    <div className="waterfall">{['rules', 'fast_llm', 'deep_llm'].map(stage => { const hit = stages.find(item => item.stage === stage); return <div className={hit ? 'stage done' : 'stage skipped'} key={stage}><span>{stage === 'rules' ? 'Rules' : stage === 'fast_llm' ? 'Fast' : 'Deep'}</span><b>{hit?.verdict || '未触发'}</b>{hit ? <><small>{hit.status} · {hit.model || '本地规则'} · {Number(hit.latency_ms || 0).toFixed(1)} ms</small><code>{hit.reason_code}</code><small title={hit.reason}>{hit.reason || '无说明'}</small>{hit.evidence?.length > 0 && <small title={hit.evidence.join('\n')}>证据：{hit.evidence.join('；')}</small>}{hit.matched_rules?.length > 0 && <small>规则 {hit.matched_rules.join(', ')}</small>}</> : <small>未触发</small>}</div> })}<div className={final?.decision === 'alert' ? 'stage final danger' : 'stage final safe'}><span>最终</span><b>{final?.decision || 'pending'}</b><small>{final?.stage || '—'}</small></div></div>
  </article>
}

function Alerts({ refresh }: { refresh: number }) {
  const { data, error } = useLoad<{data: Json[]}>('/api/alerts?limit=200', refresh)
  const [localRefresh, setLocalRefresh] = useState(0)
  const rows = useLoad<{data: Json[]}>(`/api/alerts?limit=200&v=${localRefresh + refresh}`, refresh + localRefresh).data?.data || data?.data || []
  async function setStatus(id: string, status: string) { await patch(`/api/alerts/${id}`, { status }); setLocalRefresh(v => v + 1) }
  if (error) return <ErrorState message={error}/>
  return <section className="panel"><PanelTitle title="告警中心" subtitle="观察模式只记录和告警，不阻断 Agent"/>{rows.length ? <div className="alert-cards">{rows.map(row => <article className="alert-card" key={row.id}><div className="alert-head"><Risk level={row.severity}/><span className="status-pill">{row.status}</span><time>{formatTime(row.created_at)}</time></div><h2>{row.title}</h2><code>{row.reason_code}</code><p>{row.reason}</p><div className="evidence"><b>授权证据</b>{row.evidence?.map((line: string) => <span key={line}>{line}</span>)}</div><div className="actions"><a href="#" onClick={event => event.preventDefault()}>Trace {row.trace_id.slice(0, 8)}</a><select aria-label="更新告警状态" value={row.status} onChange={event => setStatus(row.id, event.target.value)}><option value="open">open</option><option value="acknowledged">acknowledged</option><option value="false_positive">false_positive</option><option value="resolved">resolved</option></select></div></article>)}</div> : <Empty text="还没有产生告警"/>}</section>
}

function Rules({ refresh }: { refresh: number }) {
  const { data } = useLoad<{data: Json[]}>('/api/rules', refresh)
  const [text, setText] = useState('用户明确说不要 push 时，任何 git push 都告警。')
  const [preview, setPreview] = useState<Json | null>(null)
  const [error, setError] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [testUser, setTestUser] = useState('检查代码，但不要 push。')
  const [testTool, setTestTool] = useState('Bash')
  const [testArgs, setTestArgs] = useState('{"command":"git push origin main"}')
  const [testResult, setTestResult] = useState<Json | null>(null)
  const [busy, setBusy] = useState('')
  const [status, setStatus] = useState('')
  const [history, setHistory] = useState<{rule: Json; versions: Json[]} | null>(null)
  const [localRefresh, setLocalRefresh] = useState(0)
  const rows = useLoad<{data: Json[]}>(`/api/rules?v=${refresh + localRefresh}`, refresh + localRefresh).data?.data || data?.data || []
  async function compile() { setError(''); setStatus(''); setBusy('compile'); try { setPreview(await post('/api/rules/compile', { text })); setTestResult(null) } catch (err) { setError(friendlyError(err)) } finally { setBusy('') } }
  async function testPreview() { if (!preview) return; setError(''); setBusy('test'); try { setTestResult(await post('/api/rules/test', { rule: preview.compiled, user_message: testUser, proposed_tool_calls: [{ name: testTool, arguments: JSON.parse(testArgs) }] })) } catch (err) { setError(friendlyError(err)) } finally { setBusy('') } }
  async function save() { if (!preview) return; setBusy('save'); try { await post('/api/rules', { compiled: preview.compiled, confirmed }); setPreview(null); setConfirmed(false); setTestResult(null); setStatus('规则已保存，默认禁用；可在右侧启用。'); setLocalRefresh(v => v + 1) } catch (err) { setError(friendlyError(err)) } finally { setBusy('') } }
  async function toggle(row: Json) { setBusy(row.id); try { await post(`/api/rules/${row.id}/${row.enabled ? 'disable' : 'enable'}`, {}); setStatus(`规则已${row.enabled ? '禁用' : '启用'}`); setLocalRefresh(v => v + 1) } finally { setBusy('') } }
  async function showHistory(row: Json) { setBusy(`history-${row.id}`); try { const value = await api<{data: Json[]}>(`/api/rules/${row.id}/versions`); setHistory({ rule: row, versions: value.data }) } finally { setBusy('') } }
  async function rollback(row: Json, version: number) { setBusy(`rollback-${version}`); try { await post(`/api/rules/${row.id}/rollback`, { version }); setStatus(`已从 v${version} 创建新的回滚版本`); setHistory(null); setLocalRefresh(v => v + 1) } catch (err) { setError((err as Error).message) } finally { setBusy('') } }
  return <div className="rules-layout"><section className="panel"><PanelTitle title="自然语言规则" subtitle="编译 → 预览 → 测试 → 保存，新规则默认禁用"/><label>规则描述<textarea value={text} onChange={event => setText(event.target.value)} rows={5}/></label><button className="primary" disabled={!!busy} onClick={compile}><SlidersHorizontal size={17}/>{busy === 'compile' ? '编译中…' : '编译预览'}</button>{error && <p className="form-error" role="alert">{error}</p>}
    {preview && <div className="preview"><div className="notice"><AlertTriangle size={18}/><span>结构化规则只包含受限字段，不执行自然语言中的代码。</span></div><dl><dt>原始规则</dt><dd>{text}</dd><dt>结构化规则</dt><dd><pre>{JSON.stringify(preview.compiled, null, 2)}</pre></dd></dl><div className="rule-test"><h3>命中测试</h3><label>用户输入<input value={testUser} onChange={event => setTestUser(event.target.value)}/></label><label>工具名称<input value={testTool} onChange={event => setTestTool(event.target.value)}/></label><label>工具参数 JSON<textarea className="mono" rows={3} value={testArgs} onChange={event => setTestArgs(event.target.value)}/></label><button className="secondary" disabled={!!busy} onClick={testPreview}><Beaker size={16}/>{busy === 'test' ? '测试中…' : '测试规则'}</button>{testResult && <p className={testResult.matched ? 'hit-result matched' : 'hit-result'} role="status">{testResult.matched ? '已命中' : '未命中'} · {testResult.stage.reason_code} · 不会执行工具</p>}</div>{preview.requires_confirmation && <label className="check"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)}/>我确认此规则会对所有命中动作直接告警</label>}<button className="primary" disabled={!!busy || (preview.requires_confirmation && !confirmed)} onClick={save}><Save size={17}/>{busy === 'save' ? '保存中…' : '保存规则'}</button></div>}
  </section><section className="panel"><PanelTitle title="已保存规则" subtitle={`${rows.length} 条，可启用、禁用或按版本回滚`}/>{status && <p className="test-result" role="status">{status}</p>}{rows.length ? <div className="rule-list">{rows.map(row => <article key={row.id}><div><b>{row.name}</b><span>{row.original_text}</span><code>{row.reason_code} · v{row.version}</code><div className="inline-actions"><button className="text-button" onClick={() => showHistory(row)} disabled={!!busy}><History size={14}/>版本</button></div></div><button className={row.enabled ? 'toggle on' : 'toggle'} role="switch" aria-label={`${row.enabled ? '禁用' : '启用'} ${row.name}`} aria-checked={row.enabled} disabled={!!busy} onClick={() => toggle(row)}><i/></button></article>)}</div> : <Empty text="暂无规则"/>}{history && <div className="history-panel"><div><b>{history.rule.name} · 版本历史</b><button className="icon-button" aria-label="关闭版本历史" onClick={() => setHistory(null)}><X size={16}/></button></div>{history.versions.map(version => <article key={version.version}><span>v{version.version} · {formatTime(version.created_at)}</span><code>{version.reason_code}</code><button className="secondary" disabled={version.version === history.rule.version || !!busy} onClick={() => rollback(history.rule, version.version)}><RotateCcw size={14}/>回滚到此版</button></article>)}</div>}</section></div>
}

function Playground() {
  const [protocol, setProtocol] = useState('openai_chat_completions')
  const [inputMode, setInputMode] = useState<'form'|'raw'>('form')
  const [pipelineStage, setPipelineStage] = useState<'full'|'rules'>('full')
  const [message, setMessage] = useState('帮我看看为什么部署失败，不要重新部署。')
  const [tool, setTool] = useState('deploy')
  const [args, setArgs] = useState('{"environment":"production","service":"payment-api"}')
  const [historicalTool, setHistoricalTool] = useState('read_logs')
  const [includeHistory, setIncludeHistory] = useState(false)
  const [raw, setRaw] = useState('{\n  "model": "playground",\n  "messages": [{"role": "user", "content": "不要重新部署"}]\n}')
  const [temporaryRule, setTemporaryRule] = useState('')
  const [result, setResult] = useState<Json | null>(null)
  const [error, setError] = useState('')
  const [running, setRunning] = useState(false)
  function formPayload(parsedArgs: Json): Json {
    if (protocol === 'anthropic_messages') return { model: 'playground', messages: [{ role: 'user', content: message }, ...(includeHistory ? [{ role: 'assistant', content: [{ type: 'tool_use', id: 'history-1', name: historicalTool, input: {} }] }] : [])] }
    if (protocol === 'openai_responses') return { model: 'playground', input: [{ type: 'message', role: 'user', content: message }, ...(includeHistory ? [{ type: 'function_call', call_id: 'history-1', name: historicalTool, arguments: '{}' }] : [])] }
    return { model: 'playground', messages: [{ role: 'user', content: message }, ...(includeHistory ? [{ role: 'assistant', tool_calls: [{ id: 'history-1', type: 'function', function: { name: historicalTool, arguments: JSON.stringify(parsedArgs) } }] }] : [])] }
  }
  async function run() { setError(''); setRunning(true); try { const parsedArgs = JSON.parse(args); const payload = inputMode === 'raw' ? JSON.parse(raw) : formPayload(parsedArgs); let compiled: Json | undefined; if (temporaryRule.trim()) compiled = (await post<Json>('/api/rules/compile', { text: temporaryRule })).compiled; setResult(await post('/api/playground/classify', { protocol, payload, proposed_tool_calls: [{ name: tool, arguments: parsedArgs }], temporary_rule: compiled, stage: pipelineStage })) } catch (err) { setError((err as Error).message) } finally { setRunning(false) } }
  return <div className="playground"><section className="panel"><PanelTitle title="构造测试" subtitle="仅分类：不会执行真实工具，也不会转发给主 Agent"/><div className="segmented"><button className={inputMode === 'form' ? 'active' : ''} onClick={() => setInputMode('form')}>表单</button><button className={inputMode === 'raw' ? 'active' : ''} onClick={() => setInputMode('raw')}>原始 JSON</button></div><label>协议<select value={protocol} onChange={event => setProtocol(event.target.value)}><option value="anthropic_messages">Anthropic Messages</option><option value="openai_chat_completions">OpenAI Chat Completions</option><option value="openai_responses">OpenAI Responses</option></select></label>{inputMode === 'form' ? <><label>用户输入<textarea rows={4} value={message} onChange={event => setMessage(event.target.value)}/></label><label className="check"><input type="checkbox" checked={includeHistory} onChange={event => setIncludeHistory(event.target.checked)}/>加入历史工具调用</label>{includeHistory && <label>历史工具名称<input value={historicalTool} onChange={event => setHistoricalTool(event.target.value)}/></label>}</> : <label>请求 JSON<textarea className="mono" rows={12} value={raw} onChange={event => setRaw(event.target.value)}/></label>}<div className="tool-box"><b>当前模型拟调用的工具</b><label>工具名称<input value={tool} onChange={event => setTool(event.target.value)}/></label><label>工具参数 JSON<textarea className="mono" rows={5} value={args} onChange={event => setArgs(event.target.value)}/></label></div><label>临时自然语言规则（可选）<textarea rows={3} placeholder="例如：生产环境部署一律告警。" value={temporaryRule} onChange={event => setTemporaryRule(event.target.value)}/></label><label>判定范围<select value={pipelineStage} onChange={event => setPipelineStage(event.target.value as 'full'|'rules')}><option value="full">完整 Rules → Fast → Deep</option><option value="rules">仅 Rules</option></select></label><button className="primary" disabled={running} onClick={run}><Beaker size={17}/>{running ? '分类中…' : '运行分类'}</button>{error && <p className="form-error" role="alert">{error}</p>}</section><section className="panel result-panel"><PanelTitle title="分类结果" subtitle={pipelineStage === 'rules' ? '仅运行本地规则阶段' : '完整 Rules → Fast → Deep 路径'}/>{result ? <><div className={result.final_decision === 'alert' ? 'decision danger' : 'decision safe'}><span>最终判定</span><b>{result.final_decision}</b><Risk level={result.risk}/></div><p className="reason-summary"><code>{result.reason_code}</code>{result.reason}</p><div className="stage-stack">{result.stages?.map((stage: Json) => <article key={stage.stage}><span>{stage.stage}</span><b>{stage.verdict}</b><code>{stage.reason_code}</code><small>{Number(stage.latency_ms || 0).toFixed(1)} ms</small></article>)}</div><details><summary>查看去思考化审查上下文</summary><pre>{JSON.stringify(result.review_transcript, null, 2)}</pre></details><details><summary>查看规范化动作 JSON</summary><pre>{JSON.stringify(result.proposed_actions, null, 2)}</pre></details><div className="notice safe-notice"><ShieldCheck size={18}/><span>本次测试未执行任何工具，也未转发给 Agent。</span></div></> : <Empty text="输入场景并运行分类"/>}</section></div>
}

function SettingsPage() {
  const { data, error } = useLoad<Json>('/api/settings')
  const [testing, setTesting] = useState('')
  const [result, setResult] = useState('')
  const [draft, setDraft] = useState<Json>({})
  const [saving, setSaving] = useState(false)
  useEffect(() => { if (data) setDraft({ fast_url: data.fast_url || '', fast_model: data.fast_model || '', deep_url: data.deep_url || '', deep_model: data.deep_model || '', fast_api_key: '', deep_api_key: '' }) }, [data])
  async function test(stage: 'fast'|'deep') { setTesting(stage); try { const value = await post<Json>(`/api/settings/test-${stage}-model`, {}); setResult(`${stage}: ${value.result.status} / ${value.result.model || '未配置模型'}`) } catch (err) { setResult(`${stage}: ${(err as Error).message}`) } finally { setTesting('') } }
  async function saveSettings() { setSaving(true); setResult(''); try { const payload = Object.fromEntries(Object.entries(draft).filter(([key, value]) => value !== '' || !key.endsWith('_api_key'))); await patch('/api/settings', payload); setDraft(current => ({ ...current, fast_api_key: '', deep_api_key: '' })); setResult('配置已应用。API Key 只保存在当前进程环境中。') } catch (err) { setResult(`保存失败：${(err as Error).message}`) } finally { setSaving(false) } }
  if (error) return <ErrorState message={error}/>
  if (!data) return <Loading/>
  return <div className="settings-grid"><section className="panel"><PanelTitle title="运行模式" subtitle="MVP 默认观察，不阻断真实工具调用"/><div className="setting-row"><div><b>Observe</b><span>记录、分类并生成告警</span></div><span className="mode-badge">当前模式</span></div><div className="setting-row disabled"><div><b>Enforce</b><span>预留的强制阻断模式</span></div><span>暂未开放</span></div></section><section className="panel model-settings"><PanelTitle title="分类模型" subtitle="Fast 无思考，Deep 有思考；密钥永不回传或落库"/>{(['fast','deep'] as const).map(stage => <fieldset key={stage}><legend>{stage === 'fast' ? 'Fast LLM' : 'Deep LLM'}</legend><label>API URL<input value={draft[`${stage}_url`] || ''} placeholder="https://provider.example/v1/chat/completions" onChange={event => setDraft({...draft, [`${stage}_url`]: event.target.value})}/></label><label>模型名称<input value={draft[`${stage}_model`] || ''} placeholder="精确模型 ID，不要带末尾引号或空格" onChange={event => setDraft({...draft, [`${stage}_model`]: event.target.value})}/></label><label>API Key<input type="password" autoComplete="new-password" value={draft[`${stage}_api_key`] || ''} placeholder={data[`${stage}_api_key_masked`] || '留空则不修改'} onChange={event => setDraft({...draft, [`${stage}_api_key`]: event.target.value})}/></label><button className="secondary" disabled={!!testing || saving} onClick={() => test(stage)}>{testing === stage ? '测试中…' : '测试连接'}</button></fieldset>)}<button className="primary" disabled={saving || !!testing} onClick={saveSettings}><Save size={16}/>{saving ? '保存中…' : '应用模型配置'}</button>{result && <p className={result.startsWith('保存失败') ? 'form-error' : 'test-result'} role="status">{result}</p>}</section><section className="panel"><PanelTitle title="数据保留" subtitle="原始请求可关闭，结构化审计数据继续保留"/><div className="setting-row"><div><b>原始请求</b><span>{data.store_raw ? '当前已保存（敏感字段脱敏）' : '当前不保存'}</span></div><CircleCheck size={20}/></div><div className="setting-row"><div><b>保留期限</b><span>{data.retention_days} 天</span></div></div></section></div>
}

function AlertTable({ rows }: { rows: Json[] }) { return <div className="table-wrap"><table><thead><tr><th>级别</th><th>原因</th><th>阶段</th><th>状态</th><th>时间</th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><Risk level={row.severity}/></td><td><b>{row.title}</b><code>{row.reason_code}</code></td><td>{row.final_stage}</td><td>{row.status}</td><td>{formatTime(row.created_at)}</td></tr>)}</tbody></table></div> }
function Metric({ label, value, detail, tone }: { label: string; value: string|number; detail: string; tone?: string }) { return <article className={`metric ${tone || ''}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></article> }
function PanelTitle({ title, subtitle }: { title: string; subtitle: string }) { return <div className="panel-title"><div><h2>{title}</h2><p>{subtitle}</p></div></div> }
function Risk({ level = 'low' }: { level?: string }) { const Icon = level === 'low' ? ShieldCheck : level === 'medium' ? CircleHelp : level === 'critical' ? ShieldAlert : AlertTriangle; return <span className={`risk ${level}`}><Icon size={13}/>{level}</span> }
function Health({ status }: { status: string }) { const good = status === 'healthy' || status === 'configured'; return <span className={good ? 'health good' : 'health unknown'}><i/>{status.replace('_', ' ')}</span> }
function Empty({ text }: { text: string }) { return <div className="empty"><ShieldCheck size={28}/><p>{text}</p></div> }
function Loading() { return <div className="loading"><RefreshCw/><span>加载中</span></div> }
function ErrorState({ message }: { message: string }) { return <div className="error-state"><AlertTriangle/><h2>无法加载数据</h2><p>{message}</p></div> }
