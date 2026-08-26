import { useEffect, useMemo, useState } from 'react'
import { Activity, ChevronRight, Search, SlidersHorizontal, X } from 'lucide-react'
import type { Alert, Json, Session, SessionDetail, TraceDetail } from '../types'
import { useLoad } from '../lib/hooks'
import { formatTime, sessionTitle, truncate } from '../lib/format'
import { CapabilityBadge, Empty, ErrorState, Loading, PanelTitle, Risk, StatusPill } from '../components/ui'
import { DecisionWaterfall, ReviewContext } from '../components/Waterfall'
import { patch, post } from '../api'

const PROTOCOLS = [
  { value: '', label: '全部协议' },
  { value: 'anthropic_messages', label: 'Anthropic' },
  { value: 'openai_chat_completions', label: 'OpenAI Chat' },
  { value: 'openai_responses', label: 'OpenAI Responses' },
]
const RISKS = ['low', 'medium', 'high', 'critical']
const DECISIONS = ['allow', 'alert']
const CAPABILITIES = ['read', 'write', 'execute', 'delete', 'publish', 'unknown']

export function Sessions({ refresh }: { refresh: number }) {
  const initial = useMemo(() => new URLSearchParams(window.location.search), [])
  const [filters, setFilters] = useState({
    since: initial.get('since') || '', protocol: initial.get('protocol') || '', model: initial.get('model') || '',
    risk: initial.get('risk') || '', decision: initial.get('decision') || '', capability: initial.get('capability') || '',
  })
  const [search, setSearch] = useState(initial.get('q') || '')
  const [showFilters, setShowFilters] = useState(false)
  const [selected, setSelected] = useState<string | null>(initial.get('session') || null)
  const [backfilling, setBackfilling] = useState(false)
  const [backfillResult, setBackfillResult] = useState('')
  const [localRefresh, setLocalRefresh] = useState(0)

  const query = useMemo(() => {
    const value = new URLSearchParams({ limit: '200' })
    Object.entries(filters).forEach(([key, item]) => item && value.set(key, item))
    return value.toString()
  }, [filters])

  useEffect(() => {
    const hash = window.location.hash || ''
    window.history.replaceState(null, '', `${window.location.pathname}?${query}${search ? `&q=${encodeURIComponent(search)}` : ''}${selected ? `&session=${encodeURIComponent(selected)}` : ''}${hash}`)
  }, [query, search, selected])

  const { data, error } = useLoad<{ data: Session[] }>(`/api/sessions?${query}`, refresh + localRefresh)
  const update = (key: keyof typeof filters, value: string) => setFilters(current => ({ ...current, [key]: value }))
  const rows = data?.data || []
  const visibleRows = rows.filter(row => !search.trim() || `${row.external_session_id} ${row.client_type || ''} ${(row.models || []).join(' ')}`.toLowerCase().includes(search.trim().toLowerCase()))
  const activeFilters = Object.entries(filters).filter(([, value]) => value)

  async function backfill() {
    setBackfilling(true)
    setBackfillResult('')
    try {
      const stats = await post<{ regrouped_traces: number; sessions_after: number; orphan_sessions_deleted: number; baselines_written: number }>('/api/sessions/backfill', {})
      setBackfillResult(`重建完成：${stats.regrouped_traces} 条 trace 归组，${stats.baselines_written} 个会话基线，现有 ${stats.sessions_after} 个会话，清理 ${stats.orphan_sessions_deleted} 个空会话`)
      setLocalRefresh(value => value + 1)
    } catch (err) {
      setBackfillResult(`重建失败：${(err as Error).message}`)
    } finally {
      setBackfilling(false)
    }
  }

  useEffect(() => { if (data && (!selected || !rows.some(row => row.id === selected))) setSelected(rows[0]?.id || null) }, [data, selected, rows])

  if (error) return <ErrorState message={error} />

  return (
    <div className="sessions-page">
      <section className="session-intro">
        <div><p className="eyebrow">AUDIT TIMELINE</p><h2>会话审计</h2><p>先选一个工作上下文，右侧按时间线查看每次调用、拟执行工具、判定瀑布与证据。</p></div>
        <div className="session-count">
          <strong>{visibleRows.length}</strong><span>个匹配上下文</span>
          <button className="secondary compact" disabled={backfilling} onClick={backfill}>{backfilling ? '重建中…' : '重建历史会话分组'}</button>
          {backfillResult && <span className="backfill-result">{backfillResult}</span>}
        </div>
      </section>
      <div className="master-detail">
        <section className="panel list-panel">
          <PanelTitle title="工作上下文" subtitle="按会话聚合，不按 API Key 聚合" />
          <div className="session-toolbar">
            <label className="session-search"><Search size={15} /><input aria-label="搜索上下文" placeholder="搜索 session / Agent / 模型" value={search} onChange={event => setSearch(event.target.value)} /></label>
            <button className="icon-button" aria-label="更多筛选" aria-expanded={showFilters} onClick={() => setShowFilters(value => !value)}><SlidersHorizontal size={16} /></button>
          </div>
          {activeFilters.length > 0 && (
            <div className="filter-chips">
              {activeFilters.map(([key, value]) => (
                <span className="chip" key={key}>{key}: {value}<button onClick={() => update(key as keyof typeof filters, '')} aria-label={`清除 ${key} 筛选`}><X size={12} /></button></span>
              ))}
              <button className="text-button" onClick={() => setFilters({ since: '', protocol: '', model: '', risk: '', decision: '', capability: '' })}>清空</button>
            </div>
          )}
          {showFilters && (
            <div className="filter-popover">
              <label>协议<select value={filters.protocol} onChange={event => update('protocol', event.target.value)}>{PROTOCOLS.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
              <label>风险<select value={filters.risk} onChange={event => update('risk', event.target.value)}><option value="">全部</option>{RISKS.map(value => <option key={value}>{value}</option>)}</select></label>
              <label>判定<select value={filters.decision} onChange={event => update('decision', event.target.value)}><option value="">全部</option>{DECISIONS.map(value => <option key={value}>{value}</option>)}</select></label>
              <label>能力<select value={filters.capability} onChange={event => update('capability', event.target.value)}><option value="">全部</option>{CAPABILITIES.map(value => <option key={value}>{value}</option>)}</select></label>
              <label>开始日期<input type="date" value={filters.since} onChange={event => update('since', event.target.value)} /></label>
              <label>模型<input placeholder="模型精确名称" value={filters.model} onChange={event => update('model', event.target.value)} /></label>
            </div>
          )}
          {visibleRows.length ? (
            <div className="session-list">
              {visibleRows.map(row => (
                <button key={row.id} aria-pressed={selected === row.id} className={selected === row.id ? 'session-row selected' : 'session-row'} onClick={() => setSelected(row.id)}>
                  <div className="session-primary">
                    <b>{sessionTitle(row.external_session_id)}</b>
                    <span><span className="source-badge">{row.client_type || 'unknown'}</span>{row.models?.join(', ') || '未知模型'}</span>
                    {row.authorization && (row.authorization.capabilities?.length || row.authorization.forbidden_capabilities?.length) ? (
                      <span className="session-auth-summary">
                        {row.authorization.capabilities?.length ? <span className="granted">授权{row.authorization.capabilities.map((cap: string) => <CapabilityBadge key={cap} capability={cap} />)}</span> : null}
                        {row.authorization.forbidden_capabilities?.length ? <span className="forbidden">禁止{row.authorization.forbidden_capabilities.map((cap: string) => <CapabilityBadge key={cap} capability={cap} />)}</span> : null}
                      </span>
                    ) : null}
                  </div>
                  <div className="session-stat"><Risk level={row.max_risk} /><span>{row.call_count} 次请求</span></div>
                  <span className="session-time">{formatTime(row.last_seen_at)}</span>
                  <ChevronRight size={17} />
                </button>
              ))}
            </div>
          ) : <Empty text="当前筛选条件下没有会话" />}
        </section>
        {selected ? <SessionDetail id={selected} refresh={refresh} onClose={() => setSelected(null)} /> : <section className="panel detail-empty"><Activity size={30} /><h2>选择一个会话</h2><p>查看用户输入、工具动作与三级判定瀑布。</p></section>}
      </div>
    </div>
  )
}

function SessionDetail({ id, refresh, onClose }: { id: string; refresh: number; onClose: () => void }) {
  const { data, error } = useLoad<SessionDetail>(`/api/sessions/${id}/detail`, refresh)
  const [search, setSearch] = useState('')
  const [allExpanded, setAllExpanded] = useState(false)

  if (error) return <ErrorState message={error} />
  if (!data) return <section className="panel detail-panel"><Loading /></section>

  const { session, traces } = data
  const filtered = traces.filter(trace => {
    if (!search.trim()) return true
    const haystack = `${trace.trace_id} ${trace.latest_user_text || ''} ${trace.tool_actions.map(action => `${action.tool_name} ${action.target || ''}`).join(' ')} ${trace.classification?.reason || ''}`.toLowerCase()
    return haystack.includes(search.trim().toLowerCase())
  })

  return (
    <section className="panel detail-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">WORK CONTEXT DETAIL</p>
          <h2>{sessionTitle(session.external_session_id)}</h2>
          <p className="detail-subtitle">{session.external_session_id?.startsWith('trace:') ? '未绑定 session id · 仅记录本次请求' : `${session.client_type || 'unknown'} · ${session.models?.join(', ') || '未知模型'} · ${session.call_count || 0} 次请求`}{session.conversation_fingerprint ? ` · 指纹 ${truncate(session.conversation_fingerprint, 8)}` : ''}</p>
        </div>
        <div className="panel-heading-actions">
          <button className="secondary compact" onClick={() => navigator.clipboard?.writeText(window.location.href)}>复制链接</button>
          <button className="icon-button" aria-label="关闭详情" onClick={onClose}><X /></button>
        </div>
      </div>
      {session.authorization && (session.authorization.capabilities?.length || session.authorization.forbidden_capabilities?.length || session.authorization.statements?.length) ? (
        <SessionBaseline authorization={session.authorization} />
      ) : null}
      <div className="conversation-toolbar">
        <label><span>查询会话内容</span><input aria-label="查询会话内容" placeholder="搜索消息、工具或判定原因" value={search} onChange={event => setSearch(event.target.value)} /></label>
        <div><span className="toolbar-count">{filtered.length}/{traces.length} 轮</span><button className="text-button" onClick={() => setAllExpanded(value => !value)}>{allExpanded ? '全部折叠' : '全部展开'}</button></div>
      </div>
      {filtered.length ? filtered.map((trace, index) => <TraceCard key={trace.trace_id} trace={trace} index={traces.length - index} allExpanded={allExpanded} refresh={refresh} />) : <Empty text="没有匹配的对话内容" />}
    </section>
  )
}

function SessionBaseline({ authorization }: { authorization: Json }) {
  return (
    <div className="session-baseline">
      <div className="session-baseline-head"><b>会话授权基线</b><span>累积自本会话用户输入，约束后续所有轮次的审核</span></div>
      <div className="session-baseline-body">
        {authorization.capabilities?.length ? (
          <div className="evidence"><b>已授权能力</b>{authorization.capabilities.map((cap: string) => <CapabilityBadge key={cap} capability={cap} />)}</div>
        ) : null}
        {authorization.forbidden_capabilities?.length ? (
          <div className="evidence"><b>禁止能力</b>{authorization.forbidden_capabilities.map((cap: string) => <CapabilityBadge key={cap} capability={cap} />)}</div>
        ) : null}
        {authorization.statements?.length ? (
          <div className="evidence statements"><b>授权依据</b>{authorization.statements.map((item: Json) => <span key={item.text}>{item.text}</span>)}</div>
        ) : null}
      </div>
    </div>
  )
}

function TraceCard({ trace, index, allExpanded, refresh }: { trace: TraceDetail; index: number; allExpanded: boolean; refresh: number }) {
  const [open, setOpen] = useState<'waterfall' | 'context' | 'raw' | null>(allExpanded ? 'waterfall' : null)
  useEffect(() => setOpen(allExpanded ? 'waterfall' : null), [allExpanded])
  const classification = trace.classification
  const decision = classification?.final_decision || (trace.tool_actions.length ? '分类中' : '无需分类')
  const risk = classification?.risk || 'low'
  return (
    <article className="trace-card">
      <div className="turn-summary">
        <div><span className="turn-label">#{index} · REQUEST {truncate(trace.trace_id, 8)}</span><strong className={`decision-badge ${decision === 'allow' ? 'allow' : decision === 'alert' ? 'alert' : 'pending'}`}>{decision}</strong><span>{formatTime(trace.created_at)}</span></div>
        <Risk level={risk} />
      </div>
      {trace.session_evidence && (
        <div className="session-evidence"><span>Session</span><b>{trace.session_evidence.status === 'provided' ? '客户端提供' : '未提供'}</b><code>{trace.session_evidence.selected ? `${trace.session_evidence.selected.field}: ${trace.session_evidence.selected.value}` : '无 session_id · 请求级记录'}</code>{trace.session_evidence.fingerprint ? <code className="fingerprint">指纹 {truncate(String(trace.session_evidence.fingerprint), 10)}</code> : null}</div>
      )}
      <div className="trace-section">
        <div className="trace-section-head"><b>用户输入</b><span>{trace.latest_user_text ? '最新消息' : '无可解析输入'}</span></div>
        <div className="user-bubble">{trace.latest_user_text || JSON.stringify(trace.request_body || {})}</div>
      </div>
      {trace.tool_actions.length > 0 && (
        <div className="trace-section">
          <div className="trace-section-head"><b>拟调用工具</b><span>{trace.tool_actions.length} 个动作</span></div>
          {trace.tool_actions.map((action, index) => (
            <div className="tool-action" key={index}>
              <div className="tool-action-head"><b>{action.tool_name}</b><CapabilityBadge capability={action.capability} />{action.target && <span className="tool-target">{action.target}</span>}</div>
              {action.arguments != null && <pre className="args">{JSON.stringify(action.arguments, null, 2)}</pre>}
            </div>
          ))}
        </div>
      )}
      {classification && (
        <>
          <div className="trace-section">
            <div className="trace-section-head">
              <b>判定瀑布</b>
              <button className="text-button" onClick={() => setOpen(open === 'waterfall' ? null : 'waterfall')}>{open === 'waterfall' ? '收起' : '展开'}</button>
            </div>
            {open === 'waterfall' && <DecisionWaterfall classification={classification} />}
          </div>
          <div className="trace-section">
            <div className="trace-section-head">
              <b>审查上下文（分类器实际看到的内容）</b>
              <button className="text-button" onClick={() => setOpen(open === 'context' ? null : 'context')}>{open === 'context' ? '收起' : '展开'}</button>
            </div>
            {open === 'context' && <ReviewContext transcript={classification.review_transcript} />}
          </div>
        </>
      )}
      {trace.alerts.length > 0 && (
        <div className="trace-section">
          <div className="trace-section-head"><b>关联告警</b><span>{trace.alerts.length} 条</span></div>
          {trace.alerts.map(alert => <InlineAlert key={alert.id} alert={alert} refresh={refresh} />)}
        </div>
      )}
      <details className="raw-payload"><summary>查看原始 Input / Output JSON</summary><div className="raw-grid"><pre>{JSON.stringify(trace.request_body, null, 2)}</pre><pre>{JSON.stringify(trace.response_body, null, 2)}</pre></div></details>
    </article>
  )
}

function InlineAlert({ alert, refresh }: { alert: Alert; refresh: number }) {
  const [local, setLocal] = useState(alert)
  async function setStatus(status: string) {
    const updated = await patch<Alert>(`/api/alerts/${alert.id}`, { status })
    setLocal(updated)
  }
  return (
    <div className="inline-alert">
      <div className="inline-alert-head"><Risk level={local.severity} /><b>{local.title}</b><code>{local.reason_code}</code><StatusPill status={local.status} /></div>
      <p>{local.reason}</p>
      {local.evidence?.length > 0 && <div className="evidence"><b>证据</b>{local.evidence.map(line => <span key={line}>{line}</span>)}</div>}
      {local.matched_rules?.length > 0 && <div className="evidence"><b>命中规则</b>{local.matched_rules.map(line => <code key={line}>{line}</code>)}</div>}
      <div className="inline-alert-actions">
        {(['acknowledged', 'false_positive', 'resolved', 'open'] as const).filter(status => status !== local.status).map(status => <button key={status} className="secondary compact" onClick={() => setStatus(status)}>{status}</button>)}
      </div>
    </div>
  )
}
