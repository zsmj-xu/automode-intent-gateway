import { useEffect, useMemo, useState } from 'react'
import { Activity, AlertTriangle, ChevronRight, RefreshCw, Search, ShieldAlert, ShieldCheck, SlidersHorizontal, User, X } from 'lucide-react'
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

export const PURPOSE_RISK_LABELS: Record<string, { label: string; warn: boolean }> = {
  benign: { label: '正常业务', warn: false },
  dual_use: { label: '双重用途', warn: true },
  credential_exfiltration: { label: '凭据窃取', warn: true },
  unauthorized_access: { label: '未授权入侵', warn: true },
  safety_evasion: { label: '策略规避', warn: true },
  destructive_harm: { label: '破坏清库', warn: true },
  fraud: { label: '钓鱼诈骗', warn: true },
  privacy_invasion: { label: '侵犯隐私', warn: true },
  physical_harm: { label: '人身威胁', warn: true },
  malware: { label: '恶意代码', warn: true },
  unknown: { label: '未知目的', warn: false },
}

export const TRANSFER_INTENT_LABELS: Record<string, { label: string; tagClass: string }> = {
  none: { label: '无外发意图', tagClass: 'intent-muted' },
  prepare: { label: '筹备外发', tagClass: 'intent-warn' },
  external_transfer: { label: '外部推送', tagClass: 'intent-danger' },
}

export function Sessions({ refresh }: { refresh: number }) {
  const initial = useMemo(() => new URLSearchParams(window.location.search), [])
  const [filters, setFilters] = useState({
    since: initial.get('since') || '', protocol: initial.get('protocol') || '', model: initial.get('model') || '',
    risk: initial.get('risk') || '', decision: initial.get('decision') || '', capability: initial.get('capability') || '',
    category: initial.get('category') || '',
  })
  const [search, setSearch] = useState(initial.get('q') || '')
  const [showFilters, setShowFilters] = useState(false)
  const [selected, setSelected] = useState<string | null>(initial.get('session') || null)
  const [backfilling, setBackfilling] = useState(false)
  const [showBackfillConfirm, setShowBackfillConfirm] = useState(false)
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
    setShowBackfillConfirm(false)
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
        <div><p className="eyebrow">SHADOW DLP & INTENT TIMELINE</p><h2>出站请求审计</h2><p>双维度监控：① 出站数据合规 (DLP)；② 行为意图安全 (Intent)；Observe 模式旁路记录与告警。</p></div>
        <div className="session-count">
          <strong>{visibleRows.length}</strong><span>个匹配上下文</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {!showBackfillConfirm ? (
              <button className="secondary compact" disabled={backfilling} onClick={() => setShowBackfillConfirm(true)}>
                {backfilling ? '重建中…' : '重建历史会话分组'}
              </button>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: '#1c1512', border: '1px solid #7b5c2e', padding: '3px 8px', borderRadius: '6px' }}>
                <span style={{ fontSize: '11px', color: '#f1c879' }}>确认重新计算全部历史分组？</span>
                <button className="primary compact" onClick={backfill}>确认</button>
                <button className="secondary compact" onClick={() => setShowBackfillConfirm(false)}>取消</button>
              </div>
            )}
          </div>
          {backfillResult && <span className="backfill-result">{backfillResult}</span>}
        </div>
      </section>
      <div className="master-detail">
        <section className="panel list-panel">
          <PanelTitle title="工作上下文" subtitle="按会话聚合，双维度展示数据合规与意图安全" />

          {/* 快速分类过滤器 */}
          <div className="alert-filter-segmented" style={{ marginBottom: '10px' }}>
            <button className={filters.category === '' ? 'active' : ''} onClick={() => update('category', '')}>全部上下文</button>
            <button className={filters.category === 'dlp' ? 'active' : ''} onClick={() => update('category', 'dlp')}>🛡️ 敏感数据出站</button>
            <button className={filters.category === 'intent' ? 'active' : ''} onClick={() => update('category', 'intent')}>⚡ 意图行为风险</button>
          </div>

          <div className="session-toolbar">
            <label className="session-search"><Search size={15} /><input aria-label="搜索上下文" placeholder="搜索 session / Agent / 模型" value={search} onChange={event => setSearch(event.target.value)} /></label>
            <button className="icon-button" aria-label="更多筛选" aria-expanded={showFilters} onClick={() => setShowFilters(value => !value)}><SlidersHorizontal size={16} /></button>
          </div>
          {activeFilters.length > 0 && (
            <div className="filter-chips">
              {activeFilters.map(([key, value]) => (
                <span className="chip" key={key}>{key}: {value}<button onClick={() => update(key as keyof typeof filters, '')} aria-label={`清除 ${key} 筛选`}><X size={12} /></button></span>
              ))}
              <button className="text-button" onClick={() => setFilters({ since: '', protocol: '', model: '', risk: '', decision: '', capability: '', category: '' })}>清空</button>
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
              {visibleRows.map(row => {
                const hasAlert = row.alert_count > 0
                const hasDlpRisk = Boolean((row.dlp_findings_count && row.dlp_findings_count > 0) || row.has_dlp_alert)
                const hasIntentRisk = Boolean(row.has_intent_alert || (row.intent_risk && row.intent_risk !== 'low'))

                return (
                  <button
                    key={row.id}
                    aria-pressed={selected === row.id}
                    className={selected === row.id ? 'session-row selected' : 'session-row'}
                    onClick={() => setSelected(row.id)}
                  >
                    <div className="session-row-head">
                      <div className="session-title-wrap">
                        <b className="session-title" title={sessionTitle(row.external_session_id)}>
                          {sessionTitle(row.external_session_id)}
                        </b>
                        {hasAlert && <span className="session-alert-tag">告警</span>}
                      </div>
                      <Risk level={row.max_risk} />
                    </div>

                    {/* 多维度核心指标标签 */}
                    <div className="session-dual-tags">
                      {hasDlpRisk ? (
                        <span className="dual-tag dlp-warn" title={`敏感数据出站: ${row.dlp_categories?.join(', ') || '已告警'}`}>
                          <ShieldAlert size={12} />
                          <span>DLP: {row.dlp_categories?.length ? row.dlp_categories.join('/') : `${row.dlp_findings_count || 1}项敏感`}</span>
                        </span>
                      ) : (
                        <span className="dual-tag dlp-safe">
                          <ShieldCheck size={12} />
                          <span>DLP: 无敏感外发</span>
                        </span>
                      )}

                      {hasIntentRisk ? (
                        <span className="dual-tag intent-warn" title="存在高危或越权行为意图">
                          <AlertTriangle size={12} />
                          <span>动作意图: {row.intent_risk ? `${row.intent_risk.toUpperCase()}风险` : '存疑'}</span>
                        </span>
                      ) : (
                        <span className="dual-tag intent-safe">
                          <Activity size={12} />
                          <span>动作意图: 正常</span>
                        </span>
                      )}

                      {row.risk_intent_summary && (
                        <>
                          <span
                            className={`dual-tag ${
                              row.risk_intent_summary.severity === 'critical'
                                ? 'intent-danger'
                                : row.risk_intent_summary.severity === 'high'
                                ? 'intent-warn'
                                : 'intent-safe'
                            }`}
                            title={`用户目的风险: ${row.risk_intent_summary.purpose_risk}`}
                          >
                            <ShieldAlert size={12} />
                            <span>目的: {PURPOSE_RISK_LABELS[row.risk_intent_summary.purpose_risk]?.label || row.risk_intent_summary.purpose_risk}</span>
                          </span>
                          <span
                            className={`dual-tag ${
                              TRANSFER_INTENT_LABELS[row.risk_intent_summary.transfer_intent]?.tagClass || 'intent-muted'
                            }`}
                            title={`外发动作意图: ${row.risk_intent_summary.transfer_intent}`}
                          >
                            <span>外发: {TRANSFER_INTENT_LABELS[row.risk_intent_summary.transfer_intent]?.label || row.risk_intent_summary.transfer_intent}</span>
                          </span>
                        </>
                      )}
                    </div>

                    <div className="session-row-meta">
                      <span className="source-badge">{row.client_type || 'unknown'}</span>
                      <span className="session-model" title={row.models?.join(', ') || '未知模型'}>
                        {row.models?.join(', ') || '未知模型'}
                      </span>
                      <span className="session-count-tag">{row.call_count} 次请求</span>
                    </div>

                    {row.authorization && (row.authorization.capabilities?.length || row.authorization.forbidden_capabilities?.length) ? (
                      <div className="session-auth-summary">
                        {row.authorization.capabilities?.length ? (
                          <span className="granted">
                            <small>能力</small>
                            {row.authorization.capabilities.map((cap: string) => (
                              <CapabilityBadge key={cap} capability={cap} />
                            ))}
                          </span>
                        ) : null}
                        {row.authorization.forbidden_capabilities?.length ? (
                          <span className="forbidden">
                            <small>禁止</small>
                            {row.authorization.forbidden_capabilities.map((cap: string) => (
                              <CapabilityBadge key={cap} capability={cap} />
                            ))}
                          </span>
                        ) : null}
                      </div>
                    ) : null}

                    <div className="session-row-foot">
                      <span className="session-time">{formatTime(row.last_seen_at)}</span>
                      <ChevronRight size={14} className="session-chevron" />
                    </div>
                  </button>
                )
              })}
            </div>
          ) : <Empty text="当前筛选条件下没有会话" />}
        </section>
        {selected ? <SessionDetail id={selected} refresh={refresh} onClose={() => setSelected(null)} /> : <section className="panel detail-empty"><Activity size={30} /><h2>选择一个会话</h2><p>查看出站数据合规判定与模型动作旁证。</p></section>}
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

  const { session, traces, risk_intent_segments } = data
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

      {/* 双维度总体态势总结卡片 */}
      <div className="session-dual-summary-grid">
        <div className={`summary-box dlp ${session.dlp_findings_count ? 'warn' : 'safe'}`}>
          <div className="summary-box-head">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldAlert size={16} />
              <b>出站数据合规 (DLP)</b>
            </div>
            <span className={`summary-status-pill ${session.dlp_findings_count ? 'alert' : 'safe'}`}>
              {session.dlp_findings_count ? `${session.dlp_findings_count} 项敏感发现` : '未发现敏感数据'}
            </span>
          </div>
          <div className="summary-box-body">
            <span>敏感数据类型: <b>{session.dlp_categories?.length ? session.dlp_categories.join(', ') : '无'}</b></span>
            <span>外发合规判定: <b>{session.has_dlp_alert ? '命中外发策略告警 ⚠️' : '合规放行'}</b></span>
          </div>
        </div>

        <div className={`summary-box intent ${session.has_intent_alert || (session.intent_risk && session.intent_risk !== 'low') ? 'warn' : 'safe'}`}>
          <div className="summary-box-head">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Activity size={16} />
              <b>行为意图安全 (Intent)</b>
            </div>
            <Risk level={session.intent_risk || 'low'} />
          </div>
          <div className="summary-box-body">
            <span>模型动作/工具调用: <b>{session.tool_call_count || 0} 次</b></span>
            <span>意图风险状态: <b>{session.has_intent_alert ? '存在越权或高危动作告警 ⚠️' : '意图正常对齐'}</b></span>
          </div>
        </div>
      </div>

      {risk_intent_segments?.length ? (
        <div className={`session-risk-intent-card ${risk_intent_segments.some(s => s.severity === 'critical') ? 'critical' : ''}`}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px', flexWrap: 'wrap', gap: '6px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldAlert size={15} color="var(--warn)" />
              <b style={{ fontSize: '13px', color: '#f8fafc' }}>用户会话意图风险态势 (Session Risk)</b>
            </div>
            <span style={{ fontSize: '11px', color: 'var(--muted)' }}>
              Observe 模式后台审计 · 非真实外部动作证明
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {risk_intent_segments.map(segment => {
              const purposeInfo = PURPOSE_RISK_LABELS[segment.purpose_risk] || { label: segment.purpose_risk, warn: false }
              const transferInfo = TRANSFER_INTENT_LABELS[segment.transfer_intent] || { label: segment.transfer_intent, tagClass: 'intent-muted' }
              const isHighOrCrit = segment.severity === 'high' || segment.severity === 'critical'

              return (
                <div key={segment.id} className="risk-segment-item">
                  <div className="risk-segment-header">
                    <Risk level={segment.severity} />
                    <span className={`dual-tag ${isHighOrCrit ? 'intent-danger' : 'intent-safe'}`}>
                      目的: {purposeInfo.label}
                    </span>
                    <span className={`dual-tag ${transferInfo.tagClass}`}>
                      外发: {transferInfo.label}
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--muted)', marginLeft: 'auto' }}>
                      {formatTime(segment.started_at)}
                    </span>
                    {segment.state === 'needs_review' ? (
                      <span className="status-pill warn" style={{ fontSize: '10px' }}>待复核</span>
                    ) : (
                      <span className="status-pill safe" style={{ fontSize: '10px' }}>已收敛</span>
                    )}
                  </div>
                  {segment.summary && (
                    <p className="risk-segment-summary">
                      <b>判定说明：</b>{segment.summary}
                      {segment.reason_code && <code> ({segment.reason_code})</code>}
                    </p>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      ) : null}

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
      <div className="session-baseline-head"><b>历史用途摘要（旁证）</b><span>从脱敏用户输入累计，不替代本轮出站数据策略结论</span></div>
      <div className="session-baseline-body">
        {authorization.capabilities?.length ? (
          <div className="evidence"><b>请求过的能力</b>{authorization.capabilities.map((cap: string) => <CapabilityBadge key={cap} capability={cap} />)}</div>
        ) : null}
        {authorization.forbidden_capabilities?.length ? (
          <div className="evidence"><b>禁止能力</b>{authorization.forbidden_capabilities.map((cap: string) => <CapabilityBadge key={cap} capability={cap} />)}</div>
        ) : null}
        {authorization.statements?.length ? (
          <div className="evidence statements"><b>历史原文</b>{authorization.statements.map((item: Json) => <span key={item.text}>{item.text}</span>)}</div>
        ) : null}
      </div>
    </div>
  )
}

function TraceCard({ trace, index, allExpanded, refresh }: { trace: TraceDetail; index: number; allExpanded: boolean; refresh: number }) {
  const [open, setOpen] = useState<'waterfall' | 'context' | 'raw' | null>(allExpanded ? 'waterfall' : null)
  useEffect(() => setOpen(allExpanded ? 'waterfall' : null), [allExpanded])
  const classification = trace.classification
  const decision = classification?.final_decision || '分类中'
  const risk = classification?.risk || 'low'

  const stages = classification?.stages || []
  const rulesStage = stages.find(s => s.stage === 'rules')
  const deepStage = stages.find(s => s.stage === 'deep_llm')

  // 收集所有匹配到的规则/策略名称（去重）
  const matchedRules = Array.from(new Set([
    ...(trace.alerts.flatMap(a => a.matched_rules || [])),
    ...(classification?.matched_rules || []),
    ...(classification?.matched_policies || []),
    ...(rulesStage?.matched_rule_versions || []),
  ])).filter(Boolean)

  const hasAlert = trace.alerts.length > 0 || decision === 'alert'

  return (
    <article className="trace-card">
      <div className="turn-summary">
        <div>
          <span className="turn-label">#{index} · REQUEST {truncate(trace.trace_id, 8)}</span>
          <strong className={`decision-badge ${decision === 'allow' ? 'allow' : decision === 'alert' ? 'alert' : 'pending'}`}>{decision}</strong>
          <span>{formatTime(trace.created_at)}</span>
        </div>
        <Risk level={risk} />
      </div>

      {trace.session_evidence && (
        <div className="session-evidence">
          <span>Session</span>
          <b>{trace.session_evidence.status === 'provided' ? '客户端提供' : '未提供'}</b>
          <code>{trace.session_evidence.selected ? `${trace.session_evidence.selected.field}: ${trace.session_evidence.selected.value}` : '无 session_id · 请求级记录'}</code>
          {trace.session_evidence.fingerprint ? <code className="fingerprint">指纹 {truncate(String(trace.session_evidence.fingerprint), 10)}</code> : null}
        </div>
      )}

      {/* 【置顶重点】1. 告警详情与规则判定置顶卡片 */}
      {hasAlert && (
        <div className="trace-alert-card">
          <div className="trace-alert-card-head">
            <div className="trace-alert-card-title">
              <ShieldAlert size={18} className="alert-icon" />
              <b>告警与合规判定详情</b>
              <span className={`risk-tag-high ${risk}`}>{risk.toUpperCase()} RISK</span>
            </div>
            {trace.alerts.length > 0 && <span className="alert-count-pill">{trace.alerts.length} 条关联告警</span>}
          </div>

          <div className="trace-risk-reasons">
            {/* 确定性规则判定为什么认为有风险 */}
            <div className="risk-reason-item">
              <span className="reason-label">确定性规则判定</span>
              <div className="reason-content">
                <b>{rulesStage ? `${rulesStage.verdict} · ${rulesStage.reason_code}` : (classification?.reason_code || 'RISKY')}</b>
                <p>
                  {rulesStage?.reason || classification?.reason || (
                    rulesStage?.reason_code === 'ACTION_OUTSIDE_EXPLICIT_SCOPE'
                      ? '拟调用的工具动作超出会话已授权的显式范围'
                      : rulesStage?.reason_code === 'USER_CONSTRAINT'
                      ? '拟调用的工具动作违反了用户在上下文中明确声明的禁止约束'
                      : '检测到动作风险或敏感数据出站'
                  )}
                </p>
              </div>
            </div>

            {/* 审查模型介入/异常原因（如有） */}
            {deepStage && (deepStage.status === 'error' || deepStage.verdict === 'reject') && (
              <div className="risk-reason-item warning">
                <span className="reason-label">后置审查模型</span>
                <div className="reason-content">
                  <b>{deepStage.stage}: {deepStage.reason_code} ({deepStage.status})</b>
                  <p>
                    {deepStage.status === 'error'
                      ? '审查模型不可用或响应超时；系统基于安全保守原则（Fail-Closed）禁止未知放行，直接判定为高风险告警。'
                      : deepStage.reason || '审查模型判定该行为存在违规风险。'}
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* 匹配到的告警规则/策略 */}
          {matchedRules.length > 0 && (
            <div className="trace-matched-rules">
              <span className="rules-label">🎯 匹配到的告警规则/策略：</span>
              <div className="rules-list">
                {matchedRules.map((ruleName, idx) => (
                  <span key={idx} className="rule-badge">{ruleName}</span>
                ))}
              </div>
            </div>
          )}

          {/* 关联告警处置项 */}
          {trace.alerts.length > 0 && (
            <div className="trace-alert-instances">
              {trace.alerts.map(alert => <InlineAlert key={alert.id} alert={alert} refresh={refresh} />)}
            </div>
          )}
        </div>
      )}

      {/* 出站数据合规汇总（若是 outbound_request） */}
      {classification?.review_object === 'outbound_request' && (
        <div className="dlp-decision-card" aria-label="出站数据合规结论">
          <div><span>人的用途</span><b>{classification.request_purpose || 'unknown'}</b></div>
          <div><span>敏感发现</span><b>{classification.data_findings?.length || 0}</b></div>
          <div><span>模型目标</span><b>{classification.destination?.name || trace.model || '未注册'}</b><StatusPill status={classification.destination?.trust || 'external'} /></div>
          <div><span>策略结论</span><strong className={`decision-badge ${classification.policy_decision}`}>{classification.policy_decision}</strong></div>
          {!!classification.data_findings?.length && (
            <div className="dlp-findings">
              {classification.data_findings.map((finding, index) => <span key={`${finding.path}-${index}`}><code>{finding.category}</code>{finding.path} · {finding.detector}</span>)}
            </div>
          )}
        </div>
      )}

      {/* 判定瀑布流水线 */}
      {classification && (
        <div className="trace-section">
          <div className="trace-section-head">
            <b>出站数据合规判定 (RULES → FAST → DEEP)</b>
            <button className="text-button" onClick={() => setOpen(open === 'waterfall' ? null : 'waterfall')}>{open === 'waterfall' ? '收起' : '展开'}</button>
          </div>
          {open === 'waterfall' && <DecisionWaterfall classification={classification} />}
        </div>
      )}

      {/* 【下层细节】用户输入 */}
      <div className="trace-section">
        <div className="trace-section-head"><b>用户输入</b><span>{trace.latest_user_text ? '最新消息' : '无可解析输入'}</span></div>
        <div className="user-bubble">{trace.latest_user_text || JSON.stringify(trace.request_body || {})}</div>
      </div>

      {/* 【下层细节】模型动作旁证 */}
      {trace.tool_actions.length > 0 && (
        <div className="trace-section">
          <div className="trace-section-head"><b>模型动作旁证</b><span>{trace.tool_actions.length} 个动作</span></div>
          {trace.tool_actions.map((action, index) => (
            <div className="tool-action" key={index}>
              <div className="tool-action-head"><b>{action.tool_name}</b><CapabilityBadge capability={action.capability} />{action.target && <span className="tool-target">{action.target}</span>}</div>
              {action.arguments != null && <pre className="args">{JSON.stringify(action.arguments, null, 2)}</pre>}
            </div>
          ))}
        </div>
      )}

      {/* 【下层细节】审查上下文 */}
      {classification && (
        <div className="trace-section">
          <div className="trace-section-head">
            <b>审查上下文（分类器实际看到的内容）</b>
            <button className="text-button" onClick={() => setOpen(open === 'context' ? null : 'context')}>{open === 'context' ? '收起' : '展开'}</button>
          </div>
          {open === 'context' && <ReviewContext transcript={classification.review_transcript} />}
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
  const cleanTitle = local.title.replace(/^(HIGH|MEDIUM|LOW|CRITICAL):\s*/i, '')
  return (
    <div className="inline-alert">
      <div className="inline-alert-head">
        <Risk level={local.severity} />
        <b>{cleanTitle}</b>
        <code>{local.reason_code}</code>
        <StatusPill status={local.status} />
      </div>
      <p>{local.reason}</p>
      {local.evidence?.length > 0 && <div className="evidence"><b>证据</b>{local.evidence.map(line => <span key={line}>{line}</span>)}</div>}
      {local.matched_rules?.length > 0 && <div className="evidence"><b>命中规则</b>{local.matched_rules.map(line => <code key={line}>{line}</code>)}</div>}
      <div className="inline-alert-actions">
        {(['acknowledged', 'false_positive', 'resolved', 'open'] as const).filter(status => status !== local.status).map(status => (
          <button key={status} className="secondary compact" onClick={() => setStatus(status)}>
            {status === 'open' ? '重新开放' : status === 'acknowledged' ? '确认' : status === 'false_positive' ? '标记误报' : '解决'}
          </button>
        ))}
      </div>
    </div>
  )
}
