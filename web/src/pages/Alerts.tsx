import { useEffect, useState } from 'react'
import { Eye, EyeOff, LockKeyhole, Save } from 'lucide-react'
import type { Alert, AlertStatus } from '../types'
import { useLoad } from '../lib/hooks'
import { formatTime } from '../lib/format'
import { Empty, ErrorState, Loading, PanelTitle, Risk, StatusPill } from '../components/ui'
import { api, patch, post } from '../api'

const STATUSES: AlertStatus[] = ['open', 'acknowledged', 'false_positive', 'resolved']
const FEEDBACKS = [
  { value: 'correct', label: '判定正确' },
  { value: 'false_positive', label: '误报' },
  { value: 'unsure', label: '不确定' },
] as const

function llmSummary(alert: Alert): string {
  if (alert.llm_status === 'failed') return '分析失败，不能判断为无风险'
  if (alert.llm_status === 'pending' || alert.llm_status === 'processing') return '等待分析完成'
  if (alert.review_status === 'needs_review') return '无法判断，待复核'
  if (alert.llm_status === 'skipped') return '未执行 LLM 复核'
  if (alert.llm_status === 'not_needed') return '未触发 LLM 复核'
  return alert.llm_status === 'completed' ? 'LLM 未告警' : '暂无 LLM 分析结果'
}

export function Alerts({ refresh, onOpenTrace }: { refresh: number; onOpenTrace?: (sessionId: string | null, traceId: string) => void }) {
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [channelFilter, setChannelFilter] = useState<string>('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [localRefresh, setLocalRefresh] = useState(0)
  const [rawEvidence, setRawEvidence] = useState<unknown>(null)
  const [evidenceError, setEvidenceError] = useState('')
  const [evidenceBusy, setEvidenceBusy] = useState(false)
  const [noteDraft, setNoteDraft] = useState('')
  const [noteSaving, setNoteSaving] = useState(false)
  const [noteStatus, setNoteStatus] = useState('')

  let queryUrl = `/api/alerts?limit=200&status=${statusFilter}&alert_type=${typeFilter}&v=${refresh + localRefresh}`
  if (channelFilter === 'dual') queryUrl += '&channel_source=dual'
  else if (channelFilter === 'rule') queryUrl += '&channel_source=rule'
  else if (channelFilter === 'llm') queryUrl += '&channel_source=llm'
  else if (channelFilter === 'rule_hit') queryUrl += '&hit_source=rule_hit'
  else if (channelFilter === 'llm_hit') queryUrl += '&hit_source=llm_hit'
  else if (channelFilter === 'divergence') queryUrl += '&divergence=1'
  else if (channelFilter === 'needs_review') queryUrl += '&review_status=needs_review'
  else if (channelFilter === 'failed') queryUrl += '&review_status=failed'

  const { data, error } = useLoad<{ data: Alert[] }>(
    queryUrl,
    refresh + localRefresh + (channelFilter ? 1000 : 0)
  )
  const rows = data?.data || []
  const selected = rows.find(row => row.id === selectedId) || rows[0] || null

  useEffect(() => {
    setRawEvidence(null)
    setEvidenceError('')
    setNoteDraft(selected?.operator_note || '')
    setNoteStatus('')
  }, [selected?.id])

  if (error) return <ErrorState message={error} />
  if (!data) return <Loading />

  async function setStatus(id: string, status: string) {
    await patch(`/api/alerts/${id}`, { status })
    setLocalRefresh(value => value + 1)
  }

  async function feedback(id: string, value: string) {
    await post(`/api/alerts/${id}/feedback`, { feedback: value })
    setLocalRefresh(value => value + 1)
  }

  async function saveNote() {
    if (!selected) return
    setNoteSaving(true)
    setNoteStatus('')
    try {
      await patch(`/api/alerts/${selected.id}`, { operator_note: noteDraft })
      setNoteStatus('备注已保存')
      setLocalRefresh(value => value + 1)
    } catch (err) {
      setNoteStatus(`保存失败: ${(err as Error).message}`)
    } finally {
      setNoteSaving(false)
    }
  }

  async function revealEvidence(evidenceId: string) {
    setEvidenceBusy(true)
    setEvidenceError('')
    try {
      setRawEvidence(await api(`/api/evidence/${evidenceId}/raw?purpose=incident_review`))
    } catch (err) {
      setEvidenceError((err as Error).message)
    } finally {
      setEvidenceBusy(false)
    }
  }

  async function handleProposeSchema(finding: any) {
    const defaultName = finding.tool_name || (finding.path.includes('.tools[') ? 'SendMessage' : '')
    const toolName = window.prompt('请输入提报的受控工具名称 (例如 SendMessage / TaskUpdate):', defaultName)
    if (!toolName || !toolName.trim()) return
    try {
      await post('/api/tool-schemas', {
        tool_name: toolName.trim(),
        content_fingerprint: finding.fingerprint,
        description_snippet: finding.snippet || '',
        reason: '由安全管理员从告警提报受控工具 Schema',
      })
      window.alert(`已成功将工具 [${toolName.trim()}] 的 Schema 指纹提报为受控白名单！后续具有该指纹的请求将自动放行。`)
      setLocalRefresh(v => v + 1)
    } catch (err: any) {
      window.alert(`提报失败: ${err?.message || '未知错误'}`)
    }
  }

  const STATUS_LABELS: Record<string, string> = {
    '': '全部状态',
    open: '开放',
    acknowledged: '已确认',
    false_positive: '误报项',
    resolved: '已解决',
  }

  return (
    <div className="alerts-layout">
      <section className="panel list-panel">
        <PanelTitle
          title="告警中心"
          subtitle="双通道判定闭环：本地确定性规则依据 vs LLM 深度审查结论"
        />

        {/* 双通道及特征筛选 */}
        <div className="alert-filter-segmented" style={{ marginBottom: '8px' }}>
          <button className={channelFilter === '' ? 'active' : ''} onClick={() => setChannelFilter('')}>全部通道</button>
          <button className={channelFilter === 'rule_hit' ? 'active' : ''} onClick={() => setChannelFilter('rule_hit')}>规则命中（含双命中）</button>
          <button className={channelFilter === 'llm_hit' ? 'active' : ''} onClick={() => setChannelFilter('llm_hit')}>LLM 命中（含双命中）</button>
          <button className={channelFilter === 'dual' ? 'active' : ''} onClick={() => setChannelFilter('dual')}>⚡ 双命中 [Dual]</button>
          <button className={channelFilter === 'rule' ? 'active' : ''} onClick={() => setChannelFilter('rule')}>🛡️ 仅规则 [Rule]</button>
          <button className={channelFilter === 'llm' ? 'active' : ''} onClick={() => setChannelFilter('llm')}>🤖 仅 LLM [LLM]</button>
          <button className={channelFilter === 'divergence' ? 'active' : ''} onClick={() => setChannelFilter('divergence')}>⚠️ 结论分歧</button>
          <button className={channelFilter === 'needs_review' ? 'active' : ''} onClick={() => setChannelFilter('needs_review')}>🔍 待复核</button>
          <button className={channelFilter === 'failed' ? 'active' : ''} onClick={() => setChannelFilter('failed')}>分析失败</button>
        </div>

        {/* 告警类别筛选 */}
        <div className="alert-filter-segmented" style={{ marginBottom: '8px' }}>
          <button className={typeFilter === '' ? 'active' : ''} onClick={() => setTypeFilter('')}>全部类型</button>
          <button className={typeFilter === 'dlp' ? 'active' : ''} onClick={() => setTypeFilter('dlp')}>🛡️ 出站数据违规 (DLP)</button>
          <button className={typeFilter === 'intent_action' ? 'active' : ''} onClick={() => setTypeFilter('intent_action')}>⚡ 行为意图违规</button>
        </div>

        {/* 处置状态筛选 */}
        <div className="alert-filter-segmented">
          {STATUSES.map(status => (
            <button key={status} className={statusFilter === status ? 'active' : ''} onClick={() => setStatusFilter(status)}>
              {STATUS_LABELS[status] || status}
            </button>
          ))}
          {statusFilter !== '' && (
            <button className="text-button" onClick={() => setStatusFilter('')}>清空状态</button>
          )}
        </div>

        {rows.length ? (
          <div className="alert-list">
            {rows.map(row => {
              // 移除标题中重复的 severity 前缀
              const cleanTitle = row.title.replace(/^(HIGH|MEDIUM|LOW|CRITICAL):\s*/i, '')
              const isDlp = row.alert_type === 'dlp' || (row.data_findings && row.data_findings.length > 0)
              return (
                <button key={row.id} className={selected?.id === row.id ? 'alert-row selected' : 'alert-row'} onClick={() => setSelectedId(row.id)}>
                  <Risk level={row.severity} />
                  <div className="alert-row-body">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                      <span className={`alert-type-tag ${isDlp ? 'dlp' : 'intent'}`}>
                        {isDlp ? '🛡️ 数据出站' : '⚡ 动作意图'}
                      </span>
                      {row.channel_source === 'dual' && (
                        <span className="cat-chip" style={{ background: 'rgba(124, 58, 237, 0.2)', color: '#a78bfa', border: '1px solid #7c3aed' }}>
                          [Dual]
                        </span>
                      )}
                      {row.channel_source === 'rule' && (
                        <span className="cat-chip" style={{ background: 'rgba(37, 99, 235, 0.2)', color: '#60a5fa', border: '1px solid #2563eb' }}>
                          [Rule]
                        </span>
                      )}
                      {row.channel_source === 'llm' && (
                        <span className="cat-chip" style={{ background: 'rgba(5, 150, 105, 0.2)', color: '#34d399', border: '1px solid #059669' }}>
                          [LLM]
                        </span>
                      )}
                      {row.divergence && (
                        <span className="status-pill warn" style={{ fontSize: '10px' }}>
                          ⚠️ [结论分歧]
                        </span>
                      )}
                      {row.review_status === 'needs_review' && (
                        <span className="status-pill warn" style={{ fontSize: '10px' }}>
                          待复核
                        </span>
                      )}
                      <b title={row.title}>{cleanTitle}</b>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                      <code>{row.reason_code}</code>
                      {row.data_categories?.map(cat => (
                        <span key={cat} className="cat-chip">{cat}</span>
                      ))}
                    </div>
                    <span>{formatTime(row.created_at)}</span>
                  </div>
                  <StatusPill status={row.status} />
                </button>
              )
            })}
          </div>
        ) : <Empty text="当前筛选条件下没有告警" />}
      </section>

      {selected ? (
        <section className="panel detail-panel">
          <div className="panel-heading">
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px', flexWrap: 'wrap' }}>
                <span className={`alert-type-tag ${selected.alert_type === 'dlp' || (selected.data_findings && selected.data_findings.length > 0) ? 'dlp' : 'intent'}`}>
                  {selected.alert_type === 'dlp' || (selected.data_findings && selected.data_findings.length > 0)
                    ? '🛡️ 出站数据违规告警'
                    : selected.final_stage === 'session_risk'
                    ? '⚡ 会话用户意图风险告警'
                    : '⚡ 行为意图违规告警'}
                </span>
                {selected.channel_source === 'dual' && (
                  <span className="cat-chip" style={{ background: 'rgba(124, 58, 237, 0.2)', color: '#a78bfa', border: '1px solid #7c3aed' }}>
                    [Dual] 双命中
                  </span>
                )}
                {selected.channel_source === 'rule' && (
                  <span className="cat-chip" style={{ background: 'rgba(37, 99, 235, 0.2)', color: '#60a5fa', border: '1px solid #2563eb' }}>
                    [Rule] 仅规则
                  </span>
                )}
                {selected.channel_source === 'llm' && (
                  <span className="cat-chip" style={{ background: 'rgba(5, 150, 105, 0.2)', color: '#34d399', border: '1px solid #059669' }}>
                    [LLM] 仅 LLM
                  </span>
                )}
                {selected.divergence && (
                  <span className="status-pill warn" style={{ fontSize: '11px' }}>
                    ⚠️ [结论分歧]
                  </span>
                )}
                <p className="eyebrow" style={{ margin: 0 }}>ALERT DETAIL</p>
              </div>
              <h2>{selected.title}</h2>
              <p className="detail-subtitle">
                {selected.reason_code} · {formatTime(selected.created_at)}
                {selected.event_id && <span> · 关联事件: <code>{selected.event_id}</code></span>}
              </p>
            </div>
            <StatusPill status={selected.status} />
          </div>

          <div className="alert-detail-body">
            <div className="detail-grid">
              <div><span>综合风险级别</span><Risk level={selected.severity} /></div>
              <div><span>命中通道</span><b>{selected.channel_source ? selected.channel_source.toUpperCase() : selected.final_stage}</b></div>
              <div><span>原因说明</span><b>{selected.reason}</b></div>
              {selected.acknowledged_at && <div><span>确认时间</span><b>{formatTime(selected.acknowledged_at)}</b></div>}
              {selected.destination && <div><span>模型目标</span><b>{selected.destination.name} · <StatusPill status={selected.destination.trust || 'external'} /></b></div>}
            </div>

            {/* 双通道并列展示：规则依据及等级 vs LLM 依据及等级 */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', margin: '14px 0' }}>
              <div className="panel" style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <b>🛡️ 规则依据及原始等级</b>
                  {selected.rule_severity ? <Risk level={selected.rule_severity} /> : <span style={{ color: 'var(--muted)', fontSize: '12px' }}>未触发规则告警</span>}
                </div>
                <div style={{ fontSize: '12px', lineHeight: 1.5 }}>
                  <div>原始阶段: <code>{selected.final_stage}</code></div>
                  <div>规则原因码: <code>{selected.reason_code}</code></div>
                  {selected.data_categories && selected.data_categories.length > 0 && (
                    <div style={{ marginTop: '4px' }}>
                      敏感类别: {selected.data_categories.map(c => <span key={c} className="cat-chip" style={{ marginLeft: '4px' }}>{c}</span>)}
                    </div>
                  )}
                </div>
              </div>

              <div className="panel" style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <b>🤖 LLM 依据及等级</b>
                  {selected.llm_severity ? <Risk level={selected.llm_severity} /> : <span style={{ color: 'var(--muted)', fontSize: '12px' }}>{llmSummary(selected)}</span>}
                </div>
                <div style={{ fontSize: '12px', lineHeight: 1.5 }}>
                  <div>LLM 状态: <StatusPill status={selected.llm_status || 'unknown'} /></div>
                  <div>复核状态: <StatusPill status={selected.review_status || 'unknown'} /></div>
                  {selected.divergence && (
                    <div style={{ color: 'var(--warn)', marginTop: '4px', fontWeight: 600 }}>
                      ⚠️ 存在结论分歧（两通道判定不一致）
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* 1. 出站数据敏感发现分析（DLP 维度） */}
            {(!!selected.data_findings?.length || selected.alert_type === 'dlp') && (
              <div className="evidence" style={{ borderLeft: '3px solid var(--danger)', paddingLeft: '12px' }}>
                <b>🛡️ 出站数据违规发现 (DLP)</b>
                {selected.data_findings?.map((finding, index) => {
                  const isToolDesc = finding.path_type === 'tool_description' || Boolean(finding.path?.includes('.tools['))
                  const canPropose = isToolDesc && finding.category === 'source_code'
                  return (
                    <div key={`${finding.path || index}-${index}`} style={{ margin: '6px 0', padding: '6px 8px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', flexWrap: 'wrap' }}>
                        <span>
                          <code>{finding.category}</code> {finding.path} · {finding.detector}
                          {isToolDesc && (
                            <span style={{ marginLeft: '6px', fontSize: '11px', background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', padding: '1px 5px', borderRadius: '4px' }}>
                              工具说明 {finding.tool_name ? `(${finding.tool_name})` : ''}
                            </span>
                          )}
                          {finding.disposition === 'approved_metadata' && (
                            <span style={{ marginLeft: '6px', fontSize: '11px', background: 'rgba(34, 197, 94, 0.15)', color: '#4ade80', padding: '1px 5px', borderRadius: '4px' }}>
                              已登记受控 Schema
                            </span>
                          )}
                        </span>
                        {canPropose && (
                          <button
                            className="secondary compact"
                            style={{ fontSize: '11px', padding: '2px 8px', color: '#60a5fa', borderColor: '#3b82f6' }}
                            onClick={() => handleProposeSchema(finding)}
                          >
                            + 提报为受控 Schema
                          </button>
                        )}
                      </div>
                      {finding.snippet && <small style={{ display: 'block', color: '#f1c879', marginTop: '4px' }}>样例: {finding.snippet}</small>}
                    </div>
                  )
                })}
                {selected.evidence?.length > 0 && (
                  <div style={{ marginTop: '8px' }}>
                    <small style={{ color: 'var(--muted)' }}>脱敏证据:</small>
                    {selected.evidence.map(line => <span key={line}>{line}</span>)}
                  </div>
                )}
              </div>
            )}

            {/* 2. 行为意图与动作判定（Intent 维度） */}
            {(selected.actions?.length > 0 || selected.alert_type === 'intent_action') && (
              <div className="evidence" style={{ borderLeft: '3px solid var(--warn)', paddingLeft: '12px' }}>
                <b>⚡ {selected.final_stage === 'session_risk' ? '用户会话意图风险态势 (Session Risk)' : '模型动作与意图分析 (Intent & Actions)'}</b>
                {selected.actions?.map((action, index) => (
                  <span key={`${action.name}-${index}`}>
                    <code>{action.capability}</code> <b>{action.name}</b> {action.target && `-> ${action.target}`}
                    {action.side_effect && <span className="status-pill warn" style={{ marginLeft: '6px', fontSize: '10px' }}>副作用</span>}
                  </span>
                ))}
                {(!selected.actions?.length && selected.final_stage === 'session_risk') && (
                  <p style={{ fontSize: '12px', color: 'var(--muted)', margin: '6px 0 0', lineHeight: 1.4 }}>
                    注：本告警为后台 Observe 识别到的用户潜在高危意图态势，不证明 Agent 执行了真实的外部工具调用。
                  </p>
                )}
              </div>
            )}

            {selected.matched_rules?.length > 0 && (
              <div className="evidence">
                <b>命中规则/策略</b>
                {selected.matched_rules.map((rule, idx) => {
                  const r = rule as any
                  const label = typeof r === 'string' ? r : (r?.name || r?.id || JSON.stringify(r))
                  return <code key={`${label}-${idx}`}>{label}</code>
                })}
              </div>
            )}

            {selected.evidence_id && (
              <div className="raw-evidence-box">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <LockKeyhole size={18} />
                    <span><b>加密原文证据</b><small>仅允许本机管理 Token 解密；每次查看都会写入审计日志。</small></span>
                  </div>
                  {rawEvidence !== null && (
                    <button className="secondary compact" onClick={() => setRawEvidence(null)}>
                      <EyeOff size={14} />重新锁定 / 隐藏
                    </button>
                  )}
                </div>

                {rawEvidence === null && (
                  <button className="secondary" disabled={evidenceBusy} onClick={() => revealEvidence(selected.evidence_id!)}>
                    <Eye size={16} />{evidenceBusy ? '解密中…' : '解密查看原文'}
                  </button>
                )}
                {evidenceError && <p className="form-error" role="alert">{evidenceError}</p>}
                {rawEvidence !== null && (
                  <details open>
                    <summary>已解密证据原文</summary>
                    <pre>{JSON.stringify(rawEvidence, null, 2)}</pre>
                  </details>
                )}
              </div>
            )}

            <div className="triage">
              <b>操作员备注</b>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <input
                  aria-label="操作员备注"
                  placeholder="填写排查处置备注…"
                  value={noteDraft}
                  onChange={event => setNoteDraft(event.target.value)}
                />
                <button className="secondary compact" style={{ whiteSpace: 'nowrap' }} disabled={noteSaving || noteDraft === (selected.operator_note || '')} onClick={saveNote}>
                  <Save size={14} />{noteSaving ? '保存中' : '保存备注'}
                </button>
              </div>
              {noteStatus && <span style={{ fontSize: '11px', color: noteStatus.startsWith('保存失败') ? 'var(--danger)' : 'var(--safe)' }}>{noteStatus}</span>}
            </div>

            <div className="triage">
              <b>处置状态</b>
              <div className="triage-actions">
                {STATUSES.map(status => (
                  <button key={status} className={selected.status === status ? 'primary' : 'secondary'} disabled={selected.status === status} onClick={() => setStatus(selected.id, status)}>
                    {status}
                  </button>
                ))}
              </div>
            </div>

            <div className="triage">
              <b>人工反馈</b>
              <div className="triage-actions">
                {FEEDBACKS.map(item => (
                  <button key={item.value} className={selected.feedback === item.value ? 'primary' : 'secondary'} onClick={() => feedback(selected.id, item.value)}>
                    {selected.feedback === item.value ? `✓ ${item.label}` : item.label}
                  </button>
                ))}
              </div>
            </div>

            {onOpenTrace && (
              <button className="primary" style={{ marginTop: '8px' }} onClick={() => onOpenTrace(selected.session_record_id, selected.trace_id)}>
                在会话时间线中定位 ↗
              </button>
            )}
          </div>
        </section>
      ) : <section className="panel detail-empty"><h2>选择一条告警</h2><p>查看敏感发现、目标模型、加密原文和模型动作旁证。</p></section>}
    </div>
  )
}
