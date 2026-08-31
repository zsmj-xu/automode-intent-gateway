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

export function Alerts({ refresh, onOpenTrace }: { refresh: number; onOpenTrace?: (sessionId: string | null, traceId: string) => void }) {
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [localRefresh, setLocalRefresh] = useState(0)
  const [rawEvidence, setRawEvidence] = useState<unknown>(null)
  const [evidenceError, setEvidenceError] = useState('')
  const [evidenceBusy, setEvidenceBusy] = useState(false)
  const [noteDraft, setNoteDraft] = useState('')
  const [noteSaving, setNoteSaving] = useState(false)
  const [noteStatus, setNoteStatus] = useState('')

  const { data, error } = useLoad<{ data: Alert[] }>(
    `/api/alerts?limit=200&status=${statusFilter}&alert_type=${typeFilter}&v=${refresh + localRefresh}`,
    refresh + localRefresh
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
          subtitle="双维度审计：数据出站违规 vs 动作意图违规；Observe 模式不阻断 Agent"
        />

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
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span className={`alert-type-tag ${selected.alert_type === 'dlp' || (selected.data_findings && selected.data_findings.length > 0) ? 'dlp' : 'intent'}`}>
                  {selected.alert_type === 'dlp' || (selected.data_findings && selected.data_findings.length > 0) ? '🛡️ 出站数据违规告警' : '⚡ 行为意图违规告警'}
                </span>
                <p className="eyebrow" style={{ margin: 0 }}>ALERT DETAIL</p>
              </div>
              <h2>{selected.title}</h2>
              <p className="detail-subtitle">{selected.reason_code} · {formatTime(selected.created_at)}</p>
            </div>
            <StatusPill status={selected.status} />
          </div>

          <div className="alert-detail-body">
            <div className="detail-grid">
              <div><span>风险级别</span><Risk level={selected.severity} /></div>
              <div><span>判定阶段</span><b>{selected.final_stage}</b></div>
              <div><span>原因说明</span><b>{selected.reason}</b></div>
              {selected.acknowledged_at && <div><span>确认时间</span><b>{formatTime(selected.acknowledged_at)}</b></div>}
              {selected.destination && <div><span>模型目标</span><b>{selected.destination.name} · <StatusPill status={selected.destination.trust || 'external'} /></b></div>}
            </div>

            {/* 1. 出站数据敏感发现分析（DLP 维度） */}
            {(!!selected.data_findings?.length || selected.alert_type === 'dlp') && (
              <div className="evidence" style={{ borderLeft: '3px solid var(--danger)', paddingLeft: '12px' }}>
                <b>🛡️ 出站数据违规发现 (DLP)</b>
                {selected.data_findings?.map((finding, index) => (
                  <span key={`${finding.path}-${index}`}>
                    <code>{finding.category}</code> {finding.path} · {finding.detector}
                    {finding.snippet && <small style={{ display: 'block', color: '#f1c879', marginTop: '2px' }}>样例: {finding.snippet}</small>}
                  </span>
                ))}
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
                <b>⚡ 行为意图与动作旁证 (Intent)</b>
                {selected.actions?.map((action, index) => (
                  <span key={index}>
                    <code>{action.name}</code> {action.target ? ` · 目标: ${action.target}` : ''}
                    {action.capability && ` [${action.capability}]`}
                  </span>
                ))}
              </div>
            )}

            {selected.matched_rules?.length > 0 && (
              <div className="evidence">
                <b>命中规则/策略</b>
                {selected.matched_rules.map(line => <code key={line}>{line}</code>)}
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
