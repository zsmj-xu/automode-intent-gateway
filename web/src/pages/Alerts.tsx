import { useState } from 'react'
import type { Alert, AlertStatus } from '../types'
import { useLoad } from '../lib/hooks'
import { formatTime } from '../lib/format'
import { Empty, ErrorState, Loading, PanelTitle, Risk, StatusPill } from '../components/ui'
import { patch, post } from '../api'

const STATUSES: AlertStatus[] = ['open', 'acknowledged', 'false_positive', 'resolved']
const FEEDBACKS = [
  { value: 'correct', label: '判定正确' },
  { value: 'false_positive', label: '误报' },
  { value: 'unsure', label: '不确定' },
] as const

export function Alerts({ refresh, onOpenTrace }: { refresh: number; onOpenTrace?: (sessionId: string | null, traceId: string) => void }) {
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [localRefresh, setLocalRefresh] = useState(0)
  const { data, error } = useLoad<{ data: Alert[] }>(`/api/alerts?limit=200&status=${statusFilter}&v=${refresh + localRefresh}`, refresh + localRefresh)
  const rows = data?.data || []

  if (error) return <ErrorState message={error} />
  if (!data) return <Loading />

  const selected = rows.find(row => row.id === selectedId) || rows[0] || null

  async function setStatus(id: string, status: string) {
    await patch(`/api/alerts/${id}`, { status })
    setLocalRefresh(value => value + 1)
  }
  async function feedback(id: string, value: string) {
    await post(`/api/alerts/${id}/feedback`, { feedback: value })
    setLocalRefresh(value => value + 1)
  }

  return (
    <div className="alerts-layout">
      <section className="panel list-panel">
        <PanelTitle
          title="告警中心"
          subtitle="观察模式只记录和告警，不阻断 Agent"
          actions={
            <div className="segmented">
              <button className={statusFilter === '' ? 'active' : ''} onClick={() => setStatusFilter('')}>全部</button>
              {STATUSES.map(status => <button key={status} className={statusFilter === status ? 'active' : ''} onClick={() => setStatusFilter(status)}>{status}</button>)}
            </div>
          }
        />
        {rows.length ? (
          <div className="alert-list">
            {rows.map(row => (
              <button key={row.id} className={selected?.id === row.id ? 'alert-row selected' : 'alert-row'} onClick={() => setSelectedId(row.id)}>
                <Risk level={row.severity} />
                <div className="alert-row-body">
                  <b>{row.title}</b>
                  <code>{row.reason_code}</code>
                  <span>{formatTime(row.created_at)}</span>
                </div>
                <StatusPill status={row.status} />
              </button>
            ))}
          </div>
        ) : <Empty text="当前没有告警" />}
      </section>
      {selected ? (
        <section className="panel detail-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">ALERT DETAIL</p><h2>{selected.title}</h2><p className="detail-subtitle">{selected.reason_code} · {formatTime(selected.created_at)}</p></div>
            <StatusPill status={selected.status} />
          </div>
          <div className="alert-detail-body">
            <div className="detail-grid">
              <div><span>风险级别</span><Risk level={selected.severity} /></div>
              <div><span>判定阶段</span><b>{selected.final_stage}</b></div>
              <div><span>原因</span><b>{selected.reason}</b></div>
              {selected.acknowledged_at && <div><span>确认时间</span><b>{formatTime(selected.acknowledged_at)}</b></div>}
              {selected.operator_note && <div><span>备注</span><b>{selected.operator_note}</b></div>}
            </div>
            {selected.evidence?.length > 0 && <div className="evidence"><b>授权证据</b>{selected.evidence.map(line => <span key={line}>{line}</span>)}</div>}
            {selected.actions?.length > 0 && (
              <div className="evidence"><b>拟执行动作</b>
                {selected.actions.map((action, index) => <span key={index}>{action.name}{action.target ? ` · ${action.target}` : ''}</span>)}
              </div>
            )}
            {selected.matched_rules?.length > 0 && <div className="evidence"><b>命中规则</b>{selected.matched_rules.map(line => <code key={line}>{line}</code>)}</div>}
            <div className="triage">
              <b>处置状态</b>
              <div className="triage-actions">
                {STATUSES.map(status => <button key={status} className={selected.status === status ? 'primary' : 'secondary'} disabled={selected.status === status} onClick={() => setStatus(selected.id, status)}>{status}</button>)}
              </div>
            </div>
            <div className="triage">
              <b>人工反馈</b>
              <div className="triage-actions">
                {FEEDBACKS.map(item => <button key={item.value} className="secondary" onClick={() => feedback(selected.id, item.value)}>{item.label}</button>)}
              </div>
            </div>
            {onOpenTrace && <button className="primary" onClick={() => onOpenTrace(selected.session_record_id, selected.trace_id)}>↗ 在会话时间线中定位</button>}
          </div>
        </section>
      ) : <section className="panel detail-empty"><h2>选择一条告警</h2><p>查看证据、拟执行动作并处置。</p></section>}
    </div>
  )
}
