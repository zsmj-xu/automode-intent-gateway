import type { DashboardData } from '../types'
import { useLoad } from '../lib/hooks'
import { ErrorState, Health, Loading, Metric, PanelTitle } from '../components/ui'

export function Dashboard({ refresh, onOpenTrace, onOpenAlerts }: { refresh: number; onOpenTrace?: (sessionId: string | null, traceId: string) => void; onOpenAlerts?: () => void }) {
  const { data, error } = useLoad<DashboardData>('/api/dashboard', refresh)
  const alerts = useLoad<{ data: any[] }>('/api/alerts?limit=5&status=open', refresh).data?.data || []
  if (error) return <ErrorState message={error} />
  if (!data) return <Loading />

  const total = Math.max(data.trace_count || 1, 1)
  const allow = data.decisions?.allow || 0
  const alerted = data.decisions?.alert || 0
  const latency = data.classification_latency_ms || {}
  const dlp = data.dlp || { reviewed: 0, alerts: 0, category_counts: {}, destination_counts: {} }
  const totalFindings = Object.values(dlp.category_counts).reduce((sum, value) => sum + value, 0)
  const totalDestinations = Object.values(dlp.destination_counts).reduce((sum, value) => sum + value, 0) || 1

  return (
    <>
      <section className="health-grid" aria-label="服务健康状态">
        {(['gateway', 'upstream', 'fast', 'deep'] as const).map(key => (
          <article className="health-card" key={key}>
            <span>{({ gateway: 'Gateway', upstream: '上游模型', fast: 'Fast LLM', deep: 'Deep LLM' })[key]}</span>
            <Health status={data.health?.[key] || 'unknown'} />
          </article>
        ))}
      </section>

      <section className="metric-grid">
        <Metric label="出站请求" value={dlp.reviewed || data.trace_count} detail="Shadow DLP 已审查" />
        <Metric label="活跃会话" value={data.session_count} detail="按 Agent 会话聚合" />
        <Metric label="敏感发现" value={totalFindings} detail={`${Object.keys(dlp.category_counts).length} 个数据类别`} />
        <Metric label="DLP 告警率" value={`${Math.round(((dlp.alerts || alerted) / total) * 100)}%`} detail={`${data.open_alert_count} 个开放 / ${dlp.alerts || alerted} 次累计`} tone="danger" />
      </section>

      <div className="two-column" style={{ marginTop: '16px' }}>
        <section className="panel">
          <PanelTitle title="敏感数据类别分布" subtitle="本地高置信确定性检测" />
          {Object.keys(dlp.category_counts).length ? (
            <div className="bars">
              {Object.entries(dlp.category_counts).map(([category, count]) => (
                <div className="bar-row" key={category}>
                  <span><code>{category}</code></span>
                  <div className="bar-track">
                    <i style={{ width: `${Math.max(4, (count / Math.max(totalFindings, 1)) * 100)}%`, background: category === 'credential' ? 'var(--danger)' : 'var(--accent)' }} />
                  </div>
                  <b>{count}</b>
                </div>
              ))}
            </div>
          ) : <span style={{ color: 'var(--muted)', fontSize: '12px' }}>暂无敏感发现</span>}
        </section>

        <section className="panel">
          <PanelTitle title="模型目标分布" subtitle="未注册目标按 external 处理" />
          {Object.keys(dlp.destination_counts).length ? (
            <div className="bars">
              {Object.entries(dlp.destination_counts).map(([target, count]) => (
                <div className="bar-row" key={target}>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{target}</span>
                  <div className="bar-track">
                    <i style={{ width: `${Math.max(4, (count / totalDestinations) * 100)}%`, background: target.includes('external') || target.includes('未注册') ? 'var(--warn)' : 'var(--safe)' }} />
                  </div>
                  <b>{count}</b>
                </div>
              ))}
            </div>
          ) : <span style={{ color: 'var(--muted)', fontSize: '12px' }}>暂无目标数据</span>}
        </section>
      </div>

      <div className="two-column">
        <section className="panel">
          <PanelTitle title="判定分布" subtitle="Rules / Fast / Deep 调用量" />
          <div className="bars">
            {(['rules', 'fast_llm', 'deep_llm'] as const).map((stage, index) => (
              <div className="bar-row" key={stage}>
                <span>{['Rules', 'Fast LLM', 'Deep LLM'][index]}</span>
                <div className="bar-track"><i style={{ width: `${Math.max(3, ((data.stage_counts?.[stage] || 0) / total) * 100)}%` }} /></div>
                <b>{data.stage_counts?.[stage] || 0}</b>
              </div>
            ))}
          </div>
        </section>
        <section className="panel">
          <PanelTitle title="分类延迟与高频原因" subtitle="完整判定管线耗时" />
          <div className="latency-grid">
            <Metric label="P50" value={`${Number(latency.p50 || 0).toFixed(1)} ms`} detail="中位数" />
            <Metric label="P95" value={`${Number(latency.p95 || 0).toFixed(1)} ms`} detail="尾部延迟" />
          </div>
          <div className="reason-list">
            <b>高频告警原因</b>
            {data.top_reasons?.length ? (
              <ul className="rank-list">{data.top_reasons.slice(0, 3).map(item => <li key={item.reason_code}><code>{item.reason_code}</code><b>{item.count}</b></li>)}</ul>
            ) : <span>暂无告警原因</span>}
          </div>
        </section>
      </div>

      <section className="panel">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <PanelTitle title="最新开放告警" subtitle="敏感数据、目标模型和命中策略" />
          {onOpenAlerts && <button className="text-button" onClick={onOpenAlerts}>查看全部告警 →</button>}
        </div>
        {alerts.length ? <AlertTable rows={alerts} onOpenTrace={onOpenTrace} /> : <div className="empty"><p>当前没有开放告警</p></div>}
      </section>
    </>
  )
}

function AlertTable({ rows, onOpenTrace }: { rows: any[]; onOpenTrace?: (sessionId: string | null, traceId: string) => void }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>级别</th><th>原因</th><th>阶段</th><th>状态</th><th>时间</th><th>操作</th></tr></thead>
        <tbody>
          {rows.map(row => (
            <tr key={row.id}>
              <td><RiskMini level={row.severity} /></td>
              <td><b>{row.title}</b><code>{row.reason_code}</code></td>
              <td>{row.final_stage}</td>
              <td>{row.status}</td>
              <td>{formatTimeShort(row.created_at)}</td>
              <td>
                {onOpenTrace && (
                  <button className="text-button" onClick={() => onOpenTrace(row.session_record_id, row.trace_id)}>
                    定位 ↗
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function RiskMini({ level }: { level: string }) {
  return <span className={`risk ${level}`}>{level}</span>
}

function formatTimeShort(value?: string): string {
  return value ? new Intl.DateTimeFormat('zh-CN', { timeStyle: 'short' }).format(new Date(value)) : '—'
}
