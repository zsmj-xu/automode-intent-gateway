import type { DashboardData } from '../types'
import { useLoad } from '../lib/hooks'
import { ErrorState, Health, Loading, Metric, PanelTitle } from '../components/ui'

export function Dashboard({ refresh }: { refresh: number }) {
  const { data, error } = useLoad<DashboardData>('/api/dashboard', refresh)
  const alerts = useLoad<{ data: any[] }>('/api/alerts?limit=5&status=open', refresh).data?.data || []
  if (error) return <ErrorState message={error} />
  if (!data) return <Loading />

  const total = Math.max(data.trace_count || 1, 1)
  const allow = data.decisions?.allow || 0
  const alerted = data.decisions?.alert || 0
  const latency = data.classification_latency_ms || {}

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
        <Metric label="模型调用" value={data.trace_count} detail="已记录 Trace" />
        <Metric label="活跃会话" value={data.session_count} detail="按 Agent 会话聚合" />
        <Metric label="允许率" value={`${Math.round((allow / total) * 100)}%`} detail={`${allow} 次直接或复核允许`} />
        <Metric label="告警率" value={`${Math.round((data.alert_rate || 0) * 100)}%`} detail={`${data.open_alert_count} 个开放 / ${alerted} 次累计`} tone="danger" />
      </section>
      <div className="two-column">
        <section className="panel">
          <PanelTitle title="判定分布" subtitle="Rules / Fast / Deep 实际调用量" />
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
          <PanelTitle title="分类延迟" subtitle="完整判定管线耗时" />
          <div className="latency-grid">
            <Metric label="P50" value={`${Number(latency.p50 || 0).toFixed(1)} ms`} detail="中位数" />
            <Metric label="P95" value={`${Number(latency.p95 || 0).toFixed(1)} ms`} detail="尾部延迟" />
          </div>
          <div className="reason-list">
            <b>高频原因</b>
            {data.top_reasons?.length ? (
              <ul className="rank-list">{data.top_reasons.slice(0, 3).map(item => <li key={item.reason_code}><code>{item.reason_code}</code><b>{item.count}</b></li>)}</ul>
            ) : <span>暂无告警原因</span>}
          </div>
        </section>
      </div>
      <section className="panel">
        <PanelTitle title="最新开放告警" subtitle="需要操作员关注的工具动作" />
        {alerts.length ? <AlertTable rows={alerts} /> : <div className="empty"><p>当前没有开放告警</p></div>}
      </section>
    </>
  )
}

function AlertTable({ rows }: { rows: any[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>级别</th><th>原因</th><th>阶段</th><th>状态</th><th>时间</th></tr></thead>
        <tbody>
          {rows.map(row => (
            <tr key={row.id}>
              <td><RiskMini level={row.severity} /></td>
              <td><b>{row.title}</b><code>{row.reason_code}</code></td>
              <td>{row.final_stage}</td>
              <td>{row.status}</td>
              <td>{formatTimeShort(row.created_at)}</td>
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
