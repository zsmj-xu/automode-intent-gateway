import { useState } from 'react'
import type { DashboardData, SystemStats } from '../types'
import { useLoad } from '../lib/hooks'
import { ErrorState, Health, Loading, Metric, PanelTitle } from '../components/ui'

export function Dashboard({ refresh, onOpenTrace, onOpenAlerts }: { refresh: number; onOpenTrace?: (sessionId: string | null, traceId: string) => void; onOpenAlerts?: () => void }) {
  const { data, error } = useLoad<DashboardData>('/api/dashboard', refresh)
  const statsLoad = useLoad<SystemStats>('/api/stats', refresh)
  const [alertTypeFilter, setAlertTypeFilter] = useState<string>('')

  const alerts = useLoad<{ data: any[] }>(
    `/api/alerts?limit=10&status=open${alertTypeFilter ? `&alert_type=${alertTypeFilter}` : ''}`,
    refresh + (alertTypeFilter ? 10 : 0)
  ).data?.data || []

  if (error) return <ErrorState message={error} />
  if (!data) return <Loading />

  const stats = statsLoad.data || data.event_stats
  const total = Math.max(data.trace_count || 1, 1)
  const allow = data.decisions?.allow || 0
  const alerted = data.decisions?.alert || 0
  const latency = data.classification_latency_ms || {}
  const dlp = data.dlp || { reviewed: 0, alerts: 0, category_counts: {}, destination_counts: {} }
  const totalFindings = Object.values(dlp.category_counts).reduce((sum, value) => sum + value, 0)
  const totalDestinations = Object.values(dlp.destination_counts).reduce((sum, value) => sum + value, 0) || 1

  const diskUsedMB = ((stats?.disk_buffer_bytes || 0) / (1024 * 1024)).toFixed(1)
  const diskLimitMB = ((stats?.disk_buffer_limit_bytes || 1073741824) / (1024 * 1024)).toFixed(0)
  const diskPercent = Math.min(100, Math.round(((stats?.disk_buffer_bytes || 0) / (stats?.disk_buffer_limit_bytes || 1)) * 100))
  const reliability = ({
    persistent_encrypted: '标准事件已落盘',
    proxy_async_encrypted: '代理异步落盘，落盘前可能丢失',
    proxy_best_effort: '代理尽力分析，不保证恢复',
    standard_event_only: '独立事件服务',
    standard_event_disabled: '标准入口未配置密钥',
  } as Record<string, string>)[stats?.reliability_mode || ''] || '可靠性状态未知'

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

      {/* 事件接入与队列积压状态 */}
      <section className="metric-grid" aria-label="事件接入流水线积压">
        <Metric
          label="规则阶段积压"
          value={stats?.rule_queue_depth ?? 0}
          detail="Rule Worker 待处理"
          tone={stats && stats.rule_queue_depth > 10 ? 'warn' : undefined}
        />
        <Metric
          label="LLM 阶段积压"
          value={stats?.reviewer_queue_depth ?? 0}
          detail="Reviewer Worker 待审查"
          tone={stats && stats.reviewer_queue_depth > 10 ? 'warn' : undefined}
        />
        <Metric
          label="最老任务等待"
          value={stats?.oldest_pending_task_age_seconds != null ? `${stats.oldest_pending_task_age_seconds.toFixed(1)} s` : '无等待'}
          detail="排队等待时长"
          tone={stats && (stats.oldest_pending_task_age_seconds ?? 0) > 30 ? 'danger' : undefined}
        />
        <Metric
          label="磁盘加密缓冲"
          value={`${diskUsedMB} / ${diskLimitMB} MB`}
          detail={`${diskPercent}% 占用 · ${reliability}${stats?.proxy_dropped_count ? ` · 丢弃: ${stats.proxy_dropped_count}` : ''}`}
          tone={diskPercent > 80 ? 'danger' : undefined}
        />
      </section>

      <section className="metric-grid" style={{ marginTop: '12px' }}>
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
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
          <PanelTitle title="最新开放告警" subtitle="双通道 DLP 判定与会话意图告警" />
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div className="alert-filter-segmented">
              <button className={alertTypeFilter === '' ? 'active' : ''} onClick={() => setAlertTypeFilter('')}>全部类型</button>
              <button className={alertTypeFilter === 'dlp' ? 'active' : ''} onClick={() => setAlertTypeFilter('dlp')}>🛡️ 出站数据 (DLP)</button>
              <button className={alertTypeFilter === 'intent_action' ? 'active' : ''} onClick={() => setAlertTypeFilter('intent_action')}>⚡ 会话意图</button>
            </div>
            {onOpenAlerts && <button className="text-button" onClick={onOpenAlerts}>查看全部告警 →</button>}
          </div>
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
        <thead><tr><th>级别</th><th>原因与来源</th><th>阶段</th><th>状态</th><th>时间</th><th>操作</th></tr></thead>
        <tbody>
          {rows.map(row => (
            <tr key={row.id}>
              <td><RiskMini level={row.severity} /></td>
              <td>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                  {row.channel_source === 'dual' && <span className="cat-chip" style={{ background: 'rgba(124, 58, 237, 0.2)', color: '#a78bfa', border: '1px solid #7c3aed' }}>[Dual]</span>}
                  {row.channel_source === 'rule' && <span className="cat-chip" style={{ background: 'rgba(37, 99, 235, 0.2)', color: '#60a5fa', border: '1px solid #2563eb' }}>[Rule]</span>}
                  {row.channel_source === 'llm' && <span className="cat-chip" style={{ background: 'rgba(5, 150, 105, 0.2)', color: '#34d399', border: '1px solid #059669' }}>[LLM]</span>}
                  {row.divergence && <span className="status-pill warn" style={{ fontSize: '10px' }}>⚠️ [结论分歧]</span>}
                  <b>{row.title}</b>
                  <code>{row.reason_code}</code>
                </div>
              </td>
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
