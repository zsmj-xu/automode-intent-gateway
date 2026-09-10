import { useEffect, useState } from 'react'
import { AlertCircle, AlertTriangle, CheckCircle2, Clock, Copy, Key, Layers, Plus, RefreshCw, RotateCcw, Shield, Trash2, X } from 'lucide-react'
import type { EventItem, SourceItem } from '../types'
import { fetchEvents, fetchEventDetail, retryEvent, fetchSources, createSource, updateSource, deleteSource } from '../api'
import { formatTime } from '../lib/format'
import { Empty, ErrorState, Loading, PanelTitle, Risk, StatusPill } from '../components/ui'

export function Events({ refresh }: { refresh: number }) {
  const [activeTab, setActiveTab] = useState<'events' | 'sources'>('events')
  const [localRefresh, setLocalRefresh] = useState(0)

  // Events list state
  const [events, setEvents] = useState<EventItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null)
  const [detailEvent, setDetailEvent] = useState<EventItem | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [retryBusy, setRetryBusy] = useState(false)
  const [actionNotice, setActionNotice] = useState('')

  // Filters
  const [sourceFilter, setSourceFilter] = useState('')
  const [timeFilter, setTimeFilter] = useState<'all' | 'realtime' | 'historical'>('all')
  const [statusFilter, setStatusFilter] = useState('')
  const [assocFilter, setAssocFilter] = useState('')

  // Sources list state
  const [sources, setSources] = useState<SourceItem[]>([])
  const [sourcesLoading, setSourcesLoading] = useState(false)
  const [createSourceOpen, setCreateSourceOpen] = useState(false)
  const [newSourceName, setNewSourceName] = useState('')
  const [newSourceId, setNewSourceId] = useState('')
  const [newSourceToken, setNewSourceToken] = useState('')
  const [newSourceTrusted, setNewSourceTrusted] = useState(false)
  const [newSourceRateLimit, setNewSourceRateLimit] = useState<number | undefined>(undefined)
  const [sourceSaving, setSourceSaving] = useState(false)

  // Load events
  useEffect(() => {
    let active = true
    setLoading(true)
    setError('')
    const isHistorical = timeFilter === 'historical' ? true : timeFilter === 'realtime' ? false : undefined
    fetchEvents({
      limit: 100,
      source_id: sourceFilter || undefined,
      is_historical: isHistorical,
      processing_status: statusFilter || undefined,
      association_status: assocFilter || undefined,
    })
      .then(res => {
        if (!active) return
        setEvents(res.data || [])
        setTotal(res.total || 0)
        setLoading(false)
      })
      .catch(err => {
        if (!active) return
        setError(err.message || '加载事件失败')
        setLoading(false)
      })
    return () => { active = false }
  }, [refresh, localRefresh, sourceFilter, timeFilter, statusFilter, assocFilter])

  // Load sources
  useEffect(() => {
    if (activeTab === 'sources') {
      loadSources()
    }
  }, [activeTab, refresh, localRefresh])

  function loadSources() {
    setSourcesLoading(true)
    fetchSources()
      .then(res => {
        setSources(res.data || [])
        setSourcesLoading(false)
      })
      .catch(() => setSourcesLoading(false))
  }

  // Load event detail when selected
  useEffect(() => {
    if (!selectedEventId) {
      setDetailEvent(null)
      return
    }
    let active = true
    setDetailLoading(true)
    fetchEventDetail(selectedEventId)
      .then(res => {
        if (active) {
          setDetailEvent(res)
          setDetailLoading(false)
        }
      })
      .catch(err => {
        if (active) {
          setActionNotice(`加载详情失败: ${err.message}`)
          setDetailLoading(false)
        }
      })
    return () => { active = false }
  }, [selectedEventId, localRefresh])

  async function handleRetry(eventId: string) {
    setRetryBusy(true)
    setActionNotice('')
    try {
      await retryEvent(eventId)
      setActionNotice(`已重置并重试事件 ${eventId}`)
      setLocalRefresh(v => v + 1)
    } catch (err: any) {
      setActionNotice(`重试失败: ${err.message}`)
    } finally {
      setRetryBusy(false)
    }
  }

  async function handleCreateSource(e: React.FormEvent) {
    e.preventDefault()
    if (!newSourceName.trim()) return
    setSourceSaving(true)
    try {
      await createSource({
        id: newSourceId.trim() || undefined,
        name: newSourceName.trim(),
        token: newSourceToken.trim() || undefined,
        allow_trusted_identity: newSourceTrusted,
        rate_limit_per_minute: newSourceRateLimit || undefined,
      })
      setCreateSourceOpen(false)
      setNewSourceName('')
      setNewSourceId('')
      setNewSourceToken('')
      setNewSourceTrusted(false)
      setNewSourceRateLimit(undefined)
      loadSources()
    } catch (err: any) {
      window.alert(`创建失败: ${err.message}`)
    } finally {
      setSourceSaving(false)
    }
  }

  async function handleToggleSource(source: SourceItem) {
    try {
      await updateSource(source.id, { enabled: !source.enabled })
      loadSources()
    } catch (err: any) {
      window.alert(`更新失败: ${err.message}`)
    }
  }

  async function handleDeleteSource(sourceId: string) {
    if (!window.confirm(`确定要删除来源 ${sourceId} 吗？`)) return
    try {
      await deleteSource(sourceId)
      loadSources()
    } catch (err: any) {
      window.alert(`删除失败: ${err.message}`)
    }
  }

  return (
    <div className="events-layout" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <section className="panel">
        <PanelTitle
          title="标准事件中心"
          subtitle="透明可靠接入出站事件，分阶段驱动 DLP 规则检测与 LLM 深度审查"
          actions={
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div className="alert-filter-segmented">
                <button className={activeTab === 'events' ? 'active' : ''} onClick={() => setActiveTab('events')}>
                  <Layers size={14} style={{ marginRight: '4px', verticalAlign: 'middle' }} />事件流 ({total})
                </button>
                <button className={activeTab === 'sources' ? 'active' : ''} onClick={() => setActiveTab('sources')}>
                  <Key size={14} style={{ marginRight: '4px', verticalAlign: 'middle' }} />来源与授权
                </button>
              </div>
              <button className="secondary compact" onClick={() => setLocalRefresh(v => v + 1)}>
                <RefreshCw size={14} /> 刷新
              </button>
            </div>
          }
        />

        {actionNotice && (
          <div style={{ padding: '8px 12px', marginBottom: '12px', background: 'rgba(59,130,246,0.1)', border: '1px solid #3b82f6', borderRadius: '6px', fontSize: '13px', display: 'flex', justifyContent: 'space-between' }}>
            <span>{actionNotice}</span>
            <button className="text-button" onClick={() => setActionNotice('')}>关闭</button>
          </div>
        )}

        {activeTab === 'events' && (
          <>
            {/* Filters */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginBottom: '16px', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '12px', color: 'var(--muted)' }}>来源:</span>
                <input
                  type="text"
                  placeholder="按 source_id 过滤..."
                  value={sourceFilter}
                  onChange={e => setSourceFilter(e.target.value)}
                  style={{ padding: '4px 8px', fontSize: '12px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--bg-input)' }}
                />
              </div>

              <div className="alert-filter-segmented">
                <button className={timeFilter === 'all' ? 'active' : ''} onClick={() => setTimeFilter('all')}>全部时效</button>
                <button className={timeFilter === 'realtime' ? 'active' : ''} onClick={() => setTimeFilter('realtime')}>⚡ 实时事件</button>
                <button className={timeFilter === 'historical' ? 'active' : ''} onClick={() => setTimeFilter('historical')}>📜 历史补发</button>
              </div>

              <div className="alert-filter-segmented">
                <button className={statusFilter === '' ? 'active' : ''} onClick={() => setStatusFilter('')}>全部状态</button>
                <button className={statusFilter === 'pending' ? 'active' : ''} onClick={() => setStatusFilter('pending')}>待处理</button>
                <button className={statusFilter === 'processing' ? 'active' : ''} onClick={() => setStatusFilter('processing')}>处理中</button>
                <button className={statusFilter === 'completed' ? 'active' : ''} onClick={() => setStatusFilter('completed')}>已完成</button>
                <button className={statusFilter === 'failed' ? 'active' : ''} onClick={() => setStatusFilter('failed')}>⚠️ 失败</button>
              </div>

              <div className="alert-filter-segmented">
                <button className={assocFilter === '' ? 'active' : ''} onClick={() => setAssocFilter('')}>全部关联</button>
                <button className={assocFilter === 'associated' ? 'active' : ''} onClick={() => setAssocFilter('associated')}>已关联</button>
                <button className={assocFilter === 'request_missing' ? 'active' : ''} onClick={() => setAssocFilter('request_missing')}>⚠️ 请求缺失</button>
                <button className={assocFilter === 'none' ? 'active' : ''} onClick={() => setAssocFilter('none')}>未关联</button>
              </div>
            </div>

            {loading ? (
              <Loading />
            ) : error ? (
              <ErrorState message={error} />
            ) : !events.length ? (
              <Empty text="未查询到符合条件的事件记录" />
            ) : (
              <div className="table-wrap">
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                  <thead>
                    <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
                      <th>来源 / 事件 ID</th>
                      <th>类型 / 协议</th>
                      <th>阶段 / 完整性</th>
                      <th>关联状态</th>
                      <th>双通道判定</th>
                      <th>关联告警</th>
                      <th>处理状态</th>
                      <th>发生 / 接收时间</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map(ev => {
                      const evId = ev.id || ev.event_id || ''
                      const externalId = ev.external_event_id || ev.event_id || evId
                      const ruleRisk = ev.rule_verdict?.risk
                      const llmRisk = ev.llm_verdict?.llm_severity || (ev.llm_status === 'completed' ? ev.llm_verdict?.risk : null)
                      const isRequestMissing = ev.association_status === 'request_missing'
                      return (
                        <tr key={evId} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                          <td>
                            <div style={{ display: 'flex', flexDirection: 'column' }}>
                              <span style={{ fontWeight: 600 }}><code>{ev.source_id}</code></span>
                              <small title={externalId} style={{ color: 'var(--muted)', fontSize: '11px' }}>{externalId.slice(0, 16)}...</small>
                              <span style={{ fontSize: '10px', marginTop: '2px' }}>
                                {ev.is_realtime ? <span style={{ color: 'var(--safe)' }}>⚡ 实时</span> : <span style={{ color: 'var(--muted)' }}>📜 历史</span>}
                              </span>
                            </div>
                          </td>
                          <td>
                            <div><b>{ev.event_type}</b></div>
                            <small style={{ color: 'var(--muted)', fontSize: '11px' }}>{ev.protocol}</small>
                          </td>
                          <td>
                            <div>
                              <span className={`status-pill ${ev.capture_stage === 'model_outbound' ? 'warn' : ''}`} style={{ fontSize: '11px' }}>
                                {ev.capture_stage}
                              </span>
                            </div>
                            <small style={{ color: ev.content_integrity === 'complete' ? 'var(--safe)' : 'var(--warn)', fontSize: '11px' }}>
                              {ev.content_integrity}
                            </small>
                          </td>
                          <td>
                            {isRequestMissing ? (
                              <span style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', border: '1px solid #ef4444', padding: '2px 6px', borderRadius: '4px', fontWeight: 600, fontSize: '11px' }}>
                                ⚠️ 缺失对应请求
                              </span>
                            ) : ev.association_status === 'associated' ? (
                              <span style={{ color: 'var(--safe)', fontSize: '11px' }}>✓ 已关联</span>
                            ) : (
                              <span style={{ color: 'var(--muted)', fontSize: '11px' }}>未关联</span>
                            )}
                          </td>
                          <td>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                              <div style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                <span style={{ color: 'var(--muted)' }}>规则:</span>
                                {ruleRisk ? <Risk level={ruleRisk} /> : <span style={{ color: 'var(--muted)' }}>{ev.rule_status}</span>}
                              </div>
                              <div style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                <span style={{ color: 'var(--muted)' }}>LLM:</span>
                                {llmRisk ? <Risk level={llmRisk} /> : <span style={{ color: 'var(--muted)' }}>{ev.llm_status}</span>}
                              </div>
                            </div>
                          </td>
                          <td>
                            {ev.alerts && ev.alerts.length > 0 ? (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                {ev.alerts.map(al => (
                                  <span key={al.id} style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                    <Risk level={al.severity} />
                                    <span style={{ fontSize: '10px', background: 'rgba(255,255,255,0.05)', padding: '1px 4px', borderRadius: '3px' }}>
                                      {al.channel_source || 'alert'}
                                    </span>
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span style={{ color: 'var(--muted)', fontSize: '11px' }}>无告警</span>
                            )}
                          </td>
                          <td>
                            <StatusPill status={ev.processing_status} />
                            {ev.retry_count > 0 && <small style={{ display: 'block', color: 'var(--warn)', fontSize: '10px' }}>重试: {ev.retry_count}</small>}
                          </td>
                          <td>
                            <div style={{ fontSize: '11px' }}>{formatTime(ev.received_at)}</div>
                            <small style={{ color: 'var(--muted)', fontSize: '10px' }}>发生: {formatTime(ev.timestamp)}</small>
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                              <button
                                className="secondary compact"
                                style={{ fontSize: '11px', padding: '2px 8px' }}
                                onClick={() => setSelectedEventId(evId)}
                              >
                                详情
                              </button>
                              {ev.processing_status === 'failed' && (
                                <button
                                  className="primary compact"
                                  title="重试此事件"
                                  style={{ fontSize: '11px', padding: '2px 8px' }}
                                  disabled={retryBusy}
                                  onClick={() => handleRetry(evId)}
                                >
                                  重试
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}

        {activeTab === 'sources' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <p style={{ margin: 0, fontSize: '13px', color: 'var(--muted)' }}>
                管理已登记的接入服务及凭证。配置是否接受来源提供的可信身份。
              </p>
              <button className="primary compact" onClick={() => setCreateSourceOpen(true)}>
                <Plus size={14} style={{ marginRight: '4px' }} /> 添加接入来源
              </button>
            </div>

            {sourcesLoading ? (
              <Loading />
            ) : !sources.length ? (
              <Empty text="暂无登记的接入来源，请点击上方按钮添加" />
            ) : (
              <div className="table-wrap">
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                  <thead>
                    <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
                      <th>来源 ID / 名称</th>
                      <th>接入 Token</th>
                      <th>可信身份授权</th>
                      <th>速率限制</th>
                      <th>状态</th>
                      <th>创建时间</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sources.map(src => (
                      <tr key={src.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td>
                          <b>{src.name}</b>
                          <div style={{ fontSize: '11px', color: 'var(--muted)' }}><code>{src.id}</code></div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <code style={{ fontSize: '11px' }}>{src.token.slice(0, 8)}...{src.token.slice(-6)}</code>
                            <button
                              className="text-button"
                              title="复制完整 Token"
                              onClick={() => {
                                navigator.clipboard.writeText(src.token)
                                setActionNotice(`Token 已复制到剪贴板`)
                              }}
                            >
                              <Copy size={12} />
                            </button>
                          </div>
                        </td>
                        <td>
                          {src.allow_trusted_identity ? (
                            <span style={{ color: 'var(--safe)', fontSize: '12px' }}>✓ 允许传入身份</span>
                          ) : (
                            <span style={{ color: 'var(--muted)', fontSize: '12px' }}>✕ 仅匿名/外部</span>
                          )}
                        </td>
                        <td>{src.rate_limit_per_minute ? `${src.rate_limit_per_minute} 次/分` : '无限制'}</td>
                        <td>
                          <button
                            className="text-button"
                            style={{ color: src.enabled ? 'var(--safe)' : 'var(--muted)', fontWeight: 600 }}
                            onClick={() => handleToggleSource(src)}
                          >
                            {src.enabled ? '● 已启用' : '○ 已停用'}
                          </button>
                        </td>
                        <td><small>{formatTime(src.created_at)}</small></td>
                        <td>
                          <button
                            className="icon-button"
                            title="删除来源"
                            style={{ color: 'var(--danger)' }}
                            onClick={() => handleDeleteSource(src.id)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Event Detail Modal */}
      {selectedEventId && (
        <div className="modal-backdrop" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.65)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '20px' }}>
          <div className="panel" style={{ width: '850px', maxHeight: '90vh', overflowY: 'auto', position: 'relative' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid var(--border)', paddingBottom: '12px' }}>
              <div>
                <h2 style={{ margin: 0, fontSize: '18px' }}>事件处理详情</h2>
                <small style={{ color: 'var(--muted)' }}><code>{selectedEventId}</code></small>
              </div>
              <button className="icon-button" onClick={() => setSelectedEventId(null)}><X size={18} /></button>
            </div>

            {detailLoading || !detailEvent ? (
              <Loading />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {detailEvent.processing_status === 'failed' && (
                  <div style={{ padding: '12px 16px', background: 'rgba(239,68,68,0.1)', border: '1px solid #ef4444', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div>
                      <b style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <AlertCircle size={16} /> 处理失败
                      </b>
                      <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--muted)' }}>{detailEvent.error_message || '未知异常'}</p>
                    </div>
                    <button
                      className="primary compact"
                      disabled={retryBusy}
                      onClick={() => handleRetry(detailEvent.id)}
                    >
                      <RotateCcw size={14} style={{ marginRight: '4px' }} /> 重新排队执行
                    </button>
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '6px', fontSize: '12px' }}>
                  <div><span style={{ color: 'var(--muted)' }}>来源:</span> <b>{detailEvent.source_id}</b></div>
                  <div><span style={{ color: 'var(--muted)' }}>调用 ID:</span> <code>{detailEvent.call_id}</code></div>
                  <div><span style={{ color: 'var(--muted)' }}>事件类型:</span> <b>{detailEvent.event_type}</b></div>
                  <div><span style={{ color: 'var(--muted)' }}>协议:</span> <b>{detailEvent.protocol}</b></div>
                  <div><span style={{ color: 'var(--muted)' }}>采集阶段:</span> <b>{detailEvent.capture_stage}</b></div>
                  <div><span style={{ color: 'var(--muted)' }}>完整性:</span> <b>{detailEvent.content_integrity}</b></div>
                  <div><span style={{ color: 'var(--muted)' }}>时效:</span> <b>{detailEvent.is_realtime ? '实时' : '历史补发'}</b></div>
                  <div><span style={{ color: 'var(--muted)' }}>关联状态:</span> <b>{detailEvent.association_status}</b></div>
                </div>

                {/* Two-Channel Verdicts */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <div className="panel" style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <b>🛡️ 规则阶段判定 (Rule Engine)</b>
                      <StatusPill status={detailEvent.rule_status} />
                    </div>
                    {detailEvent.rule_verdict ? (
                      <div style={{ fontSize: '12px', lineHeight: 1.6 }}>
                        <div>风险等级: <Risk level={detailEvent.rule_verdict.risk || 'low'} /></div>
                        <div>判定决策: <code>{detailEvent.rule_verdict.rule_decision || detailEvent.rule_verdict.decision || 'unknown'}</code></div>
                        {detailEvent.rule_verdict.reason_code && <div>原因码: <code>{detailEvent.rule_verdict.reason_code}</code></div>}
                        {detailEvent.rule_verdict.data_findings?.length > 0 && (
                          <div style={{ marginTop: '6px' }}>
                            <b>敏感线索 ({detailEvent.rule_verdict.data_findings.length}):</b>
                            <ul style={{ margin: '4px 0', paddingLeft: '18px' }}>
                              {detailEvent.rule_verdict.data_findings.map((f: any, i: number) => (
                                <li key={i}><code>{f.category}</code>: {f.snippet || f.path}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    ) : (
                      <span style={{ color: 'var(--muted)', fontSize: '12px' }}>尚无规则分析结果</span>
                    )}
                  </div>

                  <div className="panel" style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <b>🤖 LLM 阶段审查 (Reviewer)</b>
                      <StatusPill status={detailEvent.llm_status} />
                    </div>
                    {detailEvent.llm_verdict ? (
                      <div style={{ fontSize: '12px', lineHeight: 1.6 }}>
                        <div>风险等级: {detailEvent.llm_verdict.llm_severity ? <Risk level={detailEvent.llm_verdict.llm_severity} /> : <span>未产生等级，查看复核状态</span>}</div>
                        <div>摘要说明: {detailEvent.llm_verdict.reason || detailEvent.llm_verdict.summary || '暂无复核结论'}</div>
                      </div>
                    ) : (
                      <span style={{ color: 'var(--muted)', fontSize: '12px' }}>
                        {detailEvent.llm_status === 'skipped' ? '无需 LLM 深度复核 (跳过)' : '排队中或尚未完成'}
                      </span>
                    )}
                  </div>
                </div>

                {/* Tasks Timeline */}
                {!!detailEvent.response_evidence?.length && (
                  <details>
                    <summary>模型响应旁证（已脱敏，不证明工具执行）</summary>
                    <pre>{JSON.stringify(detailEvent.response_evidence, null, 2)}</pre>
                  </details>
                )}

                {detailEvent.tasks && detailEvent.tasks.length > 0 && (
                  <div>
                    <b style={{ fontSize: '13px' }}>异步执行任务状态</b>
                    <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {detailEvent.tasks.map(t => (
                        <div key={t.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', fontSize: '12px' }}>
                          <span>阶段: <b>{t.stage}</b> · 重试: {t.retry_count}</span>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <StatusPill status={t.status} />
                            <small style={{ color: 'var(--muted)' }}>{formatTime(t.updated_at)}</small>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Correlated Events */}
                {detailEvent.correlated_events && detailEvent.correlated_events.length > 0 && (
                  <div>
                    <b style={{ fontSize: '13px' }}>同调用关联事件 ({detailEvent.correlated_events.length})</b>
                    <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {detailEvent.correlated_events.map(c => (
                        <div key={c.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', fontSize: '12px' }}>
                          <span>{c.event_type} · <code>{c.id.slice(0, 12)}...</code></span>
                          <span>{c.capture_stage} · {c.content_integrity}</span>
                          <StatusPill status={c.processing_status} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Create Source Modal */}
      {createSourceOpen && (
        <div className="modal-backdrop" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.65)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '20px' }}>
          <div className="panel" style={{ width: '500px', position: 'relative' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h2 style={{ margin: 0, fontSize: '16px' }}>添加接入来源</h2>
              <button className="icon-button" onClick={() => setCreateSourceOpen(false)}><X size={18} /></button>
            </div>
            <form onSubmit={handleCreateSource} style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
              <label>
                来源名称 *
                <input
                  type="text"
                  required
                  placeholder="例如: Internal Agent Gateway"
                  value={newSourceName}
                  onChange={e => setNewSourceName(e.target.value)}
                  style={{ width: '100%', marginTop: '4px', padding: '6px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--bg-input)' }}
                />
              </label>
              <label>
                来源 ID (可选，留空自动生成)
                <input
                  type="text"
                  placeholder="例如: src_internal_agent"
                  value={newSourceId}
                  onChange={e => setNewSourceId(e.target.value)}
                  style={{ width: '100%', marginTop: '4px', padding: '6px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--bg-input)' }}
                />
              </label>
              <label>
                接入 Token (可选，留空自动生成随机秘钥)
                <input
                  type="text"
                  placeholder="留空自动生成安全 Token"
                  value={newSourceToken}
                  onChange={e => setNewSourceToken(e.target.value)}
                  style={{ width: '100%', marginTop: '4px', padding: '6px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--bg-input)' }}
                />
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={newSourceTrusted}
                  onChange={e => setNewSourceTrusted(e.target.checked)}
                />
                <span>允许该来源提供可信身份 (allow_trusted_identity)</span>
              </label>
              <label>
                速率限制 (每分钟最大事件数，留空无限制)
                <input
                  type="number"
                  placeholder="例如: 1000"
                  value={newSourceRateLimit ?? ''}
                  onChange={e => setNewSourceRateLimit(e.target.value ? Number(e.target.value) : undefined)}
                  style={{ width: '100%', marginTop: '4px', padding: '6px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--bg-input)' }}
                />
              </label>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '12px' }}>
                <button type="button" className="secondary" onClick={() => setCreateSourceOpen(false)}>取消</button>
                <button type="submit" className="primary" disabled={sourceSaving}>
                  {sourceSaving ? '保存中...' : '确认创建'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
