import { useState } from 'react'
import { Beaker, ChevronDown, ChevronRight, Database, History, RotateCcw, Save, ShieldCheck, Sliders, Trash2, X } from 'lucide-react'
import type { Destination, DetectorItem, DLPPolicy, Json, Rule } from '../types'
import { useLoad } from '../lib/hooks'
import { formatTime, friendlyError } from '../lib/format'
import { api, del, patch, post } from '../api'
import { Empty, PanelTitle, StatusPill } from '../components/ui'

const DETECTOR_CATEGORIES = [
  { key: 'credential', label: '🔑 凭据与密钥 (Credentials)', desc: 'RSA/EC/SSH 私钥、API Token、数据库连接串、敏感变量赋值等' },
  { key: 'pii', label: '👤 个人身份隐私 (PII)', desc: '身份证号、手机号码、电子邮箱、社会保障号 (SSN) 等' },
  { key: 'source_code', label: '💻 源码与服务配置 (Source & Config)', desc: '代码片段特征及应用服务配置文件内容' },
] as const

export function Governance({ refresh }: { refresh: number }) {
  const [localRefresh, setLocalRefresh] = useState(0)
  const version = refresh + localRefresh
  const policies = useLoad<{ data: DLPPolicy[] }>(`/api/dlp-policies?v=${version}`, version).data?.data || []
  const targets = useLoad<{ data: Destination[] }>(`/api/destinations?v=${version}`, version).data?.data || []
  const detectors = useLoad<{ data: DetectorItem[] }>(`/api/detectors?v=${version}`, version).data?.data || []
  const legacy = useLoad<{ data: Rule[] }>(`/api/rules?v=${version}`, version).data?.data || []

  const [policyText, setPolicyText] = useState('凭据、PII 或源码发往外部模型时告警。')
  const [preview, setPreview] = useState<Json | null>(null)
  const [testText, setTestText] = useState('password=hunter2')
  const [testModel, setTestModel] = useState('unregistered-external')
  const [testResult, setTestResult] = useState<Json | null>(null)
  const [target, setTarget] = useState({ name: '', model_pattern: '', provider: '', region: '', trust: 'trusted' as 'trusted' | 'external' })
  const [expandedPolicyId, setExpandedPolicyId] = useState<string | null>(null)
  const [busy, setBusy] = useState('')
  const [message, setMessage] = useState('')

  async function compile() {
    setBusy('compile'); setMessage('')
    try { setPreview(await post('/api/dlp-policies/compile', { text: policyText })) }
    catch (error) { setMessage(friendlyError(error)) }
    finally { setBusy('') }
  }

  async function testPolicy() {
    if (!preview?.compiled) return
    setBusy('test')
    try {
      setTestResult(await post('/api/dlp-policies/test', {
        payload: { model: testModel.trim() || 'unregistered-external', messages: [{ role: 'user', content: testText }] },
        policy: preview.compiled,
      }))
    } catch (error) { setMessage(friendlyError(error)) }
    finally { setBusy('') }
  }

  async function savePolicy() {
    if (!preview?.compiled) return
    setBusy('save')
    try {
      await post('/api/dlp-policies', { compiled: preview.compiled, enabled: false })
      setPreview(null); setTestResult(null); setMessage('策略已保存，默认禁用，可在下方列表中启用。'); setLocalRefresh(value => value + 1)
    } catch (error) { setMessage(friendlyError(error)) }
    finally { setBusy('') }
  }

  async function togglePolicy(policy: DLPPolicy) {
    setBusy(policy.id)
    try {
      await post(`/api/dlp-policies/${policy.id}/${policy.enabled ? 'disable' : 'enable'}`, {})
      setLocalRefresh(value => value + 1)
    } finally { setBusy('') }
  }

  async function deletePolicy(policyId: string) {
    setBusy(`del-${policyId}`)
    try {
      await del(`/api/dlp-policies/${policyId}`)
      setMessage('策略已删除')
      setLocalRefresh(value => value + 1)
    } catch (error) { setMessage(friendlyError(error)) }
    finally { setBusy('') }
  }

  async function saveTarget() {
    setBusy('target'); setMessage('')
    try {
      await post('/api/destinations', { ...target, upstream_pattern: '*', model_pattern: target.model_pattern || '*' })
      setTarget({ name: '', model_pattern: '', provider: '', region: '', trust: 'trusted' })
      setMessage('模型目标已注册')
      setLocalRefresh(value => value + 1)
    } catch (error) { setMessage(friendlyError(error)) }
    finally { setBusy('') }
  }

  async function toggleTargetTrust(item: Destination) {
    if (!item.id) return
    setBusy(`trust-${item.id}`)
    try {
      const nextTrust = item.trust === 'trusted' ? 'external' : 'trusted'
      await patch(`/api/destinations/${item.id}`, { trust: nextTrust })
      setLocalRefresh(value => value + 1)
    } catch (error) { setMessage(friendlyError(error)) }
    finally { setBusy('') }
  }

  async function deleteTarget(targetId: string | null | undefined) {
    if (!targetId) return
    setBusy(`del-target-${targetId}`)
    try {
      await del(`/api/destinations/${targetId}`)
      setMessage('模型目标已移除')
      setLocalRefresh(value => value + 1)
    } catch (error) { setMessage(friendlyError(error)) }
    finally { setBusy('') }
  }

  async function toggleLegacyRule(row: Rule) {
    setBusy(`legacy-${row.id}`)
    try {
      await post(`/api/rules/${row.id}/${row.enabled ? 'disable' : 'enable'}`, {})
      setLocalRefresh(v => v + 1)
    } finally { setBusy('') }
  }

  return (
    <div className="rules-layout dlp-governance">
      <section className="panel">
        <PanelTitle title="出站数据策略" subtitle="自然语言编译为受限条件；确定性告警不能被 LLM 降级" />
        <label>策略描述<textarea rows={4} value={policyText} onChange={event => setPolicyText(event.target.value)} /></label>
        <button className="primary" disabled={!!busy} onClick={compile}><ShieldCheck size={17} />{busy === 'compile' ? '编译中…' : '编译预览'}</button>
        {message && <p className={message.includes('失败') ? 'form-error' : 'test-result'} role="status">{message}</p>}

        {preview?.compiled && (
          <div className="preview">
            <dl>
              <dt>效果</dt>
              <dd><StatusPill status={preview.compiled.effect} /></dd>
              <dt>结构化条件</dt>
              <dd><pre>{JSON.stringify(preview.compiled.conditions, null, 2)}</pre></dd>
            </dl>
            <div className="rule-test">
              <h3>Shadow 命中测试</h3>
              <div className="target-form">
                <label>出站内容<textarea rows={3} value={testText} onChange={event => setTestText(event.target.value)} /></label>
                <label>测试目标模型<input value={testModel} placeholder="例如 unregistered-external 或 corp-*" onChange={event => setTestModel(event.target.value)} /></label>
              </div>
              <div className="inline-actions" style={{ marginTop: '8px', gap: '8px' }}>
                <button className="secondary" disabled={!!busy} onClick={testPolicy}><Beaker size={16} />测试</button>
                <button className="primary" disabled={!!busy} onClick={savePolicy}><Save size={16} />保存策略</button>
              </div>
              {testResult && (
                <p className={`hit-result ${testResult.policy_decision === 'alert' ? 'matched' : ''}`} role="status">
                  {testResult.policy_decision} · {(testResult.data_findings || []).length} 个敏感发现 · 目标模型: {testModel} ({testResult.destination_trust || 'external'}) · 不阻断
                </p>
              )}
            </div>
          </div>
        )}

        <div className="rule-list" style={{ marginTop: '16px' }}>
          {policies.map(policy => (
            <article key={policy.id} style={{ display: 'grid', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <b>{policy.name}</b>
                  <span>{policy.original_text}</span>
                  <code>{policy.effect} · v{policy.version} · {formatTime(policy.updated_at)}</code>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <button className="icon-button" aria-label="查看条件" title="查看条件" onClick={() => setExpandedPolicyId(expandedPolicyId === policy.id ? null : policy.id)}>
                    {expandedPolicyId === policy.id ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                  </button>
                  <button className={policy.enabled ? 'toggle on' : 'toggle'} role="switch" aria-checked={policy.enabled} aria-label={`${policy.enabled ? '禁用' : '启用'} ${policy.name}`} disabled={!!busy} onClick={() => togglePolicy(policy)}>
                    <i />
                  </button>
                  <button className="icon-button" aria-label="删除策略" title="删除策略" disabled={busy === `del-${policy.id}`} onClick={() => deletePolicy(policy.id)}>
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
              {expandedPolicyId === policy.id && (
                <pre style={{ margin: '4px 0 0', padding: '8px', background: '#0b111d', borderRadius: '6px', fontSize: '11px', color: '#aebbd2', overflow: 'auto' }}>
                  {JSON.stringify(policy.conditions, null, 2)}
                </pre>
              )}
            </article>
          ))}
          {!policies.length && <Empty text="暂无自定义出站策略；内置敏感数据外发告警始终生效" />}
        </div>
      </section>

      {/* 内置确定性检测器矩阵 */}
      <section className="panel" style={{ gridColumn: '1 / -1' }}>
        <PanelTitle
          title="内置确定性硬检测器矩阵 (Built-in Detectors)"
          subtitle="本地毫秒级正则表达式扫描凭据、PII、源码；内置检测器始终启用，命中后产生确定性告警，不能被 LLM 降级"
        />

        <div className="detector-matrix-grid">
          {DETECTOR_CATEGORIES.map(cat => {
            const items = detectors.filter(d => d.category === cat.key)
            return (
              <div key={cat.key} className="detector-category-box">
                <div className="category-header">
                  <b>{cat.label}</b>
                  <span>{cat.desc}</span>
                </div>
                <div className="detector-items">
                  {items.map(item => (
                    <div key={item.id} className="detector-item-card enabled">
                      <div className="detector-item-info">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <b className="detector-name">{item.name}</b>
                          <code>{item.id}</code>
                        </div>
                        <p className="detector-desc">{item.description}</p>
                        <code className="detector-pattern" title={item.pattern}>
                          {item.pattern}
                        </code>
                      </div>
                      <span className="mode-badge">始终启用</span>
                    </div>
                  ))}
                  {!items.length && <p style={{ fontSize: '12px', color: 'var(--muted)' }}>加载中…</p>}
                </div>
              </div>
            )
          })}
        </div>
      </section>

      <section className="panel">
        <PanelTitle title="模型目标注册表" subtitle="未匹配目标默认 external；按模型别名匹配" />
        <div className="target-form">
          <label>目标名称<input value={target.name} placeholder="例如 内部自研模型" onChange={event => setTarget(value => ({ ...value, name: event.target.value }))} /></label>
          <label>模型模式<input placeholder="例如 corp-* 或 gpt-4o" value={target.model_pattern} onChange={event => setTarget(value => ({ ...value, model_pattern: event.target.value }))} /></label>
          <label>供应商<input placeholder="例如 Azure / Internal" value={target.provider} onChange={event => setTarget(value => ({ ...value, provider: event.target.value }))} /></label>
          <label>区域<input placeholder="例如 local / us-east-1" value={target.region} onChange={event => setTarget(value => ({ ...value, region: event.target.value }))} /></label>
          <label>信任级别
            <select value={target.trust} onChange={event => setTarget(value => ({ ...value, trust: event.target.value as 'trusted' | 'external' }))}>
              <option value="trusted">trusted（受信内部模型，可豁免敏感外发）</option>
              <option value="external">external（外部第三方模型，严格检测）</option>
            </select>
          </label>
        </div>
        <button className="primary" disabled={!!busy || !target.name.trim()} onClick={saveTarget}><Database size={17} />{busy === 'target' ? '保存中…' : '添加目标'}</button>

        <div className="rule-list target-list">
          {targets.map(item => (
            <article key={item.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
              <div>
                <b>{item.name}</b>
                <span>模式: <code>{item.model_pattern || '*'}</code> · {item.provider || '未填供应商'} · {item.region || '未填区域'}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button className="secondary compact" title="点击切换信任级别" disabled={busy === `trust-${item.id}`} onClick={() => toggleTargetTrust(item)}>
                  <StatusPill status={item.trust} />
                </button>
                <button className="icon-button" aria-label="移除目标" title="移除目标" disabled={busy === `del-target-${item.id}`} onClick={() => deleteTarget(item.id)}>
                  <Trash2 size={15} />
                </button>
              </div>
            </article>
          ))}
          {!targets.length && <Empty text="尚未注册受信模型；当前所有模型均视为 external" />}
        </div>

        <details className="legacy-rules">
          <summary>兼容的模型动作规则（{legacy.length} 条）</summary>
          <p style={{ margin: '8px 0', fontSize: '11px', color: 'var(--muted)' }}>原动作规则继续保留为调查旁证，不参与出站数据主判定。</p>
          <div className="rule-list" style={{ marginTop: '8px' }}>
            {legacy.map(row => (
              <article key={row.id}>
                <div>
                  <b>{row.name}</b>
                  <span>{row.original_text}</span>
                  <code>{row.reason_code} · v{row.version}</code>
                </div>
                <button className={row.enabled ? 'toggle on' : 'toggle'} role="switch" aria-checked={row.enabled} aria-label={`${row.enabled ? '禁用' : '启用'} ${row.name}`} disabled={!!busy} onClick={() => toggleLegacyRule(row)}>
                  <i />
                </button>
              </article>
            ))}
          </div>
        </details>
      </section>
    </div>
  )
}
