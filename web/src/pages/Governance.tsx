import { useMemo, useState } from 'react'
import { Beaker, ChevronDown, ChevronRight, Database, Plus, Save, ShieldCheck, Trash2, X } from 'lucide-react'
import type { Destination, DetectorItem, DLPPolicy, Json, Rule } from '../types'
import { useLoad } from '../lib/hooks'
import { formatTime, friendlyError } from '../lib/format'
import { api, del, patch, post } from '../api'
import { Empty, PanelTitle, StatusPill } from '../components/ui'

const DETECTOR_CATEGORIES = [
  { key: 'credential', label: '🔑 凭据与密钥 (Credentials)', desc: 'RSA/EC/SSH 私钥、API Token、数据库连接串、敏感变量赋值等' },
  { key: 'pii', label: '👤 个人身份隐私 (PII)', desc: '身份证号、手机号码、电子邮箱、社会保障号 (SSN) 等' },
  { key: 'source_code', label: '💻 源码与服务配置 (Source & Config)', desc: '代码片段特征及应用服务配置文件内容' },
  { key: 'admin_keyword', label: '🏷️ 业务敏感关键词 (Keywords)', desc: '业务特有敏感关键词或密级标记匹配' },
] as const

const POLICY_TEMPLATES = [
  { label: '凭据与私钥禁止外发', text: '凭据、私钥或数据库连接串发往任何非受信模型时立即告警。' },
  { label: '境内 PII 禁止出境', text: '中国居民身份证、手机号码发往外部第三方公网模型时告警。' },
  { label: '源码与服务配置防泄露', text: '包含源码片段或服务配置文件发往外部模型时告警。' },
]

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
  const [expandedPolicyId, setExpandedPolicyId] = useState<string | null>(null)

  const [showAddDetector, setShowAddDetector] = useState(false)
  const [customDet, setCustomDet] = useState({
    name: '',
    category: 'credential' as 'credential' | 'pii' | 'source_code' | 'admin_keyword',
    description: '',
    pattern: '',
  })
  const [customTestInput, setCustomTestInput] = useState('')

  const regexTestResult = useMemo(() => {
    if (!customDet.pattern.trim() || !customTestInput) return null
    try {
      const re = new RegExp(customDet.pattern, 'is')
      const matched = re.test(customTestInput)
      return { valid: true, matched }
    } catch (err) {
      return { valid: false, error: (err as Error).message }
    }
  }, [customDet.pattern, customTestInput])

  const [target, setTarget] = useState({ name: '', model_pattern: '', provider: '', region: '', trust: 'trusted' as 'trusted' | 'external' })
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
      await post('/api/dlp-policies', { compiled: preview.compiled, enabled: true })
      setPreview(null); setTestResult(null); setMessage('策略已保存并已默认启用。'); setLocalRefresh(value => value + 1)
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

  async function toggleDetector(item: DetectorItem) {
    setBusy(`det-${item.id}`)
    try {
      await patch(`/api/detectors/${item.id}`, { enabled: !item.enabled })
      setLocalRefresh(v => v + 1)
    } catch (error) { setMessage(friendlyError(error)) }
    finally { setBusy('') }
  }

  async function saveCustomDetector() {
    if (!customDet.name.trim() || !customDet.pattern.trim()) {
      setMessage('请填写检测器名称和正则表达式')
      return
    }
    setBusy('add-det'); setMessage('')
    try {
      await post('/api/detectors', customDet)
      setMessage(`自定义检测器「${customDet.name}」已添加并启用`)
      setCustomDet({ name: '', category: 'credential', description: '', pattern: '' })
      setCustomTestInput('')
      setShowAddDetector(false)
      setLocalRefresh(v => v + 1)
    } catch (error) {
      setMessage(friendlyError(error))
    } finally {
      setBusy('')
    }
  }

  async function deleteCustomDetector(detectorId: string) {
    setBusy(`del-det-${detectorId}`)
    try {
      await del(`/api/detectors/${detectorId}`)
      setMessage('自定义检测器已删除')
      setLocalRefresh(v => v + 1)
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
        <PanelTitle title="出站数据策略" subtitle="定义「哪些敏感数据」、「发往什么信任级别的模型」时产生告警；支持自然语言编译和实时启停开关" />

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', color: 'var(--muted)' }}>常用策略预设：</span>
          {POLICY_TEMPLATES.map(tpl => (
            <button key={tpl.label} className="secondary compact" style={{ fontSize: '11px', padding: '2px 8px' }} onClick={() => { setPolicyText(tpl.text); setPreview(null); }}>
              + {tpl.label}
            </button>
          ))}
        </div>

        <label>策略自然语言描述<textarea rows={3} value={policyText} onChange={event => setPolicyText(event.target.value)} /></label>
        <button className="primary" disabled={!!busy || !policyText.trim()} onClick={compile}><ShieldCheck size={17} />{busy === 'compile' ? '编译中…' : '编译预览'}</button>
        {message && <p className={message.includes('失败') || message.includes('错误') ? 'form-error' : 'test-result'} role="status">{message}</p>}

        {preview?.compiled && (
          <div className="preview" style={{ marginTop: '12px' }}>
            <dl>
              <dt>判定动作</dt>
              <dd><StatusPill status={preview.compiled.effect} /></dd>
              <dt>结构化条件</dt>
              <dd><pre>{JSON.stringify(preview.compiled.conditions, null, 2)}</pre></dd>
            </dl>
            <div className="rule-test">
              <h3>Shadow 命中测试</h3>
              <div className="target-form">
                <label>测试出站内容<textarea rows={2} value={testText} onChange={event => setTestText(event.target.value)} /></label>
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
          <b style={{ fontSize: '13px', display: 'block', marginBottom: '8px' }}>已生效的出站策略列表（{policies.length} 条）</b>
          {policies.map(policy => (
            <article key={policy.id} style={{ display: 'grid', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <b>{policy.name}</b>
                    <StatusPill status={policy.effect} />
                    <span style={{ fontSize: '11px', color: policy.enabled ? 'var(--safe)' : 'var(--muted)' }}>{policy.enabled ? '● 已启用' : '○ 已禁用'}</span>
                  </div>
                  <span>{policy.original_text}</span>
                  <code>版本: v{policy.version} · 更新于 {formatTime(policy.updated_at)}</code>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <button className="icon-button" onClick={() => setExpandedPolicyId(expandedPolicyId === policy.id ? null : policy.id)}>
                    {expandedPolicyId === policy.id ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                  </button>
                  <button className={policy.enabled ? 'toggle on' : 'toggle'} role="switch" aria-checked={policy.enabled} disabled={busy === policy.id} onClick={() => togglePolicy(policy)}><i /></button>
                  <button className="icon-button" disabled={busy === `del-${policy.id}`} onClick={() => deletePolicy(policy.id)}><Trash2 size={15} /></button>
                </div>
              </div>
              {expandedPolicyId === policy.id && <pre style={{ margin: '4px 0 0', padding: '8px', background: '#0b111d', borderRadius: '6px', fontSize: '11px', color: '#aebbd2', overflow: 'auto' }}>{JSON.stringify(policy.conditions, null, 2)}</pre>}
            </article>
          ))}
          {!policies.length && <Empty text="暂无自定义出站策略；内置敏感数据外发告警始终兜底生效" />}
        </div>
      </section>

      <section className="panel" style={{ gridColumn: '1 / -1' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px' }}>
          <PanelTitle title="确定性硬检测器矩阵 (Deterministic Detectors Matrix)" subtitle="本地毫秒级正则表达式扫描凭据、PII、源码；支持独立开关与自定义添加" />
          <button className="primary compact" onClick={() => setShowAddDetector(v => !v)}>{showAddDetector ? <X size={15} /> : <Plus size={15} />}{showAddDetector ? '取消添加' : '添加自定义检测器'}</button>
        </div>

        {showAddDetector && (
          <div className="custom-detector-form" style={{ marginTop: '12px', padding: '14px', background: '#0d1527', border: '1px solid var(--accent)', borderRadius: '10px' }}>
            <b style={{ fontSize: '13px', color: '#c7d2ff', display: 'block', marginBottom: '10px' }}>新建自定义正则表达式检测器</b>
            <div className="target-form" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
              <label>检测器名称<input placeholder="例如 内部员工工号" value={customDet.name} onChange={e => setCustomDet({ ...customDet, name: e.target.value })} /></label>
              <label>敏感数据类别
                <select value={customDet.category} onChange={e => setCustomDet({ ...customDet, category: e.target.value as any })}>
                  <option value="credential">🔑 凭据与密钥 (credential)</option>
                  <option value="pii">👤 个人身份隐私 (pii)</option>
                  <option value="source_code">💻 源码与服务配置 (source_code)</option>
                  <option value="admin_keyword">🏷️ 业务敏感关键词 (admin_keyword)</option>
                </select>
              </label>
              <label style={{ gridColumn: '1 / -1' }}>说明描述<input value={customDet.description} onChange={e => setCustomDet({ ...customDet, description: e.target.value })} /></label>
              <label style={{ gridColumn: '1 / -1' }}>正则表达式 (RegEx Pattern)<input className="mono" value={customDet.pattern} onChange={e => setCustomDet({ ...customDet, pattern: e.target.value })} /></label>
            </div>
            <div style={{ marginTop: '8px', padding: '10px', background: '#090d18', borderRadius: '8px', border: '1px solid var(--line)' }}>
              <label style={{ margin: 0 }}>
                <span style={{ fontSize: '11px', color: 'var(--muted)' }}>实时正则测试验证：</span>
                <input style={{ marginTop: '4px' }} placeholder="输入测试文本" value={customTestInput} onChange={e => setCustomTestInput(e.target.value)} />
              </label>
              {regexTestResult && (
                <p style={{ margin: '6px 0 0', fontSize: '11px', color: !regexTestResult.valid ? 'var(--danger)' : regexTestResult.matched ? 'var(--safe)' : 'var(--warn)' }}>
                  {!regexTestResult.valid ? `⚠️ 正则表达式语法错误: ${regexTestResult.error}` : regexTestResult.matched ? '✓ 正则测试通过：成功捕获到敏感内容！' : '○ 未匹配到内容'}
                </p>
              )}
            </div>
            <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
              <button className="primary" disabled={busy === 'add-det' || !customDet.name.trim() || !customDet.pattern.trim()} onClick={saveCustomDetector}><Save size={15} />{busy === 'add-det' ? '保存中…' : '保存并启用检测器'}</button>
              <button className="secondary" onClick={() => setShowAddDetector(false)}>取消</button>
            </div>
          </div>
        )}

        <div className="detector-matrix-grid" style={{ marginTop: '14px' }}>
          {DETECTOR_CATEGORIES.map(cat => {
            const items = detectors.filter(d => d.category === cat.key)
            if (!items.length && cat.key === 'admin_keyword') return null
            return (
              <div key={cat.key} className="detector-category-box">
                <div className="category-header"><b>{cat.label}</b><span>{cat.desc}</span></div>
                <div className="detector-items">
                  {items.map(item => (
                    <div key={item.id} className={`detector-item-card ${item.enabled ? 'enabled' : 'disabled'}`}>
                      <div className="detector-item-info">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                          <b className="detector-name">{item.name}</b>
                          <code>{item.id}</code>
                          <span style={{ fontSize: '10px', color: item.enabled ? 'var(--safe)' : 'var(--muted)', fontWeight: 600 }}>{item.enabled ? '● 已启用' : '○ 已停用'}</span>
                        </div>
                        {item.description && <p className="detector-desc">{item.description}</p>}
                        <code className="detector-pattern" title={item.pattern}>{item.pattern}</code>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                        <button className={item.enabled ? 'toggle on' : 'toggle'} role="switch" disabled={busy === `det-${item.id}`} onClick={() => toggleDetector(item)}><i /></button>
                        <button className="icon-button" disabled={busy === `del-det-${item.id}`} onClick={() => deleteCustomDetector(item.id)}><Trash2 size={14} /></button>
                      </div>
                    </div>
                  ))}
                  {!items.length && <p style={{ fontSize: '12px', color: 'var(--muted)' }}>暂无该类检测器</p>}
                </div>
              </div>
            )
          })}
        </div>
      </section>

      <section className="panel">
        <PanelTitle title="模型目标注册表 (Destinations)" subtitle="用于区分出站目标是「企业内部受信模型 (trusted)」还是「公网第三方模型 (external)」；未匹配目标默认按 external 严格检测" />
        <div className="target-form">
          <label>目标名称<input value={target.name} placeholder="例如 内部自研模型" onChange={event => setTarget(value => ({ ...value, name: event.target.value }))} /></label>
          <label>模型匹配模式<input placeholder="例如 corp-* 或 gpt-4o" value={target.model_pattern} onChange={event => setTarget(value => ({ ...value, model_pattern: event.target.value }))} /></label>
          <label>供应商<input placeholder="例如 Azure / Internal" value={target.provider} onChange={event => setTarget(value => ({ ...value, provider: event.target.value }))} /></label>
          <label>区域<input placeholder="例如 local / cn-north-1" value={target.region} onChange={event => setTarget(value => ({ ...value, region: event.target.value }))} /></label>
          <label>信任级别
            <select value={target.trust} onChange={event => setTarget(value => ({ ...value, trust: event.target.value as 'trusted' | 'external' }))}>
              <option value="trusted">trusted（受信内部模型，可豁免敏感外发）</option>
              <option value="external">external（外部第三方模型，严格执行检测）</option>
            </select>
          </label>
        </div>
        <button className="primary" disabled={!!busy || !target.name.trim()} onClick={saveTarget}><Database size={17} />{busy === 'target' ? '保存中…' : '添加模型目标'}</button>

        <div className="rule-list target-list" style={{ marginTop: '14px' }}>
          {targets.map(item => (
            <article key={item.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
              <div>
                <b>{item.name}</b>
                <span>模式: <code>{item.model_pattern || '*'}</code> · {item.provider || '未填'} · {item.region || '未填'}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button className="secondary compact" title="点击切换信任级别" disabled={busy === `trust-${item.id}`} onClick={() => toggleTargetTrust(item)}><StatusPill status={item.trust} /></button>
                <button className="icon-button" aria-label="移除目标" title="移除目标" disabled={busy === `del-target-${item.id}`} onClick={() => deleteTarget(item.id)}><Trash2 size={15} /></button>
              </div>
            </article>
          ))}
          {!targets.length && <Empty text="尚未注册受信模型；当前所有模型均视为 external" />}
        </div>

        <details className="legacy-rules" style={{ marginTop: '16px' }}>
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
