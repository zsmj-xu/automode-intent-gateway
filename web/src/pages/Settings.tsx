import { useEffect, useState } from 'react'
import { CircleCheck, Save } from 'lucide-react'
import type { Json } from '../types'
import { useLoad } from '../lib/hooks'
import { patch, post } from '../api'
import { ErrorState, Loading, PanelTitle } from '../components/ui'

export function SettingsPage() {
  const { data, error } = useLoad<Json>('/api/settings')
  const [testing, setTesting] = useState('')
  const [result, setResult] = useState('')
  const [draft, setDraft] = useState<Json>({})
  const [saving, setSaving] = useState(false)
  useEffect(() => { if (data) setDraft({ fast_url: data.fast_url || '', fast_model: data.fast_model || '', deep_url: data.deep_url || '', deep_model: data.deep_model || '', fast_api_key: '', deep_api_key: '' }) }, [data])
  async function test(stage: 'fast' | 'deep') { setTesting(stage); try { const value = await post<Json>(`/api/settings/test-${stage}-model`, {}); setResult(`${stage}: ${value.result.status} / ${value.result.model || '未配置模型'}`) } catch (err) { setResult(`${stage}: ${(err as Error).message}`) } finally { setTesting('') } }
  async function saveSettings() { setSaving(true); setResult(''); try { const payload = Object.fromEntries(Object.entries(draft).filter(([key, value]) => value !== '' || !key.endsWith('_api_key'))); await patch('/api/settings', payload); setDraft(current => ({ ...current, fast_api_key: '', deep_api_key: '' })); setResult('配置已应用。API Key 只保存在当前进程环境中。') } catch (err) { setResult(`保存失败：${(err as Error).message}`) } finally { setSaving(false) } }
  if (error) return <ErrorState message={error} />
  if (!data) return <Loading />
  return (
    <div className="settings-grid">
      <section className="panel">
        <PanelTitle title="运行模式" subtitle="Shadow DLP 默认观察，不阻断目标模型调用" />
        <div className="setting-row"><div><b>Shadow / Observe</b><span>扫描完整出站请求、记录并告警</span></div><span className="mode-badge">当前模式</span></div>
        <div className="setting-row disabled"><div><b>Request Enforce</b><span>预留的模型调用前阻断模式</span></div><span>暂未开放</span></div>
      </section>
      <section className="panel model-settings">
        <PanelTitle title="可选语义模型" subtitle="只处理强脱敏后的模糊上下文，不能推翻确定性 DLP 告警" />
        {(['fast', 'deep'] as const).map(stage => (
          <fieldset key={stage}>
            <legend>{stage === 'fast' ? 'Fast LLM' : 'Deep LLM'}</legend>
            <label>API URL<input value={draft[`${stage}_url`] || ''} placeholder="https://provider.example/v1/chat/completions" onChange={event => setDraft({ ...draft, [`${stage}_url`]: event.target.value })} /></label>
            <label>模型名称<input value={draft[`${stage}_model`] || ''} placeholder="精确模型 ID，不要带末尾引号或空格" onChange={event => setDraft({ ...draft, [`${stage}_model`]: event.target.value })} /></label>
            <label>API Key<input type="password" autoComplete="new-password" value={draft[`${stage}_api_key`] || ''} placeholder={data[`${stage}_api_key_masked`] || '留空则不修改'} onChange={event => setDraft({ ...draft, [`${stage}_api_key`]: event.target.value })} /></label>
            <button className="secondary" disabled={!!testing || saving} onClick={() => test(stage)}>{testing === stage ? '测试中…' : '测试连接'}</button>
          </fieldset>
        ))}
        <button className="primary" disabled={saving || !!testing} onClick={saveSettings}><Save size={16} />{saving ? '保存中…' : '应用模型配置'}</button>
        {result && <p className={result.startsWith('保存失败') ? 'form-error' : 'test-result'} role="status">{result}</p>}
      </section>
      <section className="panel">
        <PanelTitle title="数据与信任边界" subtitle="普通 Trace 只保留脱敏副本" />
        <div className="setting-row"><div><b>脱敏 Trace</b><span>{data.store_raw ? '保存脱敏请求和响应元数据' : '当前不保存请求副本'}</span></div><CircleCheck size={20} /></div>
        <div className="setting-row"><div><b>加密原文证据</b><span>{data.evidence_encryption_configured ? 'AES-GCM 已配置，保留 30 天' : '未配置密钥，不保存原文证据'}</span></div></div>
        <div className="setting-row"><div><b>可信代理网段</b><span>{data.trusted_proxy_cidrs_configured ? '已配置' : '未配置，身份头全部视为不可信'}</span></div></div>
      </section>
    </div>
  )
}
