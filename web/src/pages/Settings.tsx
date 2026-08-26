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
        <PanelTitle title="运行模式" subtitle="MVP 默认观察，不阻断真实工具调用" />
        <div className="setting-row"><div><b>Observe</b><span>记录、分类并生成告警</span></div><span className="mode-badge">当前模式</span></div>
        <div className="setting-row disabled"><div><b>Enforce</b><span>预留的强制阻断模式</span></div><span>暂未开放</span></div>
      </section>
      <section className="panel model-settings">
        <PanelTitle title="分类模型" subtitle="Fast 无思考，Deep 有思考；密钥永不回传或落库" />
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
        <PanelTitle title="数据保留" subtitle="原始请求可关闭，结构化审计数据继续保留" />
        <div className="setting-row"><div><b>原始请求</b><span>{data.store_raw ? '当前已保存（敏感字段脱敏）' : '当前不保存'}</span></div><CircleCheck size={20} /></div>
        <div className="setting-row"><div><b>保留期限</b><span>{data.retention_days} 天</span></div></div>
      </section>
    </div>
  )
}
