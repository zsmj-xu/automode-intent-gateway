import { useEffect, useState } from 'react'
import { CircleCheck, RotateCcw, Save } from 'lucide-react'
import type { Json, PromptsResponse } from '../types'
import { useLoad } from '../lib/hooks'
import { patch, post } from '../api'
import { ErrorState, Loading, PanelTitle } from '../components/ui'

const PROMPT_KEY = 'outbound_dlp' as const

export function SettingsPage() {
  const { data, error } = useLoad<Json>('/api/settings')
  const [testing, setTesting] = useState('')
  const [result, setResult] = useState('')
  const [draft, setDraft] = useState<Json>({})
  const [saving, setSaving] = useState(false)

  // Prompts management state
  const [promptRefresh, setPromptRefresh] = useState(0)
  const { data: promptsData } = useLoad<PromptsResponse>(`/api/prompts?v=${promptRefresh}`, promptRefresh)
  const [promptDrafts, setPromptDrafts] = useState<Record<string, string>>({})
  const [promptSaving, setPromptSaving] = useState(false)
  const [promptStatus, setPromptStatus] = useState('')

  useEffect(() => {
    if (data) setDraft({ fast_url: data.fast_url || '', fast_model: data.fast_model || '', deep_url: data.deep_url || '', deep_model: data.deep_model || '', fast_api_key: '', deep_api_key: '' })
  }, [data])

  useEffect(() => {
    if (promptsData?.data) {
      setPromptDrafts(promptsData.data)
    }
  }, [promptsData])

  async function test(stage: 'fast' | 'deep') {
    setTesting(stage)
    try {
      const value = await post<Json>(`/api/settings/test-${stage}-model`, {})
      setResult(`${stage}: ${value.result.status} / ${value.result.model || '未配置模型'}`)
    } catch (err) {
      setResult(`${stage}: ${(err as Error).message}`)
    } finally {
      setTesting('')
    }
  }

  async function saveSettings() {
    setSaving(true)
    setResult('')
    try {
      const payload = Object.fromEntries(Object.entries(draft).filter(([key, value]) => value !== '' || !key.endsWith('_api_key')))
      await patch('/api/settings', payload)
      setDraft(current => ({ ...current, fast_api_key: '', deep_api_key: '' }))
      setResult('配置已应用。API Key 只保存在当前进程环境中。')
    } catch (err) {
      setResult(`保存失败：${(err as Error).message}`)
    } finally {
      setSaving(false)
    }
  }

  async function savePrompt() {
    setPromptSaving(true)
    setPromptStatus('')
    try {
      const currentText = promptDrafts[PROMPT_KEY] || ''
      await patch('/api/prompts', { prompts: { [PROMPT_KEY]: currentText } })
      setPromptStatus('提示词已保存并生效')
      setPromptRefresh(v => v + 1)
    } catch (err) {
      setPromptStatus(`保存失败: ${(err as Error).message}`)
    } finally {
      setPromptSaving(false)
    }
  }

  async function resetPrompt() {
    setPromptSaving(true)
    setPromptStatus('')
    try {
      await post('/api/prompts/reset', { name: PROMPT_KEY })
      setPromptStatus('已恢复至系统默认提示词')
      setPromptRefresh(v => v + 1)
    } catch (err) {
      setPromptStatus(`恢复失败: ${(err as Error).message}`)
    } finally {
      setPromptSaving(false)
    }
  }

  if (error) return <ErrorState message={error} />
  if (!data) return <Loading />

  const currentPromptContent = promptDrafts[PROMPT_KEY] || ''
  const defaultPromptContent = promptsData?.defaults?.[PROMPT_KEY] || ''
  const isCustomized = currentPromptContent !== defaultPromptContent

  return (
    <div className="settings-grid">
      <section className="panel">
        <PanelTitle title="运行模式" subtitle="Shadow DLP 默认观察，不阻断目标模型调用" />
        <div className="setting-row"><div><b>Shadow / Observe</b><span>扫描完整出站请求、记录并告警</span></div><span className="mode-badge">当前模式</span></div>
        <div className="setting-row disabled"><div><b>Request Enforce</b><span>预留的模型调用前阻断模式</span></div><span>暂未开放</span></div>
      </section>

      <section className="panel model-settings">
        <PanelTitle title="可选审查大模型 (LLM Reviewer)" subtitle="只处理强脱敏后的模糊上下文，不能推翻确定性 DLP 告警" />
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

      {/* 审查模型提示词管理 */}
      <section className="panel" style={{ gridColumn: '1 / -1' }}>
        <PanelTitle
          title="审查模型提示词 (System Prompts) 配置"
          subtitle="用于判定模糊的出站数据策略事件；确定性敏感外发告警不会进入该审查。"
        />
        <p style={{ fontSize: '12px', color: 'var(--muted)', margin: '0 0 10px' }}>
          出站数据合规 (DLP)：用于判定模糊或异常敏感数据外发至非完全可信模型时的策略审查。
        </p>

        <label>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>系统提示词 (System Prompt)</span>
            <span style={{ fontSize: '11px', color: isCustomized ? 'var(--warn)' : 'var(--safe)' }}>
              {isCustomized ? '● 已使用自定义提示词' : '✓ 正在使用系统默认提示词'} · {currentPromptContent.length} 字符
            </span>
          </div>
          <textarea
            className="mono"
            rows={10}
            value={currentPromptContent}
            onChange={event => setPromptDrafts({ ...promptDrafts, [PROMPT_KEY]: event.target.value })}
            placeholder="请输入系统提示词..."
          />
        </label>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '10px' }}>
          <button className="primary" disabled={promptSaving} onClick={savePrompt}>
            <Save size={16} />{promptSaving ? '保存中…' : '保存提示词'}
          </button>
          <button className="secondary" disabled={promptSaving || !isCustomized} onClick={resetPrompt}>
            <RotateCcw size={16} />恢复默认
          </button>
        </div>

        {promptStatus && (
          <p className={promptStatus.startsWith('保存失败') || promptStatus.startsWith('恢复失败') ? 'form-error' : 'test-result'} role="status" style={{ marginTop: '8px' }}>
            {promptStatus}
          </p>
        )}
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
