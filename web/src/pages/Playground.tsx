import { useState } from 'react'
import { Beaker, Sparkles } from 'lucide-react'
import type { Json } from '../types'
import { post } from '../api'
import { PanelTitle } from '../components/ui'
import { ReviewContext } from '../components/Waterfall'

const PRESETS = [
  {
    name: '凭据外发 External (告警)',
    model: 'unregistered-external',
    protocol: 'openai_chat_completions',
    message: '帮我分析连接配置：export DATABASE_URL="postgres://admin:hunter2@db.corp.net:5432/main"',
    userId: 'user_dev_01',
    dept: 'Engineering',
  },
  {
    name: 'PII 发往 Trusted 内部模型',
    model: 'corp-internal-model',
    protocol: 'openai_chat_completions',
    message: '分析用户注册信息：姓名 张三，身份证号 110101199003072345，手机号 13800138000',
    userId: 'user_hr_02',
    dept: 'HumanResources',
  },
  {
    name: '常规无害开发提问 (放行)',
    model: 'gpt-4o',
    protocol: 'openai_chat_completions',
    message: '请解释 Python aiohttp 中 ClientSession 的最佳实践与连接池复用方法。',
    userId: 'user_dev_01',
    dept: 'Engineering',
  },
]

export function Playground() {
  const [protocol, setProtocol] = useState('openai_chat_completions')
  const [targetModel, setTargetModel] = useState('unregistered-external')
  const [userId, setUserId] = useState('user_test_01')
  const [department, setDepartment] = useState('Security')
  const [inputMode, setInputMode] = useState<'form' | 'raw'>('form')
  const [pipelineStage, setPipelineStage] = useState<'full' | 'rules'>('full')
  const [message, setMessage] = useState('请检查 password=hunter2 是否出现在配置中。')
  const [raw, setRaw] = useState('{\n  "model": "unregistered-external",\n  "messages": [{"role": "user", "content": "password=hunter2"}]\n}')
  const [result, setResult] = useState<Json | null>(null)
  const [error, setError] = useState('')
  const [running, setRunning] = useState(false)

  function formPayload(): Json {
    const model = targetModel.trim() || 'unregistered-external'
    if (protocol === 'anthropic_messages') return { model, messages: [{ role: 'user', content: message }] }
    if (protocol === 'openai_responses') return { model, input: [{ type: 'message', role: 'user', content: message }] }
    return { model, messages: [{ role: 'user', content: message }] }
  }

  function applyPreset(preset: typeof PRESETS[0]) {
    setProtocol(preset.protocol)
    setTargetModel(preset.model)
    setMessage(preset.message)
    setUserId(preset.userId)
    setDepartment(preset.dept)
    setRaw(JSON.stringify({ model: preset.model, messages: [{ role: 'user', content: preset.message }] }, null, 2))
  }

  async function run() {
    setError(''); setRunning(true)
    try {
      const payload = inputMode === 'raw' ? JSON.parse(raw) : formPayload()
      setResult(await post('/api/playground/classify', { protocol, payload, stage: pipelineStage }))
    } catch (err) { setError((err as Error).message) } finally { setRunning(false) }
  }

  return (
    <div className="playground">
      <section className="panel">
        <PanelTitle title="构造出站请求" subtitle="仅运行 Shadow DLP，不执行工具、不转发给目标模型" />

        <div style={{ marginBottom: '14px' }}>
          <span style={{ fontSize: '11px', color: 'var(--muted)', display: 'block', marginBottom: '6px' }}>
            <Sparkles size={13} style={{ display: 'inline', verticalAlign: '-2px', marginRight: '4px' }} />
            预设场景模板：
          </span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {PRESETS.map((p, idx) => (
              <button key={idx} className="secondary compact" onClick={() => applyPreset(p)}>
                {p.name}
              </button>
            ))}
          </div>
        </div>

        <div className="segmented">
          <button className={inputMode === 'form' ? 'active' : ''} onClick={() => setInputMode('form')}>表单</button>
          <button className={inputMode === 'raw' ? 'active' : ''} onClick={() => setInputMode('raw')}>原始 JSON</button>
        </div>

        {inputMode === 'form' ? (
          <>
            <div className="target-form" style={{ marginTop: '12px' }}>
              <label>协议
                <select value={protocol} onChange={event => setProtocol(event.target.value)}>
                  <option value="anthropic_messages">Anthropic Messages</option>
                  <option value="openai_chat_completions">OpenAI Chat Completions</option>
                  <option value="openai_responses">OpenAI Responses</option>
                </select>
              </label>
              <label>目标模型
                <input value={targetModel} placeholder="例如 unregistered-external 或 corp-*" onChange={event => setTargetModel(event.target.value)} />
              </label>
              <label>模拟用户 ID
                <input value={userId} placeholder="例如 user_dev_01" onChange={event => setUserId(event.target.value)} />
              </label>
              <label>模拟部门
                <input value={department} placeholder="例如 Engineering" onChange={event => setDepartment(event.target.value)} />
              </label>
            </div>
            <label>用户输入内容
              <textarea rows={4} value={message} onChange={event => setMessage(event.target.value)} />
            </label>
          </>
        ) : (
          <label style={{ marginTop: '12px' }}>请求 JSON
            <textarea className="mono" rows={12} value={raw} onChange={event => setRaw(event.target.value)} />
          </label>
        )}

        <label>检测范围
          <select value={pipelineStage} onChange={event => setPipelineStage(event.target.value as 'full' | 'rules')}>
            <option value="full">完整出站请求与策略</option>
            <option value="rules">仅本地确定性检测</option>
          </select>
        </label>

        <button className="primary" disabled={running} onClick={run}>
          <Beaker size={17} />{running ? '审查中…' : '运行 Shadow DLP 审查'}
        </button>
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>

      <section className="panel">
        <PanelTitle title="审查判定结果" subtitle="就地刷新，包含敏感数据、目标信任与策略结论" />
        {result ? <ResultView result={result} /> : <div className="empty"><p>运行后在此查看结果</p></div>}
      </section>
    </div>
  )
}

function ResultView({ result }: { result: Json }) {
  const decision = result.final_decision || result.decision || 'unknown'
  const stages = result.stages || []
  return (
    <div className="result-view">
      <div className={`verdict-banner ${decision}`}>
        <b>{decision}</b>
        <span>{result.final_stage} · {result.reason_code}</span>
      </div>
      <div className="result-row"><span>风险等级</span><b>{result.risk}</b></div>
      <div className="result-row"><span>人的用途</span><b>{result.request_purpose || '—'}</b></div>
      <div className="result-row"><span>敏感数据发现</span><b>{result.data_findings?.length || 0} 个</b></div>
      <div className="result-row"><span>目标模型信任</span><b>{result.destination_trust || '—'}</b></div>
      <div className="result-row"><span>DLP 策略结论</span><strong className={`decision-badge ${result.policy_decision || decision}`}>{result.policy_decision || decision}</strong></div>
      <div className="result-row"><span>原因说明</span><b>{result.reason || result.summary || '—'}</b></div>

      {result.data_findings?.length > 0 && (
        <div style={{ padding: '8px 10px', background: '#1c1512', border: '1px solid #7b5c2e', borderRadius: '8px', marginTop: '6px' }}>
          <b style={{ fontSize: '11px', color: '#f1c879' }}>检出敏感字段：</b>
          {result.data_findings.map((f: Json, idx: number) => (
            <div key={idx} style={{ fontSize: '11.5px', marginTop: '4px', color: '#e8dbc2' }}>
              <code>{f.category}</code> {f.path} · {f.detector}
              {f.snippet && <small style={{ display: 'block', color: '#f1c879' }}>样例: {f.snippet}</small>}
            </div>
          ))}
        </div>
      )}

      {stages.length > 0 && (
        <div className="result-stages" style={{ marginTop: '8px' }}>
          {stages.map((stage: Json, index: number) => (
            <div className="result-stage" key={index}>
              <b>{stage.stage}</b>
              <span>{stage.verdict}</span>
              <code>{stage.reason_code}</code>
            </div>
          ))}
        </div>
      )}
      {result.review_transcript?.length > 0 && (
        <details style={{ marginTop: '8px' }}><summary>审查上下文</summary><ReviewContext transcript={result.review_transcript} /></details>
      )}
      <details style={{ marginTop: '8px' }}><summary>原始结果 JSON</summary><pre className="raw-json">{JSON.stringify(result, null, 2)}</pre></details>
    </div>
  )
}
