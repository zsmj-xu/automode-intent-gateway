import { useState } from 'react'
import { Beaker } from 'lucide-react'
import type { Json } from '../types'
import { post } from '../api'
import { PanelTitle } from '../components/ui'
import { ReviewContext } from '../components/Waterfall'

export function Playground() {
  const [protocol, setProtocol] = useState('openai_chat_completions')
  const [inputMode, setInputMode] = useState<'form' | 'raw'>('form')
  const [pipelineStage, setPipelineStage] = useState<'full' | 'rules'>('full')
  const [message, setMessage] = useState('帮我看看为什么部署失败，不要重新部署。')
  const [tool, setTool] = useState('deploy')
  const [args, setArgs] = useState('{"environment":"production","service":"payment-api"}')
  const [historicalTool, setHistoricalTool] = useState('read_logs')
  const [includeHistory, setIncludeHistory] = useState(false)
  const [raw, setRaw] = useState('{\n  "model": "playground",\n  "messages": [{"role": "user", "content": "不要重新部署"}]\n}')
  const [temporaryRule, setTemporaryRule] = useState('')
  const [result, setResult] = useState<Json | null>(null)
  const [error, setError] = useState('')
  const [running, setRunning] = useState(false)

  function formPayload(parsedArgs: Json): Json {
    if (protocol === 'anthropic_messages') return { model: 'playground', messages: [{ role: 'user', content: message }, ...(includeHistory ? [{ role: 'assistant', content: [{ type: 'tool_use', id: 'history-1', name: historicalTool, input: {} }] }] : [])] }
    if (protocol === 'openai_responses') return { model: 'playground', input: [{ type: 'message', role: 'user', content: message }, ...(includeHistory ? [{ type: 'function_call', call_id: 'history-1', name: historicalTool, arguments: '{}' }] : [])] }
    return { model: 'playground', messages: [{ role: 'user', content: message }, ...(includeHistory ? [{ role: 'assistant', tool_calls: [{ id: 'history-1', type: 'function', function: { name: historicalTool, arguments: JSON.stringify(parsedArgs) } }] }] : [])] }
  }

  async function run() {
    setError(''); setRunning(true)
    try {
      const parsedArgs = JSON.parse(args)
      const payload = inputMode === 'raw' ? JSON.parse(raw) : formPayload(parsedArgs)
      let compiled: Json | undefined
      if (temporaryRule.trim()) compiled = (await post<Json>('/api/rules/compile', { text: temporaryRule })).compiled
      setResult(await post('/api/playground/classify', { protocol, payload, proposed_tool_calls: [{ name: tool, arguments: parsedArgs }], temporary_rule: compiled, stage: pipelineStage }))
    } catch (err) { setError((err as Error).message) } finally { setRunning(false) }
  }

  return (
    <div className="playground">
      <section className="panel">
        <PanelTitle title="构造测试" subtitle="仅分类：不会执行真实工具，也不会转发给主 Agent" />
        <div className="segmented">
          <button className={inputMode === 'form' ? 'active' : ''} onClick={() => setInputMode('form')}>表单</button>
          <button className={inputMode === 'raw' ? 'active' : ''} onClick={() => setInputMode('raw')}>原始 JSON</button>
        </div>
        <label>协议
          <select value={protocol} onChange={event => setProtocol(event.target.value)}>
            <option value="anthropic_messages">Anthropic Messages</option>
            <option value="openai_chat_completions">OpenAI Chat Completions</option>
            <option value="openai_responses">OpenAI Responses</option>
          </select>
        </label>
        {inputMode === 'form' ? (
          <>
            <label>用户输入<textarea rows={4} value={message} onChange={event => setMessage(event.target.value)} /></label>
            <label className="check"><input type="checkbox" checked={includeHistory} onChange={event => setIncludeHistory(event.target.checked)} />加入历史工具调用</label>
            {includeHistory && <label>历史工具名称<input value={historicalTool} onChange={event => setHistoricalTool(event.target.value)} /></label>}
          </>
        ) : <label>请求 JSON<textarea className="mono" rows={12} value={raw} onChange={event => setRaw(event.target.value)} /></label>}
        <div className="tool-box">
          <b>当前模型拟调用的工具</b>
          <label>工具名称<input value={tool} onChange={event => setTool(event.target.value)} /></label>
          <label>工具参数 JSON<textarea className="mono" rows={5} value={args} onChange={event => setArgs(event.target.value)} /></label>
        </div>
        <label>临时自然语言规则（可选）<textarea rows={3} placeholder="例如：生产环境部署一律告警。" value={temporaryRule} onChange={event => setTemporaryRule(event.target.value)} /></label>
        <label>判定范围
          <select value={pipelineStage} onChange={event => setPipelineStage(event.target.value as 'full' | 'rules')}>
            <option value="full">完整 Rules → Fast → Deep</option>
            <option value="rules">仅 Rules</option>
          </select>
        </label>
        <button className="primary" disabled={running} onClick={run}><Beaker size={17} />{running ? '分类中…' : '运行分类'}</button>
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>
      <section className="panel">
        <PanelTitle title="分类结果" subtitle="就地刷新，包含判定与审查上下文" />
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
      <div className={`verdict-banner ${decision}`}><b>{decision}</b><span>{result.final_stage} · {result.reason_code}</span></div>
      <div className="result-row"><span>风险</span><b>{result.risk}</b></div>
      <div className="result-row"><span>意图对齐</span><b>{result.action_alignment || '—'}</b></div>
      <div className="result-row"><span>原因</span><b>{result.reason || result.summary || '—'}</b></div>
      {stages.length > 0 && (
        <div className="result-stages">
          {stages.map((stage: Json, index: number) => (
            <div className="result-stage" key={index}><b>{stage.stage}</b><span>{stage.verdict}</span><code>{stage.reason_code}</code></div>
          ))}
        </div>
      )}
      {result.review_transcript?.length > 0 && (
        <details><summary>审查上下文</summary><ReviewContext transcript={result.review_transcript} /></details>
      )}
      <details><summary>原始结果 JSON</summary><pre className="raw-json">{JSON.stringify(result, null, 2)}</pre></details>
    </div>
  )
}
