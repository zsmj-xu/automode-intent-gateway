import { useState } from 'react'
import { AlertTriangle, Beaker, History, RotateCcw, Save, SlidersHorizontal, X } from 'lucide-react'
import type { Json, Rule } from '../types'
import { useLoad } from '../lib/hooks'
import { formatTime, friendlyError } from '../lib/format'
import { api, post } from '../api'
import { Empty, PanelTitle } from '../components/ui'

export function Rules({ refresh }: { refresh: number }) {
  const { data } = useLoad<{ data: Rule[] }>('/api/rules', refresh)
  const [text, setText] = useState('用户明确说不要 push 时，任何 git push 都告警。')
  const [preview, setPreview] = useState<Json | null>(null)
  const [error, setError] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [testUser, setTestUser] = useState('检查代码，但不要 push。')
  const [testTool, setTestTool] = useState('Bash')
  const [testArgs, setTestArgs] = useState('{"command":"git push origin main"}')
  const [testResult, setTestResult] = useState<Json | null>(null)
  const [busy, setBusy] = useState('')
  const [status, setStatus] = useState('')
  const [history, setHistory] = useState<{ rule: Rule; versions: Json[] } | null>(null)
  const [localRefresh, setLocalRefresh] = useState(0)
  const rows = useLoad<{ data: Rule[] }>(`/api/rules?v=${refresh + localRefresh}`, refresh + localRefresh).data?.data || data?.data || []

  async function compile() { setError(''); setStatus(''); setBusy('compile'); try { setPreview(await post('/api/rules/compile', { text })); setTestResult(null) } catch (err) { setError(friendlyError(err)) } finally { setBusy('') } }
  async function testPreview() { if (!preview) return; setError(''); setBusy('test'); try { setTestResult(await post('/api/rules/test', { rule: preview.compiled, user_message: testUser, proposed_tool_calls: [{ name: testTool, arguments: JSON.parse(testArgs) }] })) } catch (err) { setError(friendlyError(err)) } finally { setBusy('') } }
  async function save() { if (!preview) return; setBusy('save'); try { await post('/api/rules', { compiled: preview.compiled, confirmed }); setPreview(null); setConfirmed(false); setTestResult(null); setStatus('规则已保存，默认禁用；可在右侧启用。'); setLocalRefresh(v => v + 1) } catch (err) { setError(friendlyError(err)) } finally { setBusy('') } }
  async function toggle(row: Rule) { setBusy(row.id); try { await post(`/api/rules/${row.id}/${row.enabled ? 'disable' : 'enable'}`, {}); setStatus(`规则已${row.enabled ? '禁用' : '启用'}`); setLocalRefresh(v => v + 1) } finally { setBusy('') } }
  async function showHistory(row: Rule) { setBusy(`history-${row.id}`); try { const value = await api<{ data: Json[] }>(`/api/rules/${row.id}/versions`); setHistory({ rule: row, versions: value.data }) } finally { setBusy('') } }
  async function rollback(row: Rule, version: number) { setBusy(`rollback-${version}`); try { await post(`/api/rules/${row.id}/rollback`, { version }); setStatus(`已从 v${version} 创建新的回滚版本`); setHistory(null); setLocalRefresh(v => v + 1) } catch (err) { setError((err as Error).message) } finally { setBusy('') } }

  return (
    <div className="rules-layout">
      <section className="panel">
        <PanelTitle title="自然语言规则" subtitle="编译 → 预览 → 测试 → 保存，新规则默认禁用" />
        <label>规则描述<textarea value={text} onChange={event => setText(event.target.value)} rows={5} /></label>
        <button className="primary" disabled={!!busy} onClick={compile}><SlidersHorizontal size={17} />{busy === 'compile' ? '编译中…' : '编译预览'}</button>
        {error && <p className="form-error" role="alert">{error}</p>}
        {preview && (
          <div className="preview">
            <div className="notice"><AlertTriangle size={18} /><span>结构化规则只包含受限字段，不执行自然语言中的代码。</span></div>
            <dl><dt>原始规则</dt><dd>{text}</dd><dt>结构化规则</dt><dd><pre>{JSON.stringify(preview.compiled, null, 2)}</pre></dd></dl>
            <div className="rule-test">
              <h3>命中测试</h3>
              <label>用户输入<input value={testUser} onChange={event => setTestUser(event.target.value)} /></label>
              <label>工具名称<input value={testTool} onChange={event => setTestTool(event.target.value)} /></label>
              <label>工具参数 JSON<textarea className="mono" rows={3} value={testArgs} onChange={event => setTestArgs(event.target.value)} /></label>
              <button className="secondary" disabled={!!busy} onClick={testPreview}><Beaker size={16} />{busy === 'test' ? '测试中…' : '测试规则'}</button>
              {testResult && <p className={testResult.matched ? 'hit-result matched' : 'hit-result'} role="status">{testResult.matched ? '已命中' : '未命中'} · {testResult.stage.reason_code} · 不会执行工具</p>}
            </div>
            {preview.requires_confirmation && <label className="check"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />我确认此规则会对所有命中动作直接告警</label>}
            <button className="primary" disabled={!!busy || (preview.requires_confirmation && !confirmed)} onClick={save}><Save size={17} />{busy === 'save' ? '保存中…' : '保存规则'}</button>
          </div>
        )}
      </section>
      <section className="panel">
        <PanelTitle title="已保存规则" subtitle={`${rows.length} 条，可启用、禁用或按版本回滚`} />
        {status && <p className="test-result" role="status">{status}</p>}
        {rows.length ? (
          <div className="rule-list">
            {rows.map(row => (
              <article key={row.id}>
                <div>
                  <b>{row.name}</b>
                  <span>{row.original_text}</span>
                  <code>{row.reason_code} · v{row.version}</code>
                  <div className="inline-actions"><button className="text-button" onClick={() => showHistory(row)} disabled={!!busy}><History size={14} />版本</button></div>
                </div>
                <button className={row.enabled ? 'toggle on' : 'toggle'} role="switch" aria-label={`${row.enabled ? '禁用' : '启用'} ${row.name}`} aria-checked={row.enabled} disabled={!!busy} onClick={() => toggle(row)}><i /></button>
              </article>
            ))}
          </div>
        ) : <Empty text="暂无规则" />}
        {history && (
          <div className="history-panel">
            <div><b>{history.rule.name} · 版本历史</b><button className="icon-button" aria-label="关闭版本历史" onClick={() => setHistory(null)}><X size={16} /></button></div>
            {history.versions.map(version => (
              <article key={version.version}><span>v{version.version} · {formatTime(version.created_at)}</span><code>{version.reason_code}</code><button className="secondary" disabled={version.version === history.rule.version || !!busy} onClick={() => rollback(history.rule, version.version)}><RotateCcw size={14} />回滚到此版</button></article>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
