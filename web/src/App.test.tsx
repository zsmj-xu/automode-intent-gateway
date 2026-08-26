// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { App } from './App'

const compiled = {
  name: '禁止发布', original_text: '任何 git push 都告警', scope: { protocols: ['*'], models: [], tools: [] },
  conditions: { capabilities: ['publish'], target_environment: [], target_contains: [] },
  effect: 'always_alert', priority: 100, reason_code: 'PUBLISH_ALWAYS_ALERT', reason: '发布动作需要告警',
}

const dashboardPayload = { trace_count: 0, session_count: 0, open_alert_count: 0, alert_rate: 0, decisions: {}, stage_counts: {}, top_reasons: [], classification_latency_ms: {}, health: {} }

beforeEach(() => {
  window.history.replaceState(null, '', '/')
  localStorage.clear()
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
    const path = String(input)
    let value: unknown = { data: [] }
    if (path === '/api/dashboard') value = dashboardPayload
    if (path === '/api/rules/compile') value = { valid: true, requires_confirmation: true, compiled }
    if (path === '/api/rules/test') value = { matched: true, stage: { reason_code: 'PUBLISH_ALWAYS_ALERT' } }
    if (path === '/api/rules') value = { id: 'r1', ...compiled, enabled: false, version: 1 }
    return { ok: true, status: 200, json: async () => value, text: async () => '' }
  }))
})
afterEach(cleanup)

test('renders accessible navigation and closes its drawer with Escape', async () => {
  const { container } = render(<App />)
  expect(screen.getByRole('navigation', { name: '主导航' })).toBeInTheDocument()
  expect(await screen.findByText('模型调用')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '打开导航' }))
  expect(container.querySelector('.sidebar')).toHaveClass('open')
  fireEvent.keyDown(window, { key: 'Escape' })
  expect(container.querySelector('.sidebar')).not.toHaveClass('open')
})

test('completes natural-language rule preview, test, confirm and save flow', async () => {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '规则' }))
  await screen.findByText('自然语言规则')
  fireEvent.click(screen.getByRole('button', { name: '编译预览' }))
  expect(await screen.findByText('结构化规则')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '测试规则' }))
  expect(await screen.findByText(/已命中/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('checkbox', { name: /我确认/ }))
  fireEvent.click(screen.getByRole('button', { name: '保存规则' }))
  expect(await screen.findByText(/规则已保存/)).toBeInTheDocument()
  await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/rules', expect.objectContaining({ method: 'POST' })))
})

test('playground exposes all protocols, raw mode, history and rules-only mode', async () => {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '测试实验室' }))
  await screen.findByText('构造测试')
  const protocol = screen.getByLabelText('协议')
  expect(protocol).toHaveTextContent('Anthropic Messages')
  expect(protocol).toHaveTextContent('OpenAI Chat Completions')
  expect(protocol).toHaveTextContent('OpenAI Responses')
  fireEvent.click(screen.getByRole('button', { name: '原始 JSON' }))
  expect(screen.getByLabelText('请求 JSON')).toBeInTheDocument()
  expect(screen.getByLabelText('判定范围')).toHaveTextContent('仅 Rules')
  expect(screen.getByText(/不会执行真实工具/)).toBeInTheDocument()
})

const jsonOk = (value: unknown) => ({ ok: true, status: 200, json: async () => value, text: async () => '' })
const sseStub = () => ({ ok: true, status: 200, json: async () => ({}), text: async () => '' })

test('sessions page renders the audit timeline with full decision report and review context', async () => {
  const session = { id: 's1', external_session_id: 'ctx-1', client_type: 'claude_code', models: ['m'], call_count: 1, max_risk: 'high', protocols: [], tool_call_count: 1, allow_count: 0, alert_count: 1, created_at: '', last_seen_at: '' }
  const detail = {
    session,
    traces: [{
      trace_id: 't1', created_at: '', model: 'm', protocol: 'openai_chat_completions', method: 'POST', path: '/v1',
      latest_user_text: '不要 push', response_status: 200, latency_ms: 5, response_capture_complete: true, session_evidence: {},
      request_body: {}, response_body: null,
      tool_actions: [{ tool_name: 'Bash', arguments: { command: 'git push' }, capability: 'publish', target: 'git push', side_effect: null, risk: 'high' }],
      classification: { final_decision: 'alert', final_stage: 'rules', risk: 'high', action_alignment: 'contradicted', reason_code: 'USER_CONSTRAINT', reason: '禁止 push', review_transcript: [{ type: 'user', text: '不要 push' }], stages: [{ stage: 'rules', status: 'completed', verdict: 'ALWAYS_ALERT', risk: 'high', reason_code: 'USER_CONSTRAINT', reason: 'x', latency_ms: 1 }] },
      alerts: [{ id: 'a1', trace_id: 't1', classification_run_id: 'r1', session_record_id: 's1', created_at: '', severity: 'high', status: 'open', reason_code: 'USER_CONSTRAINT', title: 'HIGH: Bash', reason: '禁止 push', evidence: ['不要 push'], actions: [{ name: 'Bash' }], matched_rules: [], final_stage: 'rules', acknowledged_at: null, operator_note: '', feedback: null }],
    }],
  }
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
    const path = String(input)
    if (path === '/api/dashboard') return jsonOk({ ...dashboardPayload, trace_count: 1 })
    if (path.startsWith('/api/sessions/') && path.endsWith('/detail')) return jsonOk(detail)
    if (path.startsWith('/api/sessions')) return jsonOk({ data: [session] })
    if (path === '/api/events') return sseStub()
    return jsonOk({ data: [] })
  }))
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '会话' }))
  expect(await screen.findByText('会话审计')).toBeInTheDocument()
  expect(await screen.findByText('审查上下文（分类器实际看到的内容）')).toBeInTheDocument()
  expect(await screen.findByText('拟调用工具')).toBeInTheDocument()
  expect(screen.getAllByText('不要 push').length).toBeGreaterThan(0)
})

test('alerts page submits human feedback for triage', async () => {
  const alert = { id: 'a1', trace_id: 't1', classification_run_id: 'r1', session_record_id: 's1', created_at: '', severity: 'high', status: 'open', reason_code: 'USER_CONSTRAINT', title: 'HIGH: Bash', reason: '禁止 push', evidence: ['不要 push'], actions: [{ name: 'Bash' }], matched_rules: [], final_stage: 'rules', acknowledged_at: null, operator_note: '', feedback: null }
  const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const path = String(input)
    if (path === '/api/dashboard') return jsonOk(dashboardPayload)
    if (path.startsWith('/api/alerts/') && (init?.method === 'POST')) return jsonOk({ ...alert, status: 'false_positive' })
    if (path.startsWith('/api/alerts')) return jsonOk({ data: [alert] })
    if (path === '/api/events') return sseStub()
    return jsonOk({ data: [] })
  })
  vi.stubGlobal('fetch', fetchMock)
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '告警' }))
  expect(await screen.findByText('告警中心')).toBeInTheDocument()
  expect(await screen.findByText('人工反馈')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '误报' }))
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/alerts/a1/feedback', expect.objectContaining({ method: 'POST' })))
})

test('shows the auth gate on 401 and unlocks after entering the admin token', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const path = String(input)
    const headers = (init?.headers || {}) as Record<string, string>
    if (path === '/api/dashboard') {
      if (headers['x-automode-admin-token'] !== 'secret-token') {
        return { ok: false, status: 401, json: async () => ({}), text: async () => 'admin authentication required' }
      }
      return { ok: true, status: 200, json: async () => ({ ...dashboardPayload, trace_count: 1 }), text: async () => '' }
    }
    return { ok: true, status: 200, json: async () => ({ data: [] }), text: async () => '' }
  }))
  render(<App />)
  expect(await screen.findByRole('dialog', { name: '管理端认证' })).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('管理 Token'), { target: { value: 'secret-token' } })
  fireEvent.click(screen.getByRole('button', { name: /保存并连接/ }))
  expect(await screen.findByText('模型调用')).toBeInTheDocument()
  expect(localStorage.getItem('automode.adminToken')).toBe('secret-token')
})
