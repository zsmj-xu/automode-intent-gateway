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
const dlpCompiled = {
  name: '敏感数据外发', original_text: '凭据或源码发往外部模型时告警', effect: 'alert', priority: 100,
  conditions: { data_categories: ['credential', 'source_code'], destination_trust: ['external'], departments: [], roles: [], agent_ids: [], models: [], keywords: [] },
  reason_code: 'CUSTOM_DLP_ALERT', reason: '敏感数据外发',
}

const dashboardPayload = { trace_count: 0, session_count: 0, open_alert_count: 0, alert_rate: 0, decisions: {}, stage_counts: {}, top_reasons: [], classification_latency_ms: {}, health: {} }

beforeEach(() => {
  window.history.replaceState(null, '', '/')
  localStorage.clear()
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
    const path = String(input)
    let value: unknown = { data: [] }
    if (path === '/api/dashboard') value = dashboardPayload
    if (path.startsWith('/api/dlp-policies/compile')) value = { valid: true, compiled: dlpCompiled }
    if (path.startsWith('/api/dlp-policies/test')) value = { policy_decision: 'alert', data_findings: [{ category: 'credential' }] }
    if (path === '/api/dlp-policies') value = { id: 'p1', ...dlpCompiled, enabled: false, version: 1 }
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
  expect(await screen.findByText('出站请求')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '打开导航' }))
  expect(container.querySelector('.sidebar')).toHaveClass('open')
  fireEvent.keyDown(window, { key: 'Escape' })
  expect(container.querySelector('.sidebar')).not.toHaveClass('open')
})

test('completes outbound DLP policy preview, test and save flow', async () => {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '策略' }))
  await screen.findByText('出站数据策略')
  fireEvent.click(screen.getByRole('button', { name: '编译预览' }))
  expect(await screen.findByText('结构化条件')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '测试' }))
  expect(await screen.findByText(/alert · 1 个敏感发现/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
  expect(await screen.findByText(/策略已保存/)).toBeInTheDocument()
  await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/dlp-policies', expect.objectContaining({ method: 'POST' })))
})

test('playground exposes all protocols, raw mode and local DLP mode', async () => {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '测试实验室' }))
  await screen.findByText('构造出站请求')
  const protocol = screen.getByLabelText('协议')
  expect(protocol).toHaveTextContent('Anthropic Messages')
  expect(protocol).toHaveTextContent('OpenAI Chat Completions')
  expect(protocol).toHaveTextContent('OpenAI Responses')
  fireEvent.click(screen.getByRole('button', { name: '原始 JSON' }))
  expect(screen.getByLabelText('请求 JSON')).toBeInTheDocument()
  expect(screen.getByLabelText('检测范围')).toHaveTextContent('本地确定性检测')
  expect(screen.getByText(/不执行工具/)).toBeInTheDocument()
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
  expect(await screen.findByText('出站请求审计')).toBeInTheDocument()
  expect(await screen.findByText('审查上下文（分类器实际看到的内容）')).toBeInTheDocument()
  expect(await screen.findByText('模型动作旁证')).toBeInTheDocument()
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
  expect(await screen.findByText('出站请求')).toBeInTheDocument()
  expect(localStorage.getItem('automode.adminToken')).toBe('secret-token')
})

test('events page lists ingress events and handles retry for failed events', async () => {
  const eventItem = {
    event_id: 'evt-123',
    source_id: 'src-proxy',
    session_id: 'sess-1',
    is_historical: false,
    processing_status: 'failed',
    association_status: 'request_missing',
    retry_count: 2,
    failure_reason: 'LLM reviewer timeout',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    event_summary: 'POST /v1/messages with 2 tools',
    tasks: [
      { task_id: 't-1', stage: 'rule', status: 'completed' },
      { task_id: 't-2', stage: 'reviewer', status: 'failed', failure_reason: 'LLM reviewer timeout' },
    ],
    alerts: [],
  }
  const sourceItem = {
    id: 'src-proxy',
    name: 'Proxy Gateway',
    token: 'tok-123',
    enabled: true,
    allow_trusted_identity: true,
    rate_limit_per_minute: 60,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  }

  const fetchMock = vi.fn(async (input: string | URL | Request) => {
    const path = String(input)
    if (path === '/api/dashboard') return jsonOk(dashboardPayload)
    if (path.startsWith('/api/events/evt-123/retry')) return jsonOk({ event_id: 'evt-123', status: 'pending' })
    if (path.startsWith('/api/events/evt-123')) return jsonOk(eventItem)
    if (path.startsWith('/api/events?')) return jsonOk({ data: [eventItem], total: 1 })
    if (path === '/api/sources') return jsonOk({ data: [sourceItem] })
    if (path === '/api/events') return sseStub()
    return jsonOk({ data: [] })
  })
  vi.stubGlobal('fetch', fetchMock)

  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '事件' }))
  expect(await screen.findByText('标准事件中心')).toBeInTheDocument()
  expect(await screen.findByText(/evt-123/)).toBeInTheDocument()
  expect(screen.getByText(/缺失对应请求/)).toBeInTheDocument()
  expect(screen.getByText('failed')).toBeInTheDocument()

  // Click retry
  const retryBtn = screen.getByTitle('重试此事件')
  fireEvent.click(retryBtn)
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/events/evt-123/retry', expect.objectContaining({ method: 'POST' })))

  // Switch to sources tab
  fireEvent.click(screen.getByRole('button', { name: /来源与授权/ }))
  expect(await screen.findByText('Proxy Gateway')).toBeInTheDocument()
  expect(screen.getByText('src-proxy')).toBeInTheDocument()
})

test('alerts page supports dual channel filter and displays dual badge and divergence', async () => {
  const dualAlert = {
    id: 'a-dual',
    trace_id: 't1',
    created_at: '',
    severity: 'high',
    status: 'open',
    channel_source: 'dual',
    divergence: true,
    review_status: 'needs_review',
    title: 'HIGH: Data Exfiltration',
    reason: '规则检测到私钥，LLM判定为安全操作',
    matched_rules: [{ name: 'RSA Private Key' }],
    data_findings: [{ category: 'credential' }],
    llm_analysis: { risk: 'low', reasoning: 'Mock analysis' },
    evidence: ['BEGIN RSA PRIVATE KEY'],
    actions: [],
    final_stage: 'rules',
  }

  const fetchMock = vi.fn(async (input: string | URL | Request) => {
    const path = String(input)
    if (path === '/api/dashboard') return jsonOk(dashboardPayload)
    if (path.startsWith('/api/alerts')) return jsonOk({ data: [dualAlert] })
    if (path === '/api/events') return sseStub()
    return jsonOk({ data: [] })
  })
  vi.stubGlobal('fetch', fetchMock)

  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '告警' }))
  expect(await screen.findByText('告警中心')).toBeInTheDocument()
  expect(screen.getAllByText(/Dual/).length).toBeGreaterThan(0)
  expect(screen.getAllByText(/结论分歧/).length).toBeGreaterThan(0)

  // Click filter for dual
  fireEvent.click(screen.getByRole('button', { name: /双命中 \[Dual\]/ }))
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('channel_source=dual'), expect.anything()))
})

test('failed review remains visibly unresolved and can be filtered independently of rule hits', async () => {
  const failedAlert = {
    id: 'a-failed', trace_id: 't1', created_at: '', severity: 'critical', status: 'open',
    title: 'Synthetic credential alert', reason_code: 'CREDENTIAL', reason: 'Synthetic rule hit',
    rule_severity: 'critical', llm_severity: null, llm_status: 'failed', review_status: 'failed',
    channel_source: 'rule', evidence: [], actions: [], final_stage: 'rules',
  }
  const fetchMock = vi.fn(async (input: string | URL | Request) => {
    const path = String(input)
    if (path === '/api/dashboard') return jsonOk(dashboardPayload)
    if (path.startsWith('/api/alerts')) return jsonOk({ data: [failedAlert] })
    if (path === '/api/events') return sseStub()
    return jsonOk({ data: [] })
  })
  vi.stubGlobal('fetch', fetchMock)
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '告警' }))
  expect(await screen.findByText('分析失败，不能判断为无风险')).toBeInTheDocument()
  expect(screen.queryByText('LLM 未告警')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '分析失败' }))
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('review_status=failed'), expect.anything()))
  fireEvent.click(screen.getByRole('button', { name: '规则命中（含双命中）' }))
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('hit_source=rule_hit'), expect.anything()))
})
