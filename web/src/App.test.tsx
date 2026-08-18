// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { App } from './App'

class EventSourceMock { onopen = null; onerror = null; addEventListener(){} close(){} }
vi.stubGlobal('EventSource', EventSourceMock)

const compiled = {
  name: '禁止发布', original_text: '任何 git push 都告警', scope: { protocols: ['*'], models: [], tools: [] },
  conditions: { capabilities: ['publish'], target_environment: [], target_contains: [] },
  effect: 'always_alert', priority: 100, reason_code: 'PUBLISH_ALWAYS_ALERT', reason: '发布动作需要告警',
}

beforeEach(() => {
  window.history.replaceState(null, '', '/')
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
    const path = String(input)
    let value: unknown = { data: [] }
    if (path === '/api/dashboard') value = { trace_count: 0, session_count: 0, open_alert_count: 0, alert_rate: 0, decisions: {}, stage_counts: {}, top_reasons: [], classification_latency_ms: {}, health: {} }
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
