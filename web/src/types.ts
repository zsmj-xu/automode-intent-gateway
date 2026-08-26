export type Json = Record<string, any>

export type Risk = 'low' | 'medium' | 'high' | 'critical'
export type Capability = 'read' | 'write' | 'execute' | 'delete' | 'publish' | 'unknown'
export type Decision = 'allow' | 'alert' | 'unknown'

export interface Session {
  id: string
  external_session_id: string | null
  created_at: string
  last_seen_at: string
  client_type: string | null
  protocols: string[]
  models: string[]
  call_count: number
  tool_call_count: number
  allow_count: number
  alert_count: number
  max_risk: Risk
  conversation_fingerprint?: string | null
  authorization?: Json
}

export interface ReviewEvent {
  type: 'user' | 'tool_call' | 'session_authorization'
  text?: string
  phase?: 'historical' | 'proposed' | 'session'
  name?: string
  arguments?: unknown
  capability?: string
  target?: string | null
  side_effect?: string
  risk?: string
  source?: string
  capabilities?: string[]
  forbidden_capabilities?: string[]
  statements?: string[]
}

export interface StageResult {
  stage: 'rules' | 'fast_llm' | 'deep_llm'
  status: 'completed' | 'error' | 'skipped'
  verdict: string
  risk: Risk
  reason_code: string
  reason: string
  latency_ms: number
  action_alignment?: string
  matched_rule_ids?: string[]
  matched_rule_versions?: string[]
  evidence?: string[]
  model?: string | null
  input_hash?: string | null
  input_tokens?: number | null
  output_tokens?: number | null
  error_code?: string | null
}

export interface Classification {
  id?: string
  trace_id?: string
  legacy?: boolean
  review_transcript: ReviewEvent[]
  final_decision: Decision
  final_stage: string
  risk: Risk
  action_alignment: string
  reason_code: string
  reason: string
  started_at?: string
  completed_at?: string
  total_latency_ms?: number
  stages: StageResult[]
}

export interface ToolAction {
  tool_name: string
  arguments: unknown
  capability: Capability
  target: string | null
  side_effect: string | null
  risk: string
  action_hash?: string
  created_at?: string
}

export interface AlertAction {
  name: string
  arguments?: unknown
  capability?: string
  target?: string | null
  side_effect?: string
  risk?: string
}

export type AlertStatus = 'open' | 'acknowledged' | 'false_positive' | 'resolved'

export interface Alert {
  id: string
  trace_id: string
  classification_run_id: string
  session_record_id: string | null
  created_at: string
  severity: Risk
  status: AlertStatus
  reason_code: string
  title: string
  reason: string
  evidence: string[]
  actions: AlertAction[]
  matched_rules: string[]
  final_stage: string
  acknowledged_at: string | null
  operator_note: string
  feedback: string | null
}

export interface TraceDetail {
  trace_id: string
  created_at: string
  model: string | null
  protocol: string
  method: string
  path: string
  latest_user_text: string
  response_status: number | null
  latency_ms: number | null
  response_capture_complete: boolean
  session_evidence: Json
  request_body: Json | null
  response_body: Json | null
  tool_actions: ToolAction[]
  classification: Classification | null
  alerts: Alert[]
}

export interface SessionDetail {
  session: Session
  traces: TraceDetail[]
}

export interface DashboardData {
  trace_count: number
  session_count: number
  open_alert_count: number
  alert_rate: number
  stage_counts: Record<string, number>
  decisions: Record<string, number>
  top_reasons: Array<{ reason_code: string; count: number }>
  classification_latency_ms: { p50: number; p95: number }
  health: Record<string, string>
}

export interface Rule {
  id: string
  name: string
  original_text: string
  version: number
  enabled: boolean
  created_at: string
  updated_at: string
  scope: Json
  conditions: Json
  effect: string
  priority: number
  reason_code: string
  reason: string
}
