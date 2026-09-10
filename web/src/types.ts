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
  dlp_findings_count?: number
  dlp_categories?: string[]
  has_dlp_alert?: boolean
  dlp_alert_count?: number
  latest_trace_decision?: string
  has_intent_alert?: boolean
  intent_risk?: Risk
  risk_intent_summary?: RiskIntentSummary | null
}

export interface ToolSchemaItem {
  id: string
  agent_id: string
  tool_name: string
  schema_version: string
  content_fingerprint: string
  description_snippet: string
  reason: string
  enabled: boolean
  created_at: string
}

export interface RiskIntentSummary {
  id: string
  session_id: string
  trace_id: string
  started_at: string
  ended_at: string
  purpose_risk: string
  transfer_intent: 'none' | 'prepare' | 'external_transfer'
  severity: Risk
  state: 'resolved' | 'needs_review'
  reason_code: string
  summary: string
  source: string
  version: string
  alert_id?: string | null
}

export interface ReviewEvent {
  type: 'user' | 'tool_call' | 'session_authorization' | 'dlp_finding' | 'destination' | 'identity'
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
  category?: string
  path?: string
  confidence?: string
  snippet?: string
  trust?: string
  model?: string | null
  trusted?: boolean
  user_id?: string | null
  department?: string | null
}

export interface DataFinding {
  category: 'credential' | 'pii' | 'source_code' | 'admin_keyword'
  path: string
  confidence: string
  fingerprint: string
  snippet: string
  detector: string
  canonical_fingerprint?: string
  path_type?: 'tool_description' | 'request_body' | string
  disposition?: 'approved_metadata' | 'active_alert' | string
  schema_id?: string | null
  tool_name?: string | null
}

export interface Destination {
  id?: string | null
  name: string
  upstream_pattern?: string
  model_pattern?: string
  provider?: string | null
  region?: string | null
  trust: 'trusted' | 'external'
  enabled?: boolean
  model?: string | null
  upstream?: string
  matched?: boolean
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
  review_object?: 'human_request' | 'tool_action' | 'outbound_request'
  request_safety?: 'safe' | 'harmful' | 'ambiguous' | 'needs_review' | 'not_reviewed'
  request_purpose?: 'normal' | 'suspicious' | 'unknown'
  data_findings?: DataFinding[]
  destination?: Destination
  destination_trust?: 'trusted' | 'external'
  policy_decision?: 'allow' | 'alert'
  matched_policies?: string[]
  matched_rules?: string[]
  evidence_id?: string | null
  identity?: Json
  semantic_status?: 'not_needed' | 'needs_review' | 'resolved'
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
export type ChannelSource = 'rule' | 'llm' | 'dual' | 'legacy' | string
export type ReviewStatus = 'needs_review' | 'failed' | 'resolved' | string

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
  evidence_id?: string | null
  data_findings?: DataFinding[]
  destination?: Destination
  alert_type?: 'dlp' | 'intent_action'
  data_categories?: string[]
  destination_name?: string
  destination_trust?: 'trusted' | 'external'
  rule_severity?: Risk | null
  llm_severity?: Risk | null
  llm_status?: string | null
  review_status?: ReviewStatus
  divergence?: boolean
  hit_source?: string | null
  channel_source?: ChannelSource
  event_id?: string | null
}

export type CaptureStage = 'inbound_request' | 'model_outbound' | 'unknown'
export type ContentIntegrity = 'complete' | 'truncated' | 'redacted' | 'missing'
export type ProcessingStatus = 'pending' | 'processing' | 'completed' | 'failed'
export type AssociationStatus = 'none' | 'associated' | 'request_missing'
export type StageStatus = 'pending' | 'processing' | 'completed' | 'skipped' | 'failed'

export interface EventAlertSummary {
  id: string
  severity: Risk
  title: string
  channel_source?: ChannelSource
  status?: string
}

export interface EventItem {
  id: string
  event_id?: string
  external_event_id?: string
  source_id: string
  call_id: string
  attempt_id?: string | null
  event_type: 'request' | 'response' | 'full_call' | string
  protocol: string
  capture_stage: CaptureStage
  content_integrity: ContentIntegrity
  is_realtime: boolean
  is_historical?: boolean
  timestamp: string
  received_at: string
  payload_hash?: string
  disk_buffer_path?: string | null
  processing_status: ProcessingStatus
  association_status: AssociationStatus
  rule_status: StageStatus
  llm_status: StageStatus
  rule_verdict?: Json | null
  llm_verdict?: Json | null
  response_evidence?: Json[]
  retry_count: number
  error_message?: string | null
  completed_at?: string | null
  metadata?: Json
  alerts?: EventAlertSummary[]
  tasks?: Array<{
    id: string
    stage: string
    status: string
    retry_count: number
    created_at: string
    updated_at: string
    error_message?: string | null
  }>
  correlated_events?: Array<{
    id: string
    event_type: string
    protocol: string
    capture_stage: string
    content_integrity: string
    processing_status: string
    association_status: string
    received_at: string
  }>
}

export interface SourceItem {
  id: string
  name: string
  token: string
  allow_trusted_identity: boolean
  rate_limit_per_minute?: number | null
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface SystemStats {
  rule_queue_depth: number
  reviewer_queue_depth: number
  oldest_pending_task_age_seconds: number | null
  disk_buffer_bytes: number
  disk_buffer_limit_bytes: number
  proxy_buffer_bytes: number
  proxy_dropped_count: number
  reliability_mode: string
  failed_events_count?: number
}

export interface DetectorItem {
  id: string
  name: string
  category: 'credential' | 'pii' | 'source_code' | 'admin_keyword'
  description: string
  pattern: string
  enabled: boolean
  custom?: boolean
}

export interface PromptsResponse {
  data: Record<string, string>
  defaults: Record<string, string>
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
  risk_intent_segments: RiskIntentSummary[]
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
  dlp?: {
    reviewed: number
    alerts: number
    category_counts: Record<string, number>
    destination_counts: Record<string, number>
  }
  event_stats?: SystemStats
}

export interface DLPPolicy {
  id: string
  name: string
  original_text: string
  effect: 'alert' | 'review'
  priority: number
  conditions: Json
  reason_code: string
  reason: string
  version: number
  enabled: boolean
  created_at: string
  updated_at: string
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
