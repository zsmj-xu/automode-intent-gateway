import { useState } from 'react'
import type { Classification, ReviewEvent, StageResult } from '../types'
import { ALIGNMENT_LABEL, stageLabel } from '../lib/format'
import { CapabilityBadge } from './ui'

const STAGES: Array<StageResult['stage']> = ['rules', 'fast_llm', 'deep_llm']

export function DecisionWaterfall({ classification }: { classification: Classification }) {
  const [open, setOpen] = useState<string | null>(classification.final_stage || null)
  const stages = classification.stages || []
  const final = {
    decision: classification.final_decision,
    stage: classification.final_stage,
    risk: classification.risk,
    reason_code: classification.reason_code,
    reason: classification.reason,
    action_alignment: classification.action_alignment,
    total_latency_ms: classification.total_latency_ms,
  }
  return (
    <div className="waterfall-grid">
      {STAGES.map(stage => {
        const hit = stages.find(item => item.stage === stage)
        return <StageNode key={stage} stage={stage} hit={hit} open={open === stage} onToggle={() => setOpen(open === stage ? null : stage)} />
      })}
      <div className={`stage-node final ${final.decision === 'alert' ? 'danger' : 'safe'}`} onClick={() => setOpen(open === 'final' ? null : 'final')}>
        <div className="stage-node-head"><span className="stage-idx">最终判定</span><span className={`decision-badge ${final.decision}`}>{final.decision}</span></div>
        <div className="stage-verdict">{final.risk}</div>
        <div className="stage-reason-code">{final.reason_code}</div>
        {open === 'final' && (
          <div className="stage-detail">
            <Row k="阶段" v={final.stage} />
            <Row k="意图对齐" v={ALIGNMENT_LABEL[final.action_alignment] || final.action_alignment} />
            <Row k="耗时" v={final.total_latency_ms != null ? `${final.total_latency_ms.toFixed(1)} ms` : '—'} />
            <div className="stage-reason">{final.reason || '无说明'}</div>
          </div>
        )}
      </div>
    </div>
  )
}

function StageNode({ stage, hit, open, onToggle }: { stage: string; hit?: StageResult; open: boolean; onToggle: () => void }) {
  const cls = hit ? (hit.status === 'error' ? 'error' : 'done') : 'skipped'
  return (
    <div className={`stage-node ${cls}`} onClick={onToggle}>
      <div className="stage-node-head"><span className="stage-idx">{stageLabel(stage)}</span>{hit && <span className="stage-status">{hit.status}</span>}</div>
      <div className="stage-verdict">{hit?.verdict || '未触发'}</div>
      <div className="stage-reason-code">{hit?.reason_code || '—'}</div>
      {open && hit && (
        <div className="stage-detail">
          <Row k="风险" v={hit.risk} />
          {hit.model && <Row k="模型" v={hit.model} />}
          {hit.latency_ms != null && <Row k="耗时" v={`${Number(hit.latency_ms).toFixed(1)} ms`} />}
          {hit.input_tokens != null && <Row k="tokens" v={`${hit.input_tokens} / ${hit.output_tokens ?? '—'}`} />}
          {hit.error_code && <Row k="error" v={hit.error_code} />}
          {hit.evidence?.length ? <div className="stage-evidence">{hit.evidence.map(line => <span key={line}>{line}</span>)}</div> : null}
          {hit.matched_rule_versions?.length ? <Row k="命中规则" v={hit.matched_rule_versions.join(', ')} /> : null}
          <div className="stage-reason">{hit.reason || '无说明'}</div>
        </div>
      )}
      {!hit && <div className="stage-skipped-note">{stage === 'rules' ? '—' : '规则短路 / 未触发'}</div>}
    </div>
  )
}

function Row({ k, v }: { k: string; v: string }) {
  return <div className="stage-row"><span>{k}</span><b>{v}</b></div>
}

export function ReviewContext({ transcript }: { transcript: ReviewEvent[] }) {
  if (!transcript?.length) return <p className="muted">无可解析的审查上下文</p>
  return (
    <div className="review-context">
      {transcript.map((event, index) => {
        if (event.type === 'user') {
          return <div className="rc-event" key={index}><span className="rc-tag user">用户</span><span className="rc-text">{event.text}</span></div>
        }
        if (event.type === 'session_authorization') {
          return (
            <div className="rc-event session-auth" key={index}>
              <span className="rc-tag session">会话授权基线</span>
              <span className="rc-text">
                {event.capabilities?.length ? (
                  <span className="rc-auth-line">已授权{event.capabilities.map(cap => <CapabilityBadge key={cap} capability={cap} />)}</span>
                ) : null}
                {event.forbidden_capabilities?.length ? (
                  <span className="rc-auth-line forbidden">禁止{event.forbidden_capabilities.map(cap => <CapabilityBadge key={cap} capability={cap} />)}</span>
                ) : null}
                {event.statements?.length ? (
                  <ul className="rc-statements">{event.statements.map((statement, i) => <li key={i}>{statement}</li>)}</ul>
                ) : null}
              </span>
            </div>
          )
        }
        const proposed = event.phase === 'proposed'
        return (
          <div className={`rc-event ${proposed ? 'proposed' : 'historical'}`} key={index}>
            <span className={`rc-tag ${proposed ? 'proposed' : 'historical'}`}>{proposed ? '本轮拟调用' : '历史调用'}</span>
            <span className="rc-text">
              <b>{event.name || 'unknown'}</b>
              {event.capability && <span className={`cap ${event.capability}`}>{event.capability}</span>}
              {event.target ? <span className="rc-target"> · {event.target}</span> : null}
              {event.arguments != null && <pre className="rc-args">{JSON.stringify(event.arguments, null, 2)}</pre>}
            </span>
          </div>
        )
      })}
    </div>
  )
}
