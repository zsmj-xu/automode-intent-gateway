import type { ReactNode } from 'react'
import { AlertTriangle, CircleCheck, CircleHelp, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react'
import type { Capability, Risk } from '../types'
import { CAPABILITY_LABEL } from '../lib/format'

export function Risk({ level = 'low' }: { level?: string }) {
  const Icon = level === 'low' ? ShieldCheck : level === 'medium' ? CircleHelp : level === 'critical' ? ShieldAlert : AlertTriangle
  return <span className={`risk ${level}`}><Icon size={13} />{level}</span>
}

export function CapabilityBadge({ capability }: { capability: string }) {
  const cap = (capability || 'unknown') as Capability
  return <span className={`cap ${cap}`}>{CAPABILITY_LABEL[cap] || cap}</span>
}

export function StatusPill({ status }: { status: string }) {
  return <span className={`status-pill ${status}`}>{status}</span>
}

export function PanelTitle({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="panel-title">
      <div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>
      {actions && <div className="panel-title-actions">{actions}</div>}
    </div>
  )
}

export function Metric({ label, value, detail, tone }: { label: string; value: string | number; detail?: string; tone?: string }) {
  return <article className={`metric ${tone || ''}`}><span>{label}</span><strong>{value}</strong>{detail && <small>{detail}</small>}</article>
}

export function Health({ status }: { status: string }) {
  const good = status === 'healthy' || status === 'configured'
  return <span className={good ? 'health good' : 'health unknown'}><i />{status.replace('_', ' ')}</span>
}

export function Empty({ text }: { text: string }) {
  return <div className="empty"><ShieldCheck size={28} /><p>{text}</p></div>
}

export function Loading() {
  return <div className="loading"><RefreshCw className="spin" /><span>加载中</span></div>
}

export function ErrorState({ message }: { message: string }) {
  return <div className="error-state"><AlertTriangle /><h2>无法加载数据</h2><p>{message}</p></div>
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>
}
