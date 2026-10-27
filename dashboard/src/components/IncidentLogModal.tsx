import { Fragment, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { get } from '../lib/api'
import { phaseOf, remaining, type Incident, type IncidentPhase } from '../lib/incidents'
import { Empty, ErrorNote, Skeleton } from './ui'
import { Modal } from './Modal'

type LogSpan = {
  span_id: string
  type: string
  t: number
  latency_ms: number
  tool: string | null
  model: string | null
  blocked: boolean
  reason: string | null
  cost_usd: number
  layer: string | null
  risk: string
  shadow: string | null
  input: string
  output: string
}

type Lifecycle = {
  t: number
  kind: 'opened' | 'closed' | 'destroyed' | 'expired'
  by?: string | null
  text?: string | null
}

type IncidentLog = {
  incident: Incident
  lifecycle: Lifecycle[]
  spans: LogSpan[]
  total: number
}

type Filter = 'all' | 'blocked' | 'shadow'
type Item = { t: number; span?: LogSpan; life?: Lifecycle }

const PHASE_LABEL: Record<IncidentPhase, string> = {
  capturing: 'Capturing',
  stopped: 'Stopped',
  expired: 'Expired',
  destroyed: 'Destroyed',
}

const LIFE_LABEL: Record<Lifecycle['kind'], string> = {
  opened: 'Capture opened',
  closed: 'Capture stopped',
  destroyed: 'Evidence destroyed',
  expired: 'Capture expired, evidence destroyed',
}

const RISK_COLOR: Record<string, string> = {
  critical: 'var(--color-block)',
  high: 'var(--color-block)',
  medium: 'var(--color-amber)',
}

function verdictOf(s: LogSpan) {
  if (s.blocked) return { label: 'Blocked', color: 'var(--color-block)' }
  if (s.shadow && s.shadow !== 'ALLOW') {
    return { label: `Shadow · would ${s.shadow.toLowerCase().replace(/_/g, ' ')}`, color: 'var(--color-amber)' }
  }
  return { label: 'Allowed', color: 'var(--color-dim)' }
}

const clock = (t: number) => new Date(t * 1000).toLocaleTimeString([], { hour12: false })

export function IncidentLogModal({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const [filter, setFilter] = useState<Filter>('all')
  const [expanded, setExpanded] = useState<string | null>(null)
  const live = phaseOf(incident) === 'capturing'

  const q = useQuery({
    queryKey: ['incident-log', incident.id],
    queryFn: () => get<IncidentLog>(`/api/incidents/${encodeURIComponent(incident.id)}/log?limit=300`),
    refetchInterval: live ? 3000 : false,
  })

  const data = q.data
  const spans = data?.spans ?? []
  const blockedCount = spans.filter((s) => s.blocked).length
  const shadowCount = spans.filter((s) => s.shadow && s.shadow !== 'ALLOW').length

  const items = useMemo<Item[]>(() => {
    const shown = spans.filter((s) =>
      filter === 'blocked' ? s.blocked : filter === 'shadow' ? s.shadow && s.shadow !== 'ALLOW' : true,
    )
    const life: Item[] = filter === 'all' ? (data?.lifecycle ?? []).map((l) => ({ t: l.t, life: l })) : []
    return [...shown.map((s) => ({ t: s.t, span: s })), ...life].sort((a, b) => b.t - a.t)
  }, [spans, data?.lifecycle, filter])

  const phase = phaseOf(incident)
  const chips: { id: Filter; label: string; n: number }[] = [
    { id: 'all', label: 'All', n: spans.length },
    { id: 'blocked', label: 'Blocked', n: blockedCount },
    { id: 'shadow', label: 'Shadow', n: shadowCount },
  ]

  return (
    <Modal open onClose={onClose} title={`Incident log · ${incident.agent_id}`}>
      <div className="min-w-0 space-y-3 text-[13px]">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-dim">
          <span className="text-paper">{PHASE_LABEL[phase]}</span>
          {(phase === 'capturing' || phase === 'stopped') && <span>{remaining(incident.expires_at)} left</span>}
          {phase !== 'expired' && phase !== 'destroyed' && <span>{incident.sealed_values} sealed values</span>}
          {incident.opened_by && <span>Opened by {incident.opened_by}</span>}
          {live && <span style={{ color: 'var(--color-amber)' }}>Live · refreshing every 3 s</span>}
        </div>
        {incident.reason && <div className="text-faint">{incident.reason}</div>}

        <div className="flex gap-2">
          {chips.map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setFilter(c.id)}
              className={`rounded-md border px-2.5 py-1 text-[12.5px] ${
                filter === c.id ? 'border-amber text-paper' : 'border-line text-dim hover:text-paper'
              }`}
            >
              {c.label} <span className="num text-faint">{c.n}</span>
            </button>
          ))}
        </div>

        {q.error && <ErrorNote message={(q.error as Error).message} />}

        {q.isLoading ? (
          <Skeleton className="h-40 w-full" />
        ) : items.length === 0 ? (
          <Empty
            title="Nothing captured for this filter"
            text="Actions from this agent appear here while the capture is open. Values stay masked; sealed originals are only reopened from the audit-controlled reveal."
          />
        ) : (
          <div className="max-h-[60vh] overflow-auto">
            <table className="w-full min-w-[640px] text-left">
              <thead className="sticky top-0 bg-panel text-[12.5px] text-faint">
                <tr className="border-b border-line">
                  {['Time', 'Action', 'Verdict', 'Risk', 'Latency'].map((h) => (
                    <th key={h} className="px-3 py-2 font-normal">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((it, i) => {
                  if (it.life) {
                    return (
                      <tr key={`life-${i}`} className="border-b border-line/60 bg-ink/40">
                        <td className="num px-3 py-2 text-dim">{clock(it.t)}</td>
                        <td colSpan={4} className="px-3 py-2 text-dim">
                          {LIFE_LABEL[it.life.kind]}
                          {it.life.by ? ` · ${it.life.by}` : ''}
                        </td>
                      </tr>
                    )
                  }
                  const s = it.span as LogSpan
                  const v = verdictOf(s)
                  const open = expanded === s.span_id
                  return (
                    <Fragment key={s.span_id}>
                      <tr
                        className="cursor-pointer border-b border-line/60 hover:bg-ink/40"
                        onClick={() => setExpanded(open ? null : s.span_id)}
                      >
                        <td className="num px-3 py-2 text-dim">{clock(s.t)}</td>
                        <td className="px-3 py-2">
                          <div className="text-paper">{s.tool || s.model || s.type}</div>
                          <div className="text-[12px] text-faint">{s.type === 'tool_call' ? 'tool call' : 'LLM call'}</div>
                        </td>
                        <td className="px-3 py-2" style={{ color: v.color }}>
                          {v.label}
                          {s.reason && <div className="max-w-xs truncate text-[12px] text-faint">{s.reason}</div>}
                        </td>
                        <td className="px-3 py-2" style={{ color: RISK_COLOR[s.risk] }}>
                          {s.risk}
                        </td>
                        <td className="num px-3 py-2 text-dim">{Math.round(s.latency_ms)} ms</td>
                      </tr>
                      {open && (
                        <tr className="border-b border-line/60">
                          <td colSpan={5} className="px-3 pb-3">
                            <div className="grid gap-2 md:grid-cols-2">
                              {[
                                ['Input', s.input],
                                ['Output', s.output],
                              ].map(([label, body]) => (
                                <div key={label} className="min-w-0">
                                  <div className="mb-1 text-faint">{label}</div>
                                  <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-ink p-2 text-[12px] text-dim">
                                    {body}
                                  </pre>
                                </div>
                              ))}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {data && data.total > spans.length && (
          <div className="text-faint">
            Showing the latest {spans.length} of {data.total} actions.
          </div>
        )}
      </div>
    </Modal>
  )
}
