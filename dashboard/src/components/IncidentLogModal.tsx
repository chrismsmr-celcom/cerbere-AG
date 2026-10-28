import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { get } from '../lib/api'
import { phaseOf, remaining, type Incident, type IncidentPhase } from '../lib/incidents'
import { Empty, ErrorNote, Skeleton } from './ui'
import { EvidenceReveal } from './EvidenceReveal'
import { Modal } from './Modal'
import { FilterChip, PrettyBlock, clock } from './LogParts'

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

type Access = {
  t: number
  kind: 'revealed' | 'denied'
  by: string | null
  token: string | null
  reason: string | null
  why: string | null
}

type IncidentLog = {
  incident: Incident
  lifecycle: Lifecycle[]
  access?: Access[]
  spans: LogSpan[]
  total: number
}

type Filter = 'all' | 'blocked' | 'shadow' | 'access'
type Item = { t: number; span?: LogSpan; life?: Lifecycle; access?: Access }

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

function SpanDetail({ s }: { s: LogSpan }) {
  const v = verdictOf(s)
  return (
    <div className="space-y-3 text-[13px]">
      <div>
        <div className="text-[15px] text-paper">{s.tool || s.model || s.type}</div>
        <div className="text-faint">
          {clock(s.t)} · {s.type === 'tool_call' ? 'tool call' : 'LLM call'} · {Math.round(s.latency_ms)} ms
          {s.cost_usd > 0 ? ` · $${s.cost_usd.toFixed(4)}` : ''}
          {s.layer ? ` · ${s.layer}` : ''}
        </div>
      </div>
      <div style={{ color: v.color }}>{v.label}</div>
      {s.reason && <div className="text-dim">{s.reason}</div>}
      <PrettyBlock label="Input (masked)" body={s.input} />
      <PrettyBlock label="Output (masked)" body={s.output} />
      <EvidenceReveal text={`${s.input}\n${s.output}`} />
    </div>
  )
}

export function IncidentLogModal({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const [filter, setFilter] = useState<Filter>('all')
  const [selected, setSelected] = useState<string | null>(null)
  const live = phaseOf(incident) === 'capturing'

  const q = useQuery({
    queryKey: ['incident-log', incident.id],
    queryFn: () => get<IncidentLog>(`/api/incidents/${encodeURIComponent(incident.id)}/log?limit=300`),
    refetchInterval: live ? 3000 : false,
  })

  const data = q.data
  const spans = data?.spans ?? []
  const access = data?.access ?? []
  const blockedCount = spans.filter((s) => s.blocked).length
  const shadowCount = spans.filter((s) => s.shadow && s.shadow !== 'ALLOW').length
  const current = spans.find((s) => s.span_id === selected) ?? null

  const items = useMemo<Item[]>(() => {
    const shown =
      filter === 'access'
        ? []
        : spans.filter((s) =>
            filter === 'blocked' ? s.blocked : filter === 'shadow' ? s.shadow && s.shadow !== 'ALLOW' : true,
          )
    const life: Item[] = filter === 'all' ? (data?.lifecycle ?? []).map((l) => ({ t: l.t, life: l })) : []
    const acc: Item[] = filter === 'all' || filter === 'access' ? access.map((a) => ({ t: a.t, access: a })) : []
    return [...shown.map((s) => ({ t: s.t, span: s })), ...life, ...acc].sort((a, b) => b.t - a.t)
  }, [spans, data?.lifecycle, access, filter])

  const phase = phaseOf(incident)

  return (
    <Modal open wide title={`Incident log · ${incident.agent_id}`} onClose={onClose}>
      <div className="min-w-0 space-y-3 text-[13px]">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-dim">
          <span className="text-paper">{PHASE_LABEL[phase]}</span>
          {(phase === 'capturing' || phase === 'stopped') && <span>{remaining(incident.expires_at)} left</span>}
          {phase !== 'expired' && phase !== 'destroyed' && <span>{incident.sealed_values} sealed values</span>}
          {incident.opened_by && <span>Opened by {incident.opened_by}</span>}
          {live && <span style={{ color: 'var(--color-amber)' }}>Live · refreshing every 3 s</span>}
        </div>
        {incident.reason && <div className="text-faint">{incident.reason}</div>}

        <div className="flex flex-wrap gap-2">
          <FilterChip active={filter === 'all'} onClick={() => setFilter('all')} label="All" n={spans.length} />
          <FilterChip active={filter === 'blocked'} onClick={() => setFilter('blocked')} label="Blocked" n={blockedCount} />
          <FilterChip active={filter === 'shadow'} onClick={() => setFilter('shadow')} label="Shadow" n={shadowCount} />
          <FilterChip active={filter === 'access'} onClick={() => setFilter('access')} label="Evidence access" n={access.length} />
        </div>

        {q.error && <ErrorNote message={(q.error as Error).message} />}

        {q.isLoading ? (
          <Skeleton className="h-64 w-full" />
        ) : items.length === 0 ? (
          <Empty
            title="Nothing captured for this filter"
            text="Actions from this agent appear here while the capture is open. Values stay masked; sealed originals are only reopened from the audit-controlled reveal."
          />
        ) : (
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
            <div className="max-h-[60vh] min-w-0 overflow-auto rounded-md border border-line">
              <table className="w-full min-w-[520px] text-left">
                <thead className="sticky top-0 bg-coal text-[12.5px] text-faint">
                  <tr className="border-b border-line">
                    {['Time', 'Action', 'Verdict', 'Risk'].map((h) => (
                      <th key={h} className="px-3 py-2 font-normal">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {items.map((it, i) => {
                    if (it.access) {
                      const a = it.access
                      const note = a.kind === 'denied' ? [a.why, a.reason].filter(Boolean).join(' · ') : a.reason
                      return (
                        <tr key={`acc-${i}`} className="border-b border-line/60 bg-ink/40">
                          <td className="num px-3 py-2 text-dim">{clock(it.t)}</td>
                          <td colSpan={3} className="px-3 py-2">
                            <span style={{ color: a.kind === 'denied' ? 'var(--color-block)' : 'var(--color-amber)' }}>
                              {a.kind === 'denied' ? 'Reveal denied' : 'Value revealed'}
                            </span>
                            <span className="text-dim">
                              {' · '}
                              {a.by || 'unknown'}
                              {a.token ? ` · ${a.token}` : ''}
                            </span>
                            {note && <div className="text-[12px] text-faint">{note}</div>}
                          </td>
                        </tr>
                      )
                    }
                    if (it.life) {
                      return (
                        <tr key={`life-${i}`} className="border-b border-line/60 bg-ink/40">
                          <td className="num px-3 py-2 text-dim">{clock(it.t)}</td>
                          <td colSpan={3} className="px-3 py-2 text-dim">
                            {LIFE_LABEL[it.life.kind]}
                            {it.life.by ? ` · ${it.life.by}` : ''}
                          </td>
                        </tr>
                      )
                    }
                    const s = it.span as LogSpan
                    const v = verdictOf(s)
                    const on = selected === s.span_id
                    return (
                      <tr
                        key={s.span_id}
                        tabIndex={0}
                        onClick={() => setSelected(s.span_id)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') setSelected(s.span_id)
                        }}
                        className={`cursor-pointer border-b border-line/60 ${on ? 'bg-ink' : 'hover:bg-ink/40'}`}
                      >
                        <td className="num px-3 py-2 text-dim">{clock(s.t)}</td>
                        <td className="px-3 py-2">
                          <div className="text-paper">{s.tool || s.model || s.type}</div>
                          <div className="text-[12px] text-faint">{s.type === 'tool_call' ? 'tool call' : 'LLM call'}</div>
                        </td>
                        <td className="px-3 py-2" style={{ color: v.color }}>
                          {v.label}
                          {s.reason && <div className="max-w-[16rem] truncate text-[12px] text-faint">{s.reason}</div>}
                        </td>
                        <td className="px-3 py-2" style={{ color: RISK_COLOR[s.risk] }}>
                          {s.risk}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            <div className="max-h-[60vh] min-w-0 overflow-auto rounded-md border border-line p-4">
              {current ? (
                <SpanDetail s={current} />
              ) : (
                <p className="text-faint">Select an action on the left to inspect its masked input and output, and reopen sealed values.</p>
              )}
            </div>
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