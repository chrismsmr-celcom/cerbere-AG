import { useMemo, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { get } from '../lib/api'
import { Empty, ErrorNote, Skeleton } from './ui'
import { Modal } from './Modal'
import { FilterChip, PrettyBlock, clock } from './LogParts'

type ShadowSpan = {
  span_id: string
  type: string
  t: number
  latency_ms: number
  tool: string | null
  model: string | null
  agent_id: string | null
  shadow: string | null
  reasons: string[]
  risk: string
  cost_usd: number
  input: string
  output: string
}

type ShadowLog = {
  hours: number
  window_start: number
  since_enabled: boolean
  mode: { mode: string | null; since: number | null } | null
  summary: { total: number; would_block: number; would_require_approval: number; allowed: number }
  by_tool: { tool: string; count: number }[]
  spans: ShadowSpan[]
  truncated: boolean
}

type Filter = 'flagged' | 'block' | 'approval' | 'all'

const WINDOWS = [
  { hours: 1, label: 'Last hour' },
  { hours: 24, label: 'Last 24 hours' },
  { hours: 168, label: 'Last 7 days' },
]

const RISK_COLOR: Record<string, string> = {
  critical: 'var(--color-block)',
  high: 'var(--color-block)',
  medium: 'var(--color-amber)',
}

const when = (t: number) => new Date(t * 1000).toLocaleString()

function verdictOf(action: string | null) {
  if (action === 'BLOCK') return { label: 'Would block', color: 'var(--color-block)' }
  if (action === 'REQUIRE_APPROVAL') return { label: 'Would require approval', color: 'var(--color-amber)' }
  return { label: 'Would allow', color: 'var(--color-dim)' }
}

function Tile({ label, n, color }: { label: string; n: number; color?: string }) {
  return (
    <div className="rounded-md border border-line bg-ink px-3 py-2.5">
      <div className="num text-[22px]" style={{ color }}>
        {n}
      </div>
      <div className="text-[12.5px] text-faint">{label}</div>
    </div>
  )
}

function Detail({ s }: { s: ShadowSpan }) {
  const v = verdictOf(s.shadow)
  return (
    <div className="space-y-3 text-[13px]">
      <div>
        <div className="text-[15px] text-paper">{s.tool || s.model || s.type}</div>
        <div className="text-faint">
          {clock(s.t)} · {s.agent_id || 'unknown agent'} · {s.type === 'tool_call' ? 'tool call' : 'LLM call'} ·{' '}
          {Math.round(s.latency_ms)} ms
        </div>
      </div>
      <div style={{ color: v.color }}>{v.label}</div>
      {s.reasons.length > 0 ? (
        <ul className="list-disc space-y-1 pl-5 text-dim">
          {s.reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      ) : (
        <div className="text-faint">No violation detected for this action.</div>
      )}
      <PrettyBlock label="Input (masked)" body={s.input} />
      <PrettyBlock label="Output (masked)" body={s.output} />
    </div>
  )
}

/** Journal du mode shadow : ce que Cerbere AURAIT fait, sans avoir rien bloqué.
 *  agentId absent = tous les agents de l'organisation.
 *  Pour un agent, la fenêtre par défaut démarre à l'activation du shadow. */
export function ShadowLogModal({ agentId, onClose }: { agentId?: string | null; onClose: () => void }) {
  const [hours, setHours] = useState<number>(agentId ? 0 : 24) // 0 = depuis l'activation du shadow
  const [filter, setFilter] = useState<Filter>('flagged')
  const [selected, setSelected] = useState<string | null>(null)

  const q = useQuery({
    queryKey: ['shadow-log', agentId ?? 'all', hours],
    queryFn: () =>
      get<ShadowLog>(
        `/api/shadow/log?limit=300${hours === 0 ? '&since_enabled=1&hours=24' : `&hours=${hours}`}${
          agentId ? `&agent_id=${encodeURIComponent(agentId)}` : ''
        }`,
      ),
    refetchInterval: 5000,
    placeholderData: keepPreviousData,
  })

  const data = q.data
  const spans = data?.spans ?? []
  const sum = data?.summary
  const current = spans.find((s) => s.span_id === selected) ?? null

  const shown = useMemo(
    () =>
      spans.filter((s) =>
        filter === 'block'
          ? s.shadow === 'BLOCK'
          : filter === 'approval'
            ? s.shadow === 'REQUIRE_APPROVAL'
            : filter === 'flagged'
              ? s.shadow === 'BLOCK' || s.shadow === 'REQUIRE_APPROVAL'
              : true,
      ),
    [spans, filter],
  )

  return (
    <Modal open wide title={`Shadow log · ${agentId || 'all agents'}`} onClose={onClose}>
      <div className="min-w-0 space-y-3 text-[13px]">
        <p className="max-w-3xl text-dim">
          In shadow mode the agent keeps running and nothing is blocked. This is what Cerbere would have done if the
          agent were in enforce mode.
        </p>

        {data?.mode && (
          <div className="text-dim">
            {data.mode.mode === 'shadow' ? (
              <>
                Shadow mode is <span style={{ color: 'var(--color-amber)' }}>ON</span>
                {data.mode.since ? ` since ${when(data.mode.since)}` : ''}
                {data.since_enabled ? '. Showing everything observed since then.' : '.'}
              </>
            ) : (
              <>This agent is currently in enforce mode. Showing past shadow observations from the last 24 hours.</>
            )}
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="grid flex-1 gap-3 sm:grid-cols-4">
            <Tile label="Would block" n={sum?.would_block ?? 0} color="var(--color-block)" />
            <Tile label="Would require approval" n={sum?.would_require_approval ?? 0} color="var(--color-amber)" />
            <Tile label="Would allow" n={sum?.allowed ?? 0} />
            <Tile label="Actions observed" n={sum?.total ?? 0} />
          </div>
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            aria-label="Time window"
            className="rounded-md border border-line bg-ink px-2 py-1.5 text-paper"
          >
            {agentId && <option value={0}>Since shadow was enabled</option>}
            {WINDOWS.map((w) => (
              <option key={w.hours} value={w.hours}>
                {w.label}
              </option>
            ))}
          </select>
        </div>

        {data && data.by_tool.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 text-faint">
            <span>Most flagged tools:</span>
            {data.by_tool.map((t) => (
              <span key={t.tool} className="rounded-md border border-line px-2 py-0.5 text-dim">
                {t.tool} <span className="num text-faint">×{t.count}</span>
              </span>
            ))}
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          <FilterChip
            active={filter === 'flagged'}
            onClick={() => setFilter('flagged')}
            label="Would be stopped"
            n={(sum?.would_block ?? 0) + (sum?.would_require_approval ?? 0)}
          />
          <FilterChip active={filter === 'block'} onClick={() => setFilter('block')} label="Would block" n={sum?.would_block ?? 0} />
          <FilterChip
            active={filter === 'approval'}
            onClick={() => setFilter('approval')}
            label="Would require approval"
            n={sum?.would_require_approval ?? 0}
          />
          <FilterChip active={filter === 'all'} onClick={() => setFilter('all')} label="All observed" n={sum?.total ?? 0} />
        </div>

        {q.error && <ErrorNote message={(q.error as Error).message} />}

        {q.isLoading ? (
          <Skeleton className="h-64 w-full" />
        ) : shown.length === 0 ? (
          <Empty
            title="Nothing to show for this filter"
            text="Actions appear here while an agent runs in shadow mode. Switch the agent to shadow mode in Settings, then run it."
          />
        ) : (
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
            <div className="max-h-[52vh] min-w-0 overflow-auto rounded-md border border-line">
              <table className="w-full min-w-[520px] text-left">
                <thead className="sticky top-0 bg-coal text-[12.5px] text-faint">
                  <tr className="border-b border-line">
                    {['Time', ...(agentId ? [] : ['Agent']), 'Action', 'Shadow verdict', 'Risk'].map((h) => (
                      <th key={h} className="px-3 py-2 font-normal">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {shown.map((s) => {
                    const v = verdictOf(s.shadow)
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
                        {!agentId && <td className="px-3 py-2 text-dim">{s.agent_id || '—'}</td>}
                        <td className="px-3 py-2">
                          <div className="text-paper">{s.tool || s.model || s.type}</div>
                          <div className="text-[12px] text-faint">{s.type === 'tool_call' ? 'tool call' : 'LLM call'}</div>
                        </td>
                        <td className="px-3 py-2" style={{ color: v.color }}>
                          {v.label}
                          {s.reasons[0] && <div className="max-w-[18rem] truncate text-[12px] text-faint">{s.reasons[0]}</div>}
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

            <div className="max-h-[52vh] min-w-0 overflow-auto rounded-md border border-line p-4">
              {current ? (
                <Detail s={current} />
              ) : (
                <p className="text-faint">Select an action on the left to see why Cerbere would have stopped it.</p>
              )}
            </div>
          </div>
        )}

        {data?.truncated && (
          <div className="text-faint">Showing the latest {spans.length} observed actions in this window.</div>
        )}
      </div>
    </Modal>
  )
}