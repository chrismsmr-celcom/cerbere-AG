import { useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Copy, X } from 'lucide-react'
import { useTrace } from '../lib/queries'
import type { Decision, Span } from '../lib/api'
import { ms, pretty, spanStart, usd } from '../lib/format'
import { EvidenceReveal } from './EvidenceReveal'
import { Button, DECISION_META, DecisionBadge, ErrorNote, Skeleton, useToast } from './ui'

function decisionOf(s: Span): Decision {
  if (s.blocked) return 'blocked'
  const failed = (s.security_checks || []).some((c) => c && c.passed === false)
  return failed ? 'flagged' : 'allowed'
}

function labelOf(s: Span): string {
  const inp = (s.input_data || {}) as Record<string, unknown>
  const tool = (inp.tool as string) || (inp.tool_name as string)
  return tool || s.model || s.span_type || 'span'
}

function rowId(s: Span, i: number): string {
  return s.span_id || `idx-${i}`
}

export function TraceDrawer() {
  const [params, setParams] = useSearchParams()
  const traceId = params.get('trace')
  const selected = params.get('span')
  const { data, isLoading, error } = useTrace(traceId)
  const toast = useToast()

  const spans = useMemo(() => {
    const list = [...(data || [])]
    list.sort((a, b) => spanStart(a) - spanStart(b))
    return list
  }, [data])

  const timeline = useMemo(() => {
    if (!spans.length) return { t0: 0, total: 1 }
    const t0 = Math.min(...spans.map(spanStart))
    const end = Math.max(...spans.map((s) => spanStart(s) + (s.latency_ms || 0) / 1000))
    return { t0, total: Math.max(end - t0, 0.001) }
  }, [spans])

  const current = useMemo(() => {
    if (!spans.length) return null
    const i = spans.findIndex((s, k) => rowId(s, k) === selected)
    // par défaut : le premier span bloqué, sinon le premier
    if (i >= 0) return { span: spans[i], index: i }
    const b = spans.findIndex((s) => s.blocked)
    const idx = b >= 0 ? b : 0
    return { span: spans[idx], index: idx }
  }, [spans, selected])

  const close = () =>
    setParams(
      (p) => {
        p.delete('trace')
        p.delete('span')
        return p
      },
      { replace: true },
    )

  const select = (i: number) => {
    const s = spans[i]
    if (!s) return
    setParams(
      (p) => {
        p.set('span', rowId(s, i))
        return p
      },
      { replace: true },
    )
  }

  useEffect(() => {
    if (!traceId) return
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null
      if (t && ['INPUT', 'TEXTAREA'].includes(t.tagName)) return
      if (e.key === 'Escape') close()
      if (e.key === 'ArrowRight' && current) select(Math.min(current.index + 1, spans.length - 1))
      if (e.key === 'ArrowLeft' && current) select(Math.max(current.index - 1, 0))
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })

  if (!traceId) return null

  const blocked = spans.filter((s) => s.blocked).length
  const cost = spans.reduce((a, s) => a + (s.cost_usd || 0), 0)

  return (
    <div className="fixed inset-0 z-50">
      <button aria-label="Close trace" className="absolute inset-0 bg-black/55" onClick={close} />
      <aside
        role="dialog"
        aria-label="Trace details"
        className="absolute top-0 right-0 flex h-full w-[min(780px,100vw)] flex-col border-l border-line bg-coal"
      >
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0">
            <h2 className="font-display text-lg font-medium">Trace</h2>
            <div className="mt-0.5 flex items-center gap-2">
              <code className="truncate font-mono text-[12.5px] text-dim">{traceId}</code>
              <button
                aria-label="Copy trace id"
                className="text-faint hover:text-paper"
                onClick={() => {
                  navigator.clipboard?.writeText(traceId)
                  toast('Trace id copied')
                }}
              >
                <Copy size={14} />
              </button>
            </div>
          </div>
          <button aria-label="Close" onClick={close} className="rounded p-1 text-dim hover:bg-lift hover:text-paper">
            <X size={18} />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto">
          {isLoading && (
            <div className="space-y-3 p-5">
              <Skeleton className="h-6 w-2/3" />
              <Skeleton className="h-40 w-full" />
            </div>
          )}
          {error && (
            <div className="p-5">
              <ErrorNote message={(error as Error).message} />
            </div>
          )}
          {!isLoading && !error && spans.length === 0 && (
            <p className="p-5 text-dim">No spans were recorded for this trace.</p>
          )}

          {spans.length > 0 && current && (
            <>
              <div className="num flex flex-wrap gap-x-6 gap-y-1 px-5 py-3 text-[13px] text-dim">
                <span>{spans.length} spans</span>
                <span style={{ color: blocked ? 'var(--color-block)' : undefined }}>{blocked} blocked</span>
                <span>{ms(timeline.total * 1000)} total</span>
                <span>{usd(cost)}</span>
              </div>

              <ol className="px-5 pb-2" aria-label="Span waterfall">
                {spans.map((s, i) => {
                  const d = decisionOf(s)
                  const left = ((spanStart(s) - timeline.t0) / timeline.total) * 100
                  const width = Math.max(((s.latency_ms || 0) / 1000 / timeline.total) * 100, 1.2)
                  const active = current.index === i
                  return (
                    <li key={rowId(s, i)}>
                      <button
                        onClick={() => select(i)}
                        aria-current={active}
                        className={`grid w-full grid-cols-[170px_1fr_64px] items-center gap-3 rounded px-2 py-1.5 text-left ${active ? 'bg-lift' : 'hover:bg-slab'}`}
                      >
                        <span className="truncate text-[13px] text-paper">
                          <span className="num mr-2 text-faint">{i + 1}</span>
                          {labelOf(s)}
                        </span>
                        <span className="relative h-4 rounded-sm bg-slab">
                          <span
                            className="absolute top-0 h-4 rounded-sm"
                            style={{
                              left: `${Math.min(left, 99)}%`,
                              width: `${Math.min(width, 100 - Math.min(left, 99))}%`,
                              background: DECISION_META[d].color,
                            }}
                          />
                        </span>
                        <span className="num text-right text-[12.5px] text-dim">{ms(s.latency_ms)}</span>
                      </button>
                    </li>
                  )
                })}
              </ol>

              <SpanDetail span={current.span} />
              <p className="px-5 pb-6 text-[12.5px] text-faint">Use ← and → to move between spans, Esc to close.</p>
            </>
          )}
        </div>
      </aside>
    </div>
  )
}

function Block({ title, value }: { title: string; value: unknown }) {
  const text = pretty(value)
  if (!text) return null
  return (
    <div>
      <div className="mb-1 text-[12.5px] text-faint">{title}</div>
      <pre className="max-h-64 overflow-auto rounded-md border border-line bg-ink p-3 font-mono text-[12px] leading-5 whitespace-pre-wrap break-words text-paper/90">
        {text}
      </pre>
    </div>
  )
}

function SpanDetail({ span }: { span: Span }) {
  const d = decisionOf(span)
  const checks = (span.security_checks || []).filter((c) => c && typeof c === 'object')
  const failed = checks.filter((c) => c.passed === false)
  const why = span.block_reason || span.llm_reason || failed[0]?.details || null
  return (
    <div className="space-y-4 border-t border-line px-5 py-4">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
        <DecisionBadge decision={d} />
        <span className="font-display text-[15px]">{labelOf(span)}</span>
        {span.model && <span className="font-mono text-[12.5px] text-dim">{span.model}</span>}
      </div>
      <dl className="num grid grid-cols-2 gap-x-6 gap-y-1 text-[13px] sm:grid-cols-4">
        {[
          ['Latency', ms(span.latency_ms)],
          ['Tokens', `${span.input_tokens ?? 0} in · ${span.output_tokens ?? 0} out`],
          ['Cost', usd(span.cost_usd)],
          ['Detected by', span.detection_layer || '—'],
        ].map(([k, v]) => (
          <div key={k}>
            <dt className="text-faint">{k}</dt>
            <dd className="text-paper">{v}</dd>
          </div>
        ))}
      </dl>
      {why && (
        <div className="rounded-md border border-line bg-slab px-3 py-2 text-[13px]">
          <span className="text-faint">Why: </span>
          {why}
        </div>
      )}
      {checks.length > 0 && (
        <ul className="space-y-1 text-[13px]">
          {[...failed, ...checks.filter((c) => c.passed !== false)].map((c, i) => (
            <li key={i} className="flex items-center justify-between gap-3">
              <span className={c.passed === false ? 'text-paper' : 'text-dim'}>{c.check_name || 'check'}</span>
              <span style={{ color: c.passed === false ? 'var(--color-block)' : 'var(--color-allow)' }}>
                {c.passed === false ? `failed${c.risk_level ? ` · ${c.risk_level}` : ''}` : 'passed'}
              </span>
            </li>
          ))}
        </ul>
      )}
      <Block title="Input" value={span.input_data} />
      <Block title="Output" value={span.output_data} />
      <EvidenceReveal text={pretty(span)} />
      <div className="flex justify-end">
        <Button
          onClick={() => navigator.clipboard?.writeText(pretty(span))}
          className="text-[12.5px]"
          aria-label="Copy span as JSON"
        >
          <Copy size={13} /> Copy span JSON
        </Button>
      </div>
    </div>
  )
}
