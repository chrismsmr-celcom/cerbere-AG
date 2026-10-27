import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { post } from '../../lib/api'
import { ago } from '../../lib/format'
import { useAgents } from '../../lib/queries'
import {
  phaseOf,
  remaining,
  useIncidentConfig,
  useIncidents,
  type Incident,
  type IncidentConfig,
  type IncidentPhase,
} from '../../lib/incidents'
import { Button, Empty, ErrorNote, Panel, Skeleton, useArm, useToast } from '../../components/ui'
import { Modal } from '../../components/Modal'
import { IncidentLogModal } from '../../components/IncidentLogModal'
import type { Agent } from '../../lib/api'

const PHASE: Record<IncidentPhase, { label: string; color: string }> = {
  capturing: { label: 'Capturing', color: 'var(--color-amber)' },
  stopped: { label: 'Stopped · evidence kept until expiry', color: 'var(--color-dim)' },
  expired: { label: 'Expired · evidence destroyed', color: 'var(--color-faint)' },
  destroyed: { label: 'Destroyed', color: 'var(--color-faint)' },
}

const DURATIONS = [
  { seconds: 3600, label: '1 hour' },
  { seconds: 6 * 3600, label: '6 hours' },
  { seconds: 24 * 3600, label: '24 hours' },
]

function OpenCaptureModal({
  agent,
  cfg,
  onClose,
}: {
  agent: Agent
  cfg: IncidentConfig
  onClose: () => void
}) {
  const toast = useToast()
  const qc = useQueryClient()
  const options = DURATIONS.filter((d) => d.seconds <= cfg.max_ttl_seconds)
  const [reason, setReason] = useState('')
  const [ttl, setTtl] = useState(options[Math.min(1, options.length - 1)]?.seconds ?? 3600)
  const tooShort = reason.trim().length < cfg.min_reason_length

  const open = useMutation({
    mutationFn: () => post('/api/incidents', { agent_id: agent.agent_id, ttl_seconds: ttl, reason: reason.trim() }),
    onSuccess: () => {
      toast(`Capture open for ${agent.name || agent.agent_id}. The agent starts sealing within seconds.`)
      qc.invalidateQueries({ queryKey: ['incidents'] })
      onClose()
    },
    onError: (e: Error) => toast(e.message, 'error'),
  })

  return (
    <Modal open onClose={onClose} title={`Open an incident capture · ${agent.name || agent.agent_id}`}>
      <div className="space-y-4 text-[13px]">
        <p className="text-dim">
          Spans keep being masked everywhere. In addition, the original sensitive values this agent handles are
          sealed with the incident&apos;s public key. Only a human admin, with a stated reason, can reopen them, and
          every access is written to the audit trail. Everything is destroyed when the timer ends.
        </p>
        <label className="block">
          <span className="mb-1 block text-faint">Why is this capture needed? (recorded in the audit trail)</span>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            maxLength={500}
            className="w-full rounded-md border border-line bg-ink p-2 text-paper outline-none focus:border-amber"
            placeholder="e.g. Investigating suspected customer-data leak, ticket SEC-142"
          />
          <span className="text-faint">
            {reason.trim().length}/{cfg.min_reason_length} characters minimum
          </span>
        </label>
        <label className="block">
          <span className="mb-1 block text-faint">Keep evidence for</span>
          <select
            value={ttl}
            onChange={(e) => setTtl(Number(e.target.value))}
            className="rounded-md border border-line bg-ink px-2 py-1.5 text-paper"
          >
            {options.map((d) => (
              <option key={d.seconds} value={d.seconds}>
                {d.label}
              </option>
            ))}
          </select>
        </label>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={tooShort || open.isPending} onClick={() => open.mutate()}>
            {open.isPending ? 'Opening…' : 'Open capture'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}

function IncidentRow({
  incident,
  onOpenLog,
}: {
  incident: Incident
  onOpenLog: (id: string) => void
}) {
  const toast = useToast()
  const qc = useQueryClient()
  const { armed, arm, reset } = useArm()
  const phase = phaseOf(incident)
  const meta = PHASE[phase]

  const close = useMutation({
    mutationFn: (purge: boolean) => post(`/api/incidents/${encodeURIComponent(incident.id)}/close`, { purge }),
    onSuccess: (_d, purge) => {
      toast(purge ? 'Evidence destroyed.' : 'Capture stopped. Evidence is kept until the timer ends.')
      qc.invalidateQueries({ queryKey: ['incidents'] })
    },
    onError: (e: Error) => toast(e.message, 'error'),
  })

  const destroy = () => {
    if (armed === incident.id) {
      reset()
      close.mutate(true)
    } else {
      arm(incident.id)
    }
  }

  return (
    <tr className="border-b border-line/60 align-top">
      <td className="px-4 py-2.5">
        <div className="text-paper">{incident.agent_id}</div>
        <div className="max-w-xs truncate text-[12px] text-faint" title={incident.reason || ''}>
          {incident.reason || '—'}
        </div>
      </td>
      <td className="px-4 py-2.5" style={{ color: meta.color }}>
        {meta.label}
      </td>
      <td className="num px-4 py-2.5 text-dim">{phase === 'capturing' || phase === 'stopped' ? remaining(incident.expires_at) : '—'}</td>
      <td className="num px-4 py-2.5 text-dim">{phase === 'destroyed' || phase === 'expired' ? '—' : incident.sealed_values}</td>
      <td className="px-4 py-2.5 text-dim">
        {incident.opened_by || '—'}
        <div className="text-[12px] text-faint">{ago(new Date(incident.created_at * 1000).toISOString())}</div>
      </td>
      <td className="px-4 py-2.5 text-right">
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenLog(incident.id)}>Log</Button>
          {phase === 'capturing' && (
            <Button disabled={close.isPending} onClick={() => close.mutate(false)}>
              Stop
            </Button>
          )}
          {(phase === 'capturing' || phase === 'stopped') && (
            <Button variant="danger" disabled={close.isPending} onClick={destroy}>
              {armed === incident.id ? 'Click again to destroy' : 'Destroy now'}
            </Button>
          )}
        </div>
      </td>
    </tr>
  )
}

export default function Incidents() {
  const cfgQ = useIncidentConfig()
  const cfg = cfgQ.data
  const manage = Boolean(cfg?.ready && cfg.can_manage)
  const incidentsQ = useIncidents(manage)
  const agentsQ = useAgents()
  const [target, setTarget] = useState<Agent | null>(null)
  const [logId, setLogId] = useState<string | null>(null)

  const intro = (
    <p className="max-w-2xl text-dim">
      Masking is irreversible by default: nothing sensitive is stored in clear. When you need the original values to
      investigate an incident, open a time-limited capture for one agent. Values are sealed with a key the agent
      cannot use to decrypt, and reopening one requires a human admin and a reason.
    </p>
  )

  if (cfgQ.isLoading) return <Skeleton className="h-24 w-full" />
  if (cfgQ.error) return <ErrorNote message={(cfgQ.error as Error).message} />
  if (!cfg?.enabled) {
    return (
      <div className="space-y-4">
        {intro}
        <Panel>
          <Empty
            title="Incident capture is off"
            text="Set AGENTGUARD_INCIDENT_ENABLED=true and AGENTGUARD_INCIDENT_MASTER_KEY (32 bytes, hex) on the collector, then restart it. See docs/EVIDENCE_RECOVERY.md."
          />
        </Panel>
      </div>
    )
  }
  if (!cfg.ready) {
    return (
      <div className="space-y-4">
        {intro}
        <ErrorNote message="Incident capture is enabled but the master key is missing or invalid. It stays unavailable until AGENTGUARD_INCIDENT_MASTER_KEY is a valid 64-character hex string." />
      </div>
    )
  }
  if (!cfg.can_manage) {
    return (
      <div className="space-y-4">
        {intro}
        <Panel>
          <Empty title="Admin role required" text="Only organization admins can open captures or reopen sealed values." />
        </Panel>
      </div>
    )
  }

  const agents = agentsQ.data?.agents || []
  const incidents = incidentsQ.data?.incidents || []
  const logIncident = incidents.find((i) => i.id === logId)
  const live = new Set(incidents.filter((i) => phaseOf(i) === 'capturing').map((i) => i.agent_id))

  return (
    <div className="space-y-4">
      {intro}
      {incidentsQ.error && <ErrorNote message={(incidentsQ.error as Error).message} />}

      <Panel title="Start a capture">
        {agentsQ.isLoading ? (
          <Skeleton className="m-4 h-16" />
        ) : agents.length === 0 ? (
          <Empty title="No agent observed yet" text="Agents appear here once they have sent telemetry." />
        ) : (
          <ul>
            {agents.map((a) => (
              <li
                key={a.agent_id}
                className="flex flex-wrap items-center justify-between gap-3 border-b border-line/60 px-4 py-3 text-[13px] last:border-0"
              >
                <div>
                  <div className="text-paper">{a.name || a.agent_id}</div>
                  <div className="text-faint">
                    {a.agent_id} · {a.state}
                  </div>
                </div>
                <Button disabled={live.has(a.agent_id)} onClick={() => setTarget(a)}>
                  {live.has(a.agent_id) ? 'Capture in progress' : 'Open capture'}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Incidents">
        {incidentsQ.isLoading ? (
          <Skeleton className="m-4 h-16" />
        ) : incidents.length === 0 ? (
          <Empty title="No incident yet" text="Opened captures and their remaining time appear here." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-[13px]">
              <thead className="text-[12.5px] text-faint">
                <tr className="border-b border-line">
                  {['Agent', 'Status', 'Time left', 'Sealed values', 'Opened by', ''].map((h) => (
                    <th key={h} className="px-4 py-2 font-normal">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {incidents.map((i) => (
                  <IncidentRow key={i.id} incident={i} onOpenLog={setLogId} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {target && <OpenCaptureModal agent={target} cfg={cfg} onClose={() => setTarget(null)} />}
      {logIncident && <IncidentLogModal incident={logIncident} onClose={() => setLogId(null)} />}
    </div>
  )
}
