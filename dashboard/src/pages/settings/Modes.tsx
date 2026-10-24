import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { get, put } from '../../lib/api'
import { Button, Empty, ErrorNote, Panel, Skeleton, useArm, useToast } from '../../components/ui'
import type { Agent, AgentsResponse } from '../../lib/api'

type Mode = 'enforce' | 'shadow'

interface ModeResponse {
  agent_id: string | null
  mode: Mode
  updated_at?: string | null
}

function ModeRow({ agent }: { agent: Agent }) {
  const toast = useToast()
  const qc = useQueryClient()
  const { armed, arm, reset } = useArm()

  const modeQ = useQuery({
    queryKey: ['agent-mode', agent.agent_id],
    queryFn: () =>
      get<ModeResponse>(`/api/agent/mode?agent_id=${encodeURIComponent(agent.agent_id)}`),
    staleTime: 5_000,
  })

  const setMode = useMutation({
    mutationFn: (mode: Mode) =>
      put(`/api/agents/${encodeURIComponent(agent.agent_id)}/mode`, { mode }),
    onSuccess: (_d, mode) => {
      qc.setQueryData(['agent-mode', agent.agent_id], (old: ModeResponse | undefined) =>
        old ? { ...old, mode } : old,
      )
      toast(`${agent.agent_id} → ${mode} (active in < 10s)`)
    },
    onError: (e: Error) => toast(e.message, 'error'),
  })

  const mode = modeQ.data?.mode || 'enforce'
  const isShadow = mode === 'shadow'

  // Bascule vers shadow = confirmation en deux clics (un shadow agent
  // exécute les actions au lieu de les bloquer : c'est une décision assumée).
  const toggle = () => {
    if (isShadow) {
      setMode.mutate('enforce')
      reset()
      return
    }
    if (armed === agent.agent_id) {
      reset()
      setMode.mutate('shadow')
    } else {
      arm(agent.agent_id)
    }
  }

  return (
    <li className="flex flex-wrap items-center justify-between gap-3 border-b border-line/60 px-4 py-3 text-[13px] last:border-0">
      <div>
        <div className="text-paper">{agent.name || agent.agent_id}</div>
        <div className="text-faint">
          {agent.agent_id} · {agent.state}
          {agent.last_seen_at ? ` · last seen ${agent.last_seen_at}` : ''}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <span
          className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${
            isShadow ? 'bg-amber-500 text-black' : 'bg-lift text-dim'
          }`}
        >
          {modeQ.isLoading ? '…' : isShadow ? 'Shadow ON' : 'Enforce'}
        </span>
        <Button
          variant={isShadow ? 'primary' : 'default'}
          disabled={setMode.isPending || modeQ.isLoading}
          onClick={toggle}
        >
          {setMode.isPending
            ? 'Saving…'
            : isShadow
              ? 'Back to enforce'
              : armed === agent.agent_id
                ? 'Confirm shadow'
                : 'Shadow mode'}
        </Button>
      </div>
    </li>
  )
}

export default function Modes() {
  const agentsQ = useQuery({
    queryKey: ['agents-modes'],
    queryFn: () => get<AgentsResponse>('/api/agents'),
  })
  const agents = agentsQ.data?.agents || []

  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-dim">
        Shadow mode lets an agent execute actions that would be blocked, while
        recording what would have happened (<code>cerbere_shadow</code> on each
        span). Server-signed DENY decisions are never bypassed. Takes effect
        within 10 seconds per agent; any network failure falls back to enforce.
      </p>
      {agentsQ.error && <ErrorNote message={(agentsQ.error as Error).message} />}

      <Panel title="Agent execution mode">
        {agentsQ.isLoading ? (
          <Skeleton className="m-4 h-16" />
        ) : agents.length === 0 ? (
          <Empty
            title="No agent observed yet"
            text="Agents appear here once they have sent telemetry (spans, traces or events)."
          />
        ) : (
          <ul>
            {agents.map((a) => (
              <ModeRow key={a.agent_id} agent={a} />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}