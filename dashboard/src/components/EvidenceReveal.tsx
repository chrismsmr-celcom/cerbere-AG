import { useEffect, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { post } from '../lib/api'
import { extractTokens, useAvailableTokens, useIncidentConfig } from '../lib/incidents'
import { Button, ErrorNote, useToast } from './ui'
import { Modal } from './Modal'

const SHOW_SECONDS = 20

interface Revealed {
  token: string
  value: string
}

/** Affiche, sous un span, les valeurs masquées dont une preuve scellée existe
 * encore, avec un bouton « Reveal » (motif obligatoire, audité côté serveur).
 * N'affiche rien si la fonctionnalité est off, si l'utilisateur n'est pas admin
 * ou s'il n'y a aucune preuve disponible pour ce span. */
export function EvidenceReveal({ text }: { text: string }) {
  const cfgQ = useIncidentConfig()
  const cfg = cfgQ.data
  const allowed = Boolean(cfg?.ready && cfg.can_manage)
  const tokens = allowed ? extractTokens(text) : []
  const availableQ = useAvailableTokens(tokens, allowed)
  const available = availableQ.data?.available || []

  const [pending, setPending] = useState<string | null>(null)
  const [reason, setReason] = useState('')
  const [shown, setShown] = useState<(Revealed & { until: number }) | null>(null)
  const [now, setNow] = useState(Date.now())
  const toast = useToast()
  const minReason = cfg?.min_reason_length ?? 10

  useEffect(() => {
    if (!shown) return
    const t = window.setInterval(() => {
      setNow(Date.now())
      if (Date.now() >= shown.until) setShown(null)
    }, 500)
    return () => window.clearInterval(t)
  }, [shown])

  // Une valeur révélée ne survit pas à un changement de span.
  useEffect(() => {
    setShown(null)
    setPending(null)
    setReason('')
  }, [text])

  const reveal = useMutation({
    mutationFn: (token: string) => post<Revealed>('/api/incidents/reveal', { token, reason: reason.trim() }),
    onSuccess: (d) => {
      setShown({ token: d.token, value: d.value, until: Date.now() + SHOW_SECONDS * 1000 })
      setPending(null)
      setReason('')
    },
    onError: (e: Error) => toast(e.message, 'error'),
  })

  if (!allowed || available.length === 0) return null

  return (
    <div className="rounded-md border border-amber/40 bg-slab px-3 py-2.5 text-[13px]">
      <div className="mb-1.5 text-paper">
        Sealed evidence · {available.length} masked value{available.length > 1 ? 's' : ''} can be reopened
      </div>
      <ul className="space-y-1.5">
        {available.map((t) => (
          <li key={t} className="flex flex-wrap items-center justify-between gap-2">
            <code className="font-mono text-[12px] text-dim">{t}</code>
            <Button disabled={reveal.isPending} onClick={() => setPending(t)} aria-label={`Reveal ${t}`}>
              Reveal
            </Button>
          </li>
        ))}
      </ul>

      {shown && (
        <div role="status" className="mt-3 rounded-md border border-line bg-ink p-2.5">
          <div className="mb-1 text-[12px] text-faint">
            Hidden again in {Math.max(0, Math.ceil((shown.until - now) / 1000))}s · this access was audited
          </div>
          <pre className="font-mono text-[12.5px] break-all whitespace-pre-wrap text-paper">{shown.value}</pre>
          <Button className="mt-2" onClick={() => setShown(null)}>
            Hide now
          </Button>
        </div>
      )}

      {pending && (
        <Modal open onClose={() => setPending(null)} title="Reveal a sealed value">
          <div className="space-y-3 text-[13px]">
            <p className="text-dim">
              This reopens the original value behind <code className="font-mono">{pending}</code>. Your identity and the
              reason below are written to the audit trail.
            </p>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={2}
              maxLength={500}
              className="w-full rounded-md border border-line bg-ink p-2 text-paper outline-none focus:border-amber"
              placeholder="Reason (e.g. legal request ref 4521)"
              aria-label="Reason for revealing"
            />
            {reveal.error && <ErrorNote message={(reveal.error as Error).message} />}
            <div className="flex justify-end gap-2">
              <Button onClick={() => setPending(null)}>Cancel</Button>
              <Button
                variant="primary"
                disabled={reason.trim().length < minReason || reveal.isPending}
                onClick={() => reveal.mutate(pending)}
              >
                {reveal.isPending ? 'Revealing…' : 'Reveal value'}
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
