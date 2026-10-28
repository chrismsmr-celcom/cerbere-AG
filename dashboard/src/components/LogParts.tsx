export const clock = (t: number) => new Date(t * 1000).toLocaleTimeString([], { hour12: false })

/** JSON joliment indenté ; si le texte est tronqué (donc invalide), on l'affiche tel quel. */
export function pretty(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2)
  } catch {
    return body
  }
}

export function PrettyBlock({ label, body }: { label: string; body: string }) {
  return (
    <div className="min-w-0">
      <div className="mb-1 text-faint">{label}</div>
      <pre className="max-h-[28vh] overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-ink p-2 text-[12px] text-dim">
        {pretty(body)}
      </pre>
    </div>
  )
}

export function FilterChip({
  active,
  onClick,
  label,
  n,
}: {
  active: boolean
  onClick: () => void
  label: string
  n: number
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-md border px-2.5 py-1 text-[12.5px] ${
        active ? 'border-amber text-paper' : 'border-line text-dim hover:text-paper'
      }`}
    >
      {label} <span className="num text-faint">{n}</span>
    </button>
  )
}