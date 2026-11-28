import { useState } from 'react'
import { Copy } from 'lucide-react'
import { INTEGRATIONS } from '../../lib/integrations'
import { Button, useToast } from '../../components/ui'

export default function Connect() {
  const [id, setId] = useState(INTEGRATIONS[0].id)
  const toast = useToast()
  const current = INTEGRATIONS.find((i) => i.id === id) || INTEGRATIONS[0]
  // L'URL du collector est déjà connue : on la remplit. La clé reste à coller.
  const code = current.code.replace(/https:\/\/YOUR_AGENTGUARD_HOST/g, window.location.origin)

  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-dim">
        Pick how your agent runs. The collector address is filled in for you; replace YOUR_AGENTGUARD_API_KEY with a key from the API keys tab.
      </p>
      <div role="tablist" aria-label="Integrations" className="flex flex-wrap gap-1">
        {INTEGRATIONS.map((i) => (
          <button
            key={i.id}
            role="tab"
            aria-selected={id === i.id}
            onClick={() => setId(i.id)}
            className={`rounded-md border px-3 py-1.5 text-[13px] ${id === i.id ? 'border-amber/60 bg-lift text-paper' : 'border-line text-dim hover:text-paper'}`}
          >
            {i.title}
          </button>
        ))}
      </div>
      <section className="rounded-lg border border-line bg-coal p-4" role="tabpanel">
        <h2 className="font-display text-[16px]">{current.title}</h2>
        <p className="mt-1 text-dim">{current.description}</p>
        <div className="relative mt-3">
          <pre className="max-h-[420px] overflow-auto rounded-md border border-line bg-ink p-4 pr-24 font-mono text-[12.5px] leading-5 whitespace-pre-wrap break-words">{code}</pre>
          <Button
            className="absolute top-2 right-2"
            onClick={() => {
              navigator.clipboard?.writeText(code)
              toast('Snippet copied')
            }}
          >
            <Copy size={13} /> Copy
          </Button>
        </div>
        <p className="mt-3 text-[13px] text-dim">
          <span className="text-paper">Next:</span> run it from your server, send one real event, then open the Live feed to see it arrive.
        </p>
      </section>
      <section className="rounded-lg border border-line bg-coal p-4">
        <h2 className="font-display text-[15px]">Security coverage and limitations</h2>
        <p className="mt-1 text-[13px] text-dim">
          Integration snippets only protect execution paths routed through the selected SDK, hook, or MCP gateway. Advanced primitives such as data contracts, delegation, and egress checks have implementation-specific limits and are not all configurable from this screen.
        </p>
        <a
          className="mt-2 inline-block text-[13px] text-amber hover:underline"
          href="https://github.com/chrismsmr-celcom/cerbere-AG/blob/main/docs/SECURITY_PRIMITIVES.md"
          target="_blank"
          rel="noreferrer"
        >
          Read the security primitive reference
        </a>
      </section>
    </div>
  )
}
