import { useEffect, useRef, type ReactNode } from 'react'
import { X } from 'lucide-react'

const FOCUSABLE = 'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'

export function Modal({
  open,
  onClose,
  title,
  children,
  wide = false,
}: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  /** Fenêtre large pour les journaux (max-w-6xl, 92 % de la hauteur). */
  wide?: boolean
}) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const previous = document.activeElement as HTMLElement | null
    ref.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        // Une modale imbriquée (ex. le formulaire « Reveal » dans un journal)
        // garde la main : Échap ne ferme que la plus interne.
        if (ref.current?.querySelector('[role="dialog"]')) return
        e.stopPropagation()
        onClose()
        return
      }
      if (e.key !== 'Tab' || !ref.current) return
      const items = Array.from(ref.current.querySelectorAll<HTMLElement>(FOCUSABLE))
      if (!items.length) return
      const first = items[0]
      const last = items[items.length - 1]
      if (e.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => {
      window.removeEventListener('keydown', onKey, true)
      previous?.focus?.()
    }
  }, [open, onClose])

  if (!open) return null
  return (
    <div className={`fixed inset-0 z-[65] flex items-start justify-center px-3 ${wide ? 'pt-[4vh]' : 'pt-[10vh]'}`}>
      <button aria-label="Close" tabIndex={-1} className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        className={`relative w-full overflow-y-auto rounded-xl border border-line bg-coal shadow-2xl ${
          wide ? 'max-h-[92vh] max-w-6xl' : 'max-h-[80vh] max-w-xl'
        }`}
      >
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-line bg-coal px-5 py-4">
          <h2 className="font-display text-[18px] font-medium">{title}</h2>
          <button aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-dim hover:bg-lift hover:text-paper">
            <X size={18} />
          </button>
        </header>
        <div className="px-5 py-4">{children}</div>
      </div>
    </div>
  )
}