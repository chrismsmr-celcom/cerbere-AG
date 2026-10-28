import { useEffect, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

/** Fenêtre large (jusqu'à 72 rem, 92 % de la hauteur) pour les journaux.
 *  - Échap ferme, clic sur le fond ferme, le défilement de la page est bloqué.
 *  - Échap est ignoré quand le focus est dans une modale imbriquée
 *    (ex. le formulaire « Reveal »), pour ne pas tout fermer d'un coup. */
export function WideModal({
  title,
  onClose,
  children,
}: {
  title: string
  onClose: () => void
  children: ReactNode
}) {
  const box = useRef<HTMLDivElement>(null)
  const closeRef = useRef(onClose)
  closeRef.current = onClose // l'effet ne dépend pas de l'identité de onClose

  useEffect(() => {
    box.current?.focus()
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && box.current?.contains(document.activeElement)) closeRef.current()
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prevOverflow
    }
  }, [])

  return createPortal(
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-3 sm:p-6"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) closeRef.current()
      }}
    >
      <div
        ref={box}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="flex max-h-[92vh] w-full max-w-6xl flex-col rounded-lg border border-line bg-slab shadow-2xl outline-none"
      >
        <div className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h2 className="truncate text-[15px] text-paper">{title}</h2>
          <button
            type="button"
            onClick={() => closeRef.current()}
            aria-label="Close"
            className="rounded-md px-2 py-1 text-dim hover:text-paper"
          >
            ✕
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-5">{children}</div>
      </div>
    </div>,
    document.body,
  )
}
