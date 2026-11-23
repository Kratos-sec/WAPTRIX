import { useEffect } from 'react'
import { ArrowLeft, X } from 'lucide-react'

export function Section({ title, children, right }) {
  return (
    <section className="rounded-lg border border-slate-800 bg-ink-900 p-4">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="panel-title">{title}</h3>
        {right}
      </div>
      {children}
    </section>
  )
}

export function KV({ label, children }) {
  return (
    <div className="grid grid-cols-[9rem_minmax(0,1fr)] gap-3 py-1.5 text-xs">
      <dt className="text-slate-500">{label}</dt>
      <dd className="break-words font-mono text-slate-200">{children ?? '—'}</dd>
    </div>
  )
}

export default function Drawer({ label, onClose, onBack, header, children }) {
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/30" onClick={onClose}>
      <aside
        className="flex h-full w-full max-w-4xl flex-col border-l border-slate-800 bg-ink-950 shadow-float animate-[drawer-in_180ms_ease-out]"
        onClick={(e) => e.stopPropagation()}
        aria-label={label}
      >
        <header className="flex flex-wrap items-center gap-4 border-b border-slate-800 px-6 py-4">
          {onBack && (
            <button className="btn-ghost p-2" onClick={onBack} aria-label="Back"><ArrowLeft className="h-4 w-4" /></button>
          )}
          {header}
          <button className="btn-ghost p-2" onClick={onClose} aria-label="Close"><X className="h-4 w-4" /></button>
        </header>
        <div className="flex-1 space-y-4 overflow-y-auto px-6 py-5">{children}</div>
      </aside>
    </div>
  )
}
