import { useEffect, useRef, useState } from 'react'
import { Braces, ChevronDown, Download, FileCode2, FileSpreadsheet, FileText, Globe, Loader2 } from 'lucide-react'
import { downloadExport } from '../lib/api'

const OPTIONS = [
  { format: 'pdf', label: 'PDF report', icon: FileText },
  { format: 'html', label: 'HTML report', icon: Globe },
  { format: 'json', label: 'JSON (full data)', icon: Braces },
  { format: 'csv', label: 'CSV (findings)', icon: FileSpreadsheet },
  { format: 'sarif', label: 'SARIF 2.1.0', icon: FileCode2 },
]

export default function ExportMenu({ auditId, subdomain, label = 'Export', onNotify, align = 'right' }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(null)
  const ref = useRef(null)

  useEffect(() => {
    const close = (e) => ref.current && !ref.current.contains(e.target) && setOpen(false)
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])

  async function run(format) {
    setBusy(format)
    try {
      const { filename, fallback } = await downloadExport(auditId, format, subdomain)
      onNotify?.({ type: fallback ? 'warning' : 'success', message: fallback ? `${filename}: ${fallback}` : `Downloaded ${filename}` })
      setOpen(false)
    } catch (err) {
      onNotify?.({ type: 'error', message: `Export failed: ${err.message}` })
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="relative" ref={ref}>
      <button className="btn-ghost" onClick={() => setOpen((o) => !o)} aria-haspopup="menu" aria-expanded={open}>
        <Download className="h-4 w-4" />
        {label}
        <ChevronDown className="h-3.5 w-3.5 opacity-60" />
      </button>
      {open && (
        <div role="menu" className={`absolute z-30 mt-2 w-56 overflow-hidden rounded-lg border border-slate-700 bg-ink-850 py-1 shadow-float ${align === 'right' ? 'right-0' : 'left-0'}`}>
          <div className="px-3 py-1.5 text-xs font-medium text-slate-500">
            {subdomain ? `Subdomain: ${subdomain}` : 'Full engagement'}
          </div>
          {OPTIONS.map(({ format, label: text, icon: Icon }) => (
            <button key={format} role="menuitem" onClick={() => run(format)} disabled={busy !== null}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-slate-200 hover:bg-ink-700 disabled:opacity-50">
              {busy === format ? <Loader2 className="h-4 w-4 animate-spin" /> : <Icon className="h-4 w-4 text-accent-300" />}
              {text}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
