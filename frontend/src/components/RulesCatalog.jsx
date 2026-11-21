import { useEffect, useMemo, useState } from 'react'
import { Loader2, Search } from 'lucide-react'
import { api } from '../lib/api'
import { SeverityBadge } from './Badges'

export default function RulesCatalog() {
  const [rules, setRules] = useState(null)
  const [error, setError] = useState(null)
  const [query, setQuery] = useState('')

  useEffect(() => {
    api.rules().then(setRules).catch((e) => setError(e.message))
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (rules ?? []).filter((r) => !q || [r.id, r.title, r.cwe, r.wstg, r.check, ...r.owasp].some((v) => v?.toLowerCase().includes(q)))
  }, [rules, query])

  if (error) return <div className="panel p-6 text-sm text-red-300">{error}</div>
  if (!rules) return <div className="panel flex items-center gap-2 p-6 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" />Loading rules…</div>

  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-800 px-4 py-3">
        <div className="panel-title mr-auto">{rules.length} passive rules · Burp-style, read-only</div>
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-slate-500" />
          <input className="input w-64 pl-8" placeholder="Filter by rule, CWE, OWASP…" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[960px] text-sm">
          <thead className="bg-ink-850/60 text-left text-[11px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2.5 font-medium">Rule</th>
              <th className="px-3 py-2.5 font-medium">Severity</th>
              <th className="px-3 py-2.5 font-medium">Module</th>
              <th className="px-3 py-2.5 font-medium">OWASP 2025</th>
              <th className="px-3 py-2.5 font-medium">CWE</th>
              <th className="px-3 py-2.5 font-medium">WSTG v4.2</th>
              <th className="px-4 py-2.5 text-right font-medium">CVSS 3.1</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {filtered.map((r) => (
              <tr key={r.id} className="align-top hover:bg-ink-800/40">
                <td className="px-4 py-2.5">
                  <div className="text-slate-100">{r.title}</div>
                  <div className="font-mono text-[11px] text-slate-500">{r.id}</div>
                </td>
                <td className="px-3 py-2.5"><SeverityBadge severity={r.severity} /></td>
                <td className="px-3 py-2.5 font-mono text-xs text-slate-400">{r.check}</td>
                <td className="px-3 py-2.5 font-mono text-xs text-cyan-300">{r.owasp.join(', ')}</td>
                <td className="px-3 py-2.5 text-xs text-slate-300" title={r.cwe_name}>{r.cwe}</td>
                <td className="px-3 py-2.5 font-mono text-xs text-slate-300">{r.wstg ?? '—'}</td>
                <td className="px-4 py-2.5 text-right font-mono text-xs text-slate-200" title={r.cvss_vector}>{r.cvss_score.toFixed(1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
