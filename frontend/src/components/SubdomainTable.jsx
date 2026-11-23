import { useMemo, useState } from 'react'
import { ArrowUpDown, Lock, LockOpen, Search, ServerCrash } from 'lucide-react'
import { SEVERITIES } from '../lib/format'
import { GradeBadge, SeverityBadge } from './Badges'

const SORTS = {
  score: (a, b) => (a.score ?? -1) - (b.score ?? -1),
  name: (a, b) => a.subdomain.localeCompare(b.subdomain),
  findings: (a, b) => b.findings.length - a.findings.length,
}

export default function SubdomainTable({ audit, onSelect }) {
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState('score')

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return audit.subdomains.filter((s) => !q || s.subdomain.includes(q)).sort(SORTS[sort])
  }, [audit, query, sort])

  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-800 px-4 py-3">
        <div className="panel-title mr-auto">{audit.subdomains.length} subdomains</div>
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-slate-500" />
          <input className="input w-56 pl-8" placeholder="Filter hosts…" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
        <div className="flex items-center gap-1 text-xs text-slate-400">
          <ArrowUpDown className="h-3.5 w-3.5" />
          {Object.keys(SORTS).map((key) => (
            <button key={key} onClick={() => setSort(key)}
              className={`rounded-md px-2 py-1 capitalize ${sort === key ? 'bg-ink-700 text-accent-300' : 'hover:text-slate-200'}`}>
              {key}
            </button>
          ))}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[880px] text-sm">
          <thead className="bg-ink-850/60 text-left text-xs font-medium text-slate-500">
            <tr>
              <th className="px-4 py-2.5 font-medium">Subdomain</th>
              <th className="px-3 py-2.5 font-medium">Grade</th>
              <th className="px-3 py-2.5 text-right font-medium">Score</th>
              <th className="px-3 py-2.5 font-medium">HTTP</th>
              <th className="px-3 py-2.5 font-medium">TLS</th>
              <th className="px-3 py-2.5 font-medium">Certificate</th>
              <th className="px-4 py-2.5 font-medium">Findings</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.map((s) => {
              const tls = s.tls
              const certOk = tls && !tls.error && tls.trusted !== false && tls.hostname_match !== false && (tls.days_to_expiry ?? 0) >= 0
              return (
                <tr key={s.subdomain} onClick={() => onSelect(s.subdomain)} className="cursor-pointer hover:bg-ink-800/50">
                  <td className="px-4 py-3">
                    <div className="font-mono text-slate-100">{s.subdomain}</div>
                    <div className="max-w-xs truncate text-[11px] text-slate-500">{s.final_url ?? s.error ?? '—'}</div>
                  </td>
                  <td className="px-3 py-3"><GradeBadge grade={s.grade} /></td>
                  <td className="px-3 py-3 text-right font-mono text-slate-200">{s.score ?? '—'}</td>
                  <td className="px-3 py-3">
                    {s.reachable ? (
                      <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                        {s.scheme === 'https' ? <Lock className="h-3.5 w-3.5 text-emerald-400" /> : <LockOpen className="h-3.5 w-3.5 text-red-400" />}
                        {s.status_code}
                        {s.https_redirect === false && <span className="text-orange-300">· no redirect</span>}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs text-slate-500"><ServerCrash className="h-3.5 w-3.5" />down</span>
                    )}
                  </td>
                  <td className="px-3 py-3 font-mono text-xs text-slate-300">
                    {tls?.protocol ?? <span className="text-slate-500">—</span>}
                    {tls?.legacy_protocols_accepted?.length > 0 && <span className="ml-1 text-red-300">+{tls.legacy_protocols_accepted.join(',')}</span>}
                  </td>
                  <td className="px-3 py-3 text-xs">
                    {!tls || tls.error ? (
                      <span className="text-slate-500">n/a</span>
                    ) : certOk ? (
                      <span className="text-emerald-300">valid · {tls.days_to_expiry}d</span>
                    ) : (
                      <span className="text-red-300">
                        {(tls.days_to_expiry ?? 0) < 0 ? 'expired' : tls.hostname_match === false ? 'mismatch' : 'untrusted'}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {SEVERITIES.filter((sev) => s.severity_counts[sev]).map((sev) => (
                        <SeverityBadge key={sev} severity={sev} count={s.severity_counts[sev]} />
                      ))}
                      {s.findings.length === 0 && <span className="text-xs text-slate-500">{s.reachable ? 'clean' : '—'}</span>}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
