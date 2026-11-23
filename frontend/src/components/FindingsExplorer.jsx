import { useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { SEVERITIES, SEVERITY_META, allFindings } from '../lib/format'
import { usePanels } from '../lib/panels'
import FindingCard from './FindingCard'

const PAGE = 40
const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

export default function FindingsExplorer({ audit }) {
  const findings = useMemo(() => allFindings(audit), [audit])
  const { openIssue } = usePanels()
  const [severities, setSeverities] = useState(new Set(SEVERITIES))
  const [category, setCategory] = useState('')
  const [subdomain, setSubdomain] = useState('')
  const [query, setQuery] = useState('')
  const [groupByRule, setGroupByRule] = useState(false)
  const [limit, setLimit] = useState(PAGE)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return findings
      .filter((f) => severities.has(f.severity))
      .filter((f) => !category || f.owasp.includes(category))
      .filter((f) => !subdomain || f.subdomain === subdomain)
      .filter((f) => !q || [f.title, f.rule_id, f.evidence, f.url, f.cwe].some((v) => v?.toLowerCase().includes(q)))
      .sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.rule_id.localeCompare(b.rule_id))
  }, [findings, severities, category, subdomain, query])

  const groups = useMemo(() => {
    if (!groupByRule) return null
    const map = new Map()
    for (const f of filtered) {
      if (!map.has(f.rule_id)) map.set(f.rule_id, [])
      map.get(f.rule_id).push(f)
    }
    return [...map.entries()]
  }, [filtered, groupByRule])

  const toggle = (sev) =>
    setSeverities((prev) => {
      const next = new Set(prev)
      next.has(sev) ? next.delete(sev) : next.add(sev)
      return next
    })

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]))

  return (
    <div className="space-y-4">
      <div className="panel flex flex-wrap items-center gap-3 p-3">
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((sev) => (
            <button key={sev} onClick={() => toggle(sev)}
              className={`chip transition ${severities.has(sev) ? SEVERITY_META[sev].chip : 'bg-transparent text-slate-500 ring-1 ring-slate-700'}`}>
              {SEVERITY_META[sev].label} <span className="font-mono">{counts[sev]}</span>
            </button>
          ))}
        </div>
        <select className="input w-auto" value={category} onChange={(e) => setCategory(e.target.value)} aria-label="OWASP category">
          <option value="">All OWASP categories</option>
          {audit.summary.categories.map((c) => <option key={c.id} value={c.id}>{c.id} {c.name}</option>)}
        </select>
        <select className="input w-auto" value={subdomain} onChange={(e) => setSubdomain(e.target.value)} aria-label="Subdomain">
          <option value="">All subdomains</option>
          {audit.subdomains.map((s) => <option key={s.subdomain} value={s.subdomain}>{s.subdomain}</option>)}
        </select>
        <div className="relative min-w-[12rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-slate-500" />
          <input className="input pl-8" placeholder="Search title, rule, evidence, CWE…" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
        <label className="flex items-center gap-2 text-xs text-slate-300">
          <input type="checkbox" className="accent-accent-400" checked={groupByRule} onChange={(e) => setGroupByRule(e.target.checked)} />
          Group by rule
        </label>
      </div>

      <div className="text-xs text-slate-500">{filtered.length} of {findings.length} findings</div>

      {groups ? (
        <div className="space-y-4">
          {groups.map(([ruleId, items]) => (
            <div key={ruleId} className="panel p-3">
              <div className="mb-2 flex items-center justify-between px-1">
                <button onClick={() => openIssue(ruleId)} className="text-left text-sm font-medium text-slate-100 hover:text-accent-300">{items[0].title}</button>
                <div className="font-mono text-xs text-slate-500">{ruleId} · {items.length} on {new Set(items.map((i) => i.subdomain)).size} host(s)</div>
              </div>
              <div className="space-y-2">{items.map((f) => <FindingCard key={f.id} finding={f} showSubdomain />)}</div>
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.slice(0, limit).map((f) => <FindingCard key={f.id} finding={f} showSubdomain />)}
          {filtered.length > limit && (
            <button className="btn-ghost w-full justify-center" onClick={() => setLimit((l) => l + PAGE)}>
              Show {Math.min(PAGE, filtered.length - limit)} more
            </button>
          )}
          {filtered.length === 0 && <div className="panel p-8 text-center text-sm text-slate-400">No findings match these filters.</div>}
        </div>
      )}
    </div>
  )
}
