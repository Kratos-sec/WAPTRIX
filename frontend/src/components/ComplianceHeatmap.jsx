import { STATUS_META, shortCat } from '../lib/format'
import { usePanels } from '../lib/panels'
import { GradeBadge } from './Badges'

export default function ComplianceHeatmap({ audit, onSelectSubdomain }) {
  const cats = audit.summary.categories
  const { openCategory } = usePanels()
  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-5 py-3.5">
        <div>
          <h2 className="panel-title">Host compliance matrix</h2>
          <p className="mt-0.5 text-xs text-slate-500">Each cell is one host against one OWASP Top 10 (2025) category. Select a cell to see why.</p>
        </div>
        <div className="flex flex-wrap gap-3 text-xs text-slate-400">
          {Object.entries(STATUS_META).map(([key, meta]) => (
            <span key={key} className="inline-flex items-center gap-1.5"><span className={`h-2.5 w-2.5 rounded-sm ${meta.dot}`} />{meta.label}</span>
          ))}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[860px] border-separate border-spacing-[3px] px-3 py-2 text-xs">
          <thead>
            <tr>
              <th className="px-2 py-1 text-left font-medium text-slate-400">Subdomain</th>
              <th className="px-2 py-1 font-medium text-slate-400">Grade</th>
              {cats.map((c) => (
                <th key={c.id} className="px-1 py-1 font-mono font-medium text-slate-400">
                  <button onClick={() => openCategory(c.id)} title={`About ${c.id} ${c.name}`} className="w-full hover:text-accent-300">
                    {shortCat(c.id)}
                    <div className="truncate font-sans text-[9px] font-normal text-slate-500">{c.name.split(' ').slice(0, 2).join(' ')}</div>
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {audit.subdomains.map((s) => (
              <tr key={s.subdomain} className="group">
                <td className="whitespace-nowrap px-2 py-1">
                  <button onClick={() => onSelectSubdomain(s.subdomain)} className="text-left font-mono text-slate-200 hover:text-accent-300">
                    {s.subdomain}
                  </button>
                  <div className="text-[10px] text-slate-500">{s.reachable ? `${s.score}/100 · ${s.findings.length} findings` : 'unreachable'}</div>
                </td>
                <td className="px-2 py-1 text-center"><GradeBadge grade={s.grade} size="sm" /></td>
                {s.categories.map((c) => {
                  const meta = STATUS_META[c.status]
                  return (
                    <td key={c.id} className="p-0">
                      <button
                        onClick={() => onSelectSubdomain(s.subdomain, c.id)}
                        title={`${s.subdomain} · ${c.id} ${c.name}: ${meta.label}${c.finding_count ? ` (${c.finding_count} findings: ${c.rule_ids.join(', ')})` : ''}`}
                        className={`flex h-9 w-full flex-col items-center justify-center rounded ring-1 ring-inset transition-shadow hover:ring-2 ${meta.cell}`}
                      >
                        {c.finding_count > 0 ? <span className="font-mono text-[12px] font-medium">{c.finding_count}</span> : <span className="sr-only">{meta.label}</span>}
                      </button>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
