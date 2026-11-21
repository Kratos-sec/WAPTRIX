import { STATUS_META, shortCat } from '../lib/format'
import { usePanels } from '../lib/panels'
import { GradeBadge } from './Badges'

export default function ComplianceHeatmap({ audit, onSelectSubdomain }) {
  const cats = audit.summary.categories
  const { openCategory } = usePanels()
  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-4 py-3">
        <div className="panel-title">Subdomain × OWASP Top 10 (2025) matrix</div>
        <div className="flex flex-wrap gap-2">
          {Object.entries(STATUS_META).map(([key, meta]) => (
            <span key={key} className={`chip ring-1 ${meta.cell}`}>{meta.short}</span>
          ))}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[860px] border-separate border-spacing-1 p-2 text-xs">
          <thead>
            <tr>
              <th className="px-2 py-1 text-left font-medium text-slate-400">Subdomain</th>
              <th className="px-2 py-1 font-medium text-slate-400">Grade</th>
              {cats.map((c) => (
                <th key={c.id} className="px-1 py-1 font-mono font-medium text-slate-400">
                  <button onClick={() => openCategory(c.id)} title={`About ${c.id} ${c.name}`} className="w-full hover:text-cyan-300">
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
                  <button onClick={() => onSelectSubdomain(s.subdomain)} className="text-left font-mono text-slate-200 hover:text-cyan-300">
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
                        className={`flex h-10 w-full flex-col items-center justify-center rounded-md ring-1 transition hover:brightness-125 ${meta.cell}`}
                      >
                        <span className="text-[10px] font-bold tracking-wide">{meta.short}</span>
                        {c.finding_count > 0 && <span className="font-mono text-[10px] opacity-80">{c.finding_count}</span>}
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
