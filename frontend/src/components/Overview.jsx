import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { COVERAGE_LABEL, SEVERITIES, SEVERITY_META, STATUS_META, scoreColor, shortCat } from '../lib/format'
import { usePanels } from '../lib/panels'
import { CHART } from '../lib/theme'
import { SeverityBadge, StatusBadge } from './Badges'
import ComplianceHeatmap from './ComplianceHeatmap'

const STATUS_FILL = { pass: '#10b981', warning: '#eab308', fail: '#ef4444', manual_review: '#94a3b8' }
const GRADE_TEXT = { A: 'text-emerald-300', B: 'text-lime-300', C: 'text-yellow-300', D: 'text-orange-300', F: 'text-red-300' }

function ChartTooltip({ active, payload, label, suffix = '' }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-md border border-slate-800 bg-ink-900 px-3 py-2 text-xs shadow-float">
      {label && <div className="mb-1 font-medium text-slate-100">{label}</div>}
      {payload.map((p) => (
        <div key={p.dataKey ?? p.name} className="flex items-center gap-2 text-slate-300">
          <span className="h-2 w-2 rounded-full" style={{ background: p.payload.fill ?? p.color }} />
          {p.payload.tooltipName ?? p.name}: <span className="font-mono text-slate-100">{p.value}{suffix}</span>
        </div>
      ))}
    </div>
  )
}

function verdict(summary, highCrit, hostsWithHigh) {
  if (summary.subdomains_reachable === 0) return 'No host answered, so nothing could be graded.'
  if (highCrit > 0) {
    return `${highCrit} high or critical finding${highCrit === 1 ? '' : 's'} on ${hostsWithHigh} host${hostsWithHigh === 1 ? '' : 's'}. Start there.`
  }
  if (summary.total_findings === 0) return 'No issues found on any reachable host.'
  return 'Nothing high or critical. The remaining findings are hardening work.'
}

function SeverityRibbon({ counts, total }) {
  if (!total) return <div className="h-2.5 rounded-full bg-ink-700" />
  return (
    <div>
      <div className="flex h-2.5 gap-0.5 overflow-hidden rounded-full" role="img"
        aria-label={SEVERITIES.map((s) => `${counts[s] ?? 0} ${s}`).join(', ')}>
        {SEVERITIES.filter((s) => counts[s]).map((s) => (
          <div key={s} style={{ flexGrow: counts[s], background: SEVERITY_META[s].color }} title={`${SEVERITY_META[s].label}: ${counts[s]}`} />
        ))}
      </div>
      <dl className="mt-3 flex flex-wrap gap-x-6 gap-y-2">
        {SEVERITIES.map((s) => (
          <div key={s} className="flex items-baseline gap-2">
            <span className="h-2 w-2 self-center rounded-sm" style={{ background: SEVERITY_META[s].color }} />
            <dt className="text-[13px] text-slate-400">{SEVERITY_META[s].label}</dt>
            <dd className={`font-mono text-[13px] ${counts[s] ? 'text-slate-100' : 'text-slate-500'}`}>{counts[s] ?? 0}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

function Verdict({ audit, highCrit }) {
  const { summary } = audit
  const counts = summary.severity_counts ?? {}
  const hostsWithHigh = audit.subdomains.filter((s) => s.findings.some((f) => f.severity === 'high' || f.severity === 'critical')).length
  const distinct = new Set(audit.subdomains.flatMap((s) => s.findings.map((f) => f.rule_id))).size
  const unreachable = summary.subdomains_total - summary.subdomains_reachable
  const stats = [
    { label: 'Hosts graded', value: `${summary.subdomains_reachable} of ${summary.subdomains_total}`, sub: unreachable ? `${unreachable} unreachable` : 'all reachable' },
    { label: 'Findings', value: summary.total_findings, sub: `${distinct} distinct rules` },
    { label: 'Awaiting re-test', value: summary.total_retest ?? 0, sub: 'below the agreement threshold' },
    { label: 'Categories failing', value: summary.categories.filter((c) => c.status === 'fail').length, sub: `of ${summary.categories.length} OWASP categories` },
  ]
  return (
    <section className="panel" aria-label="Audit verdict">
      <div className="grid gap-8 p-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center md:p-8">
        <div className="flex items-end gap-4">
          <span className={`text-[112px] font-semibold leading-[0.8] tracking-tighter ${GRADE_TEXT[summary.grade] ?? 'text-slate-400'}`}>
            {summary.grade}
          </span>
          <div className="pb-1">
            <div className="font-mono text-2xl text-slate-100">{summary.overall_score ?? '—'}<span className="text-slate-500">/100</span></div>
            <div className="text-xs text-slate-500">mean host score</div>
          </div>
        </div>
        <div className="min-w-0">
          <p className="max-w-[60ch] text-lg font-medium leading-snug text-slate-100">{verdict(summary, highCrit, hostsWithHigh)}</p>
          <div className="mt-5"><SeverityRibbon counts={counts} total={summary.total_findings} /></div>
        </div>
      </div>
      <dl className="grid grid-cols-2 border-t border-slate-800 lg:grid-cols-4">
        {stats.map((st, i) => (
          <div key={st.label} className={`px-6 py-4 md:px-8 ${i % 2 ? 'border-l border-slate-800' : ''} ${i >= 2 ? 'border-t border-slate-800 lg:border-t-0' : ''} ${i === 2 ? 'lg:border-l' : ''}`}>
            <dt className="text-xs text-slate-500">{st.label}</dt>
            <dd className="mt-1 font-mono text-xl text-slate-100">{st.value}</dd>
            <dd className="text-xs text-slate-500">{st.sub}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

export default function Overview({ audit, onSelectSubdomain }) {
  const { summary } = audit
  const { openIssue, openCategory } = usePanels()
  const counts = summary.severity_counts ?? {}
  const highCrit = (counts.high ?? 0) + (counts.critical ?? 0)

  const categoryData = summary.categories.map((c) => ({
    name: shortCat(c.id),
    id: c.id,
    tooltipName: c.name,
    value: c.finding_count,
    fill: STATUS_FILL[c.status],
  }))

  const subdomainData = [...audit.subdomains]
    .sort((a, b) => (a.score ?? -1) - (b.score ?? -1))
    .map((s) => ({ name: s.subdomain, value: s.score ?? 0, fill: scoreColor(s.score), tooltipName: 'Score' }))

  return (
    <div className="space-y-6">
      <Verdict audit={audit} highCrit={highCrit} />

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="panel p-5">
          <h2 className="panel-title">Findings per OWASP category</h2>
          <p className="mt-0.5 text-xs text-slate-500">Bar colour is the category's status. Select a bar for details.</p>
          <div className="mt-4 h-56">
            <ResponsiveContainer>
              <BarChart data={categoryData} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
                <CartesianGrid stroke={CHART.grid} vertical={false} />
                <XAxis dataKey="name" tick={{ fill: CHART.tick, fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: CHART.tickMuted, fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: CHART.cursor }} />
                <Bar dataKey="value" name="Findings" radius={[3, 3, 0, 0]} maxBarSize={36} isAnimationActive={false}
                  onClick={(d) => openCategory(d.id)} className="cursor-pointer">
                  {categoryData.map((d) => <Cell key={d.name} fill={d.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-400">
            {Object.entries(STATUS_META).map(([key, meta]) => (
              <span key={key} className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-sm" style={{ background: STATUS_FILL[key] }} />{meta.label}
              </span>
            ))}
          </div>
        </div>

        <div className="panel p-5">
          <h2 className="panel-title">Score by host</h2>
          <p className="mt-0.5 text-xs text-slate-500">Lowest first. Select a host to open it.</p>
          <div className="mt-4 h-56">
            <ResponsiveContainer>
              <BarChart data={subdomainData} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={CHART.grid} horizontal={false} />
                <XAxis type="number" domain={[0, 100]} tick={{ fill: CHART.tickMuted, fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={168} tick={{ fill: CHART.tick, fontSize: 11, fontFamily: 'IBM Plex Mono' }} axisLine={false} tickLine={false}
                  tickFormatter={(v) => (v.length > 21 ? `${v.slice(0, 20)}…` : v)} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: CHART.cursor }} />
                <Bar dataKey="value" name="Score" radius={[0, 3, 3, 0]} maxBarSize={18} isAnimationActive={false}
                  onClick={(d) => onSelectSubdomain(d.name)} className="cursor-pointer">
                  {subdomainData.map((d) => <Cell key={d.name} fill={d.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <ComplianceHeatmap audit={audit} onSelectSubdomain={onSelectSubdomain} />

      <div className="grid gap-6 xl:grid-cols-2">
        <div className="panel overflow-hidden">
          <h2 className="panel-title border-b border-slate-800 px-5 py-3.5">OWASP Top 10 (2025) compliance</h2>
          <table className="w-full text-sm">
            <tbody className="divide-y divide-slate-800">
              {summary.categories.map((c) => (
                <tr key={c.id} onClick={() => openCategory(c.id)} className="cursor-pointer hover:bg-ink-800/60">
                  <td className="px-5 py-2.5">
                    <div className="font-medium text-slate-100"><span className="mr-1.5 font-mono text-slate-500">{shortCat(c.id)}</span>{c.name}</div>
                    <div className="text-[11px] text-slate-500">Coverage: {COVERAGE_LABEL[c.coverage] ?? c.coverage}</div>
                  </td>
                  <td className="whitespace-nowrap px-2 py-2.5 text-right font-mono text-xs text-slate-400">
                    {c.pass_rate !== null && c.pass_rate !== undefined ? `${Math.round(c.pass_rate * 100)}% pass` : '—'}
                  </td>
                  <td className="px-2 py-2.5 text-right font-mono text-xs text-slate-300">{c.finding_count}</td>
                  <td className="px-5 py-2.5 text-right"><StatusBadge status={c.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel overflow-hidden">
          <h2 className="panel-title border-b border-slate-800 px-5 py-3.5">Most significant issues</h2>
          {summary.top_rules.length === 0 ? (
            <p className="p-5 text-[13px] text-slate-400">No issues found on any reachable host.</p>
          ) : (
            <table className="w-full text-sm">
              <tbody className="divide-y divide-slate-800">
                {summary.top_rules.map((r) => (
                  <tr key={r.rule_id} onClick={() => openIssue(r.rule_id)} className="cursor-pointer hover:bg-ink-800/60">
                    <td className="px-5 py-2.5"><SeverityBadge severity={r.severity} /></td>
                    <td className="py-2.5 pr-2">
                      <div className="text-slate-100">{r.title}</div>
                      <div className="font-mono text-[11px] text-slate-500">{r.rule_id}</div>
                    </td>
                    <td className="whitespace-nowrap px-5 py-2.5 text-right text-xs text-slate-400">
                      <span className="font-mono text-slate-200">{r.count}</span> on {r.subdomains} host{r.subdomains === 1 ? '' : 's'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
