import { AlertTriangle, Globe2, ListChecks, ShieldCheck } from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { COVERAGE_LABEL, SEVERITIES, SEVERITY_META, STATUS_META, scoreColor, shortCat } from '../lib/format'
import { usePanels } from '../lib/panels'
import { GradeBadge, SeverityBadge, StatusBadge } from './Badges'
import ComplianceHeatmap from './ComplianceHeatmap'

const STATUS_FILL = { pass: '#34d399', warning: '#facc15', fail: '#f87171', manual_review: '#64748b' }

function ChartTooltip({ active, payload, label, suffix = '' }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-slate-700 bg-ink-850 px-3 py-2 text-xs shadow-xl">
      {label && <div className="mb-1 font-semibold text-slate-200">{label}</div>}
      {payload.map((p) => (
        <div key={p.dataKey ?? p.name} className="flex items-center gap-2 text-slate-300">
          <span className="h-2 w-2 rounded-full" style={{ background: p.payload.fill ?? p.color }} />
          {p.payload.tooltipName ?? p.name}: <span className="font-mono text-white">{p.value}{suffix}</span>
        </div>
      ))}
    </div>
  )
}

function Kpi({ icon: Icon, label, value, sub, accent = 'text-white' }) {
  return (
    <div className="panel flex items-start gap-3 p-4">
      <div className="rounded-lg bg-ink-700/70 p-2 text-cyan-300"><Icon className="h-5 w-5" /></div>
      <div className="min-w-0">
        <div className="panel-title">{label}</div>
        <div className={`mt-1 text-2xl font-bold ${accent}`}>{value}</div>
        {sub && <div className="mt-0.5 truncate text-xs text-slate-500">{sub}</div>}
      </div>
    </div>
  )
}

function ScoreGauge({ score, grade }) {
  const value = score ?? 0
  const data = [
    { name: 'score', value, fill: scoreColor(score) },
    { name: 'rest', value: 100 - value, fill: '#1c2740' },
  ]
  return (
    <div className="panel flex items-center gap-5 p-4">
      <div className="relative h-28 w-28 shrink-0">
        <ResponsiveContainer>
          <PieChart>
            <Pie data={data} dataKey="value" innerRadius="72%" outerRadius="100%" startAngle={90} endAngle={-270} stroke="none" isAnimationActive={false}>
              {data.map((d) => <Cell key={d.name} fill={d.fill} />)}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-extrabold text-white">{score ?? '—'}</span>
          <span className="text-[10px] uppercase tracking-widest text-slate-500">/ 100</span>
        </div>
      </div>
      <div>
        <div className="panel-title">Overall compliance</div>
        <div className="mt-2 flex items-center gap-3">
          <GradeBadge grade={grade} size="lg" />
          <p className="max-w-[14rem] text-xs leading-relaxed text-slate-400">
            Mean of reachable subdomain scores. Each unique rule deducts by severity.
          </p>
        </div>
      </div>
    </div>
  )
}

export default function Overview({ audit, onSelectSubdomain }) {
  const { summary } = audit
  const { openIssue, openCategory } = usePanels()
  const counts = summary.severity_counts ?? {}
  const highCrit = (counts.high ?? 0) + (counts.critical ?? 0)

  const severityData = SEVERITIES.map((s) => ({
    name: SEVERITY_META[s].label,
    value: counts[s] ?? 0,
    fill: SEVERITY_META[s].color,
  }))

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
    <div className="space-y-5">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_repeat(3,minmax(0,1fr))]">
        <ScoreGauge score={summary.overall_score} grade={summary.grade} />
        <Kpi icon={Globe2} label="Subdomains" value={`${summary.subdomains_reachable}/${summary.subdomains_total}`}
          sub={`${summary.subdomains_total - summary.subdomains_reachable} unreachable · ${audit.scope_rejections.length} rejected`} />
        <Kpi icon={ListChecks} label="Findings" value={summary.total_findings}
          sub={`${new Set(audit.subdomains.flatMap((s) => s.findings.map((f) => f.rule_id))).size} distinct rules${summary.total_retest ? ` · ${summary.total_retest} awaiting re-test` : ''}`} />
        <Kpi icon={AlertTriangle} label="High / critical" value={highCrit} accent={highCrit ? 'text-red-300' : 'text-emerald-300'}
          sub={`${counts.medium ?? 0} medium · ${counts.low ?? 0} low · ${counts.info ?? 0} info`} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="panel p-4">
          <div className="panel-title mb-3">Findings by severity</div>
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={severityData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                <CartesianGrid stroke="#1c2740" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(148,163,184,0.06)' }} />
                <Bar dataKey="value" name="Findings" radius={[5, 5, 0, 0]} isAnimationActive={false}>
                  {severityData.map((d) => <Cell key={d.name} fill={d.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel p-4">
          <div className="panel-title mb-3">Findings per OWASP Top 10 (2025) category</div>
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={categoryData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                <CartesianGrid stroke="#1c2740" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(148,163,184,0.06)' }} />
                <Bar dataKey="value" name="Findings" radius={[5, 5, 0, 0]} isAnimationActive={false}
                  onClick={(d) => openCategory(d.id)} className="cursor-pointer">
                  {categoryData.map((d) => <Cell key={d.name} fill={d.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-slate-400">
            {Object.entries(STATUS_META).map(([key, meta]) => (
              <span key={key} className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-sm" style={{ background: STATUS_FILL[key] }} />{meta.label}
              </span>
            ))}
          </div>
        </div>

        <div className="panel p-4">
          <div className="panel-title mb-3">Score by subdomain</div>
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={subdomainData} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="#1c2740" horizontal={false} />
                <XAxis type="number" domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={130} tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false}
                  tickFormatter={(v) => (v.length > 22 ? `${v.slice(0, 21)}…` : v)} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(148,163,184,0.06)' }} />
                <Bar dataKey="value" name="Score" radius={[0, 5, 5, 0]} isAnimationActive={false}
                  onClick={(d) => onSelectSubdomain(d.name)} className="cursor-pointer">
                  {subdomainData.map((d) => <Cell key={d.name} fill={d.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <ComplianceHeatmap audit={audit} onSelectSubdomain={onSelectSubdomain} />

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="panel overflow-hidden">
          <div className="panel-title border-b border-slate-800 px-4 py-3">OWASP Top 10 (2025) compliance</div>
          <table className="w-full text-sm">
            <tbody className="divide-y divide-slate-800/70">
              {summary.categories.map((c) => (
                <tr key={c.id} onClick={() => openCategory(c.id)} className="cursor-pointer hover:bg-ink-800/40">
                  <td className="px-4 py-2.5">
                    <div className="font-medium text-slate-100"><span className="font-mono text-cyan-300">{shortCat(c.id)}</span> {c.name}</div>
                    <div className="text-[11px] text-slate-500">Coverage: {COVERAGE_LABEL[c.coverage] ?? c.coverage}</div>
                  </td>
                  <td className="px-2 py-2.5 text-right font-mono text-xs text-slate-400">
                    {c.pass_rate !== null && c.pass_rate !== undefined ? `${Math.round(c.pass_rate * 100)}% pass` : '—'}
                  </td>
                  <td className="px-2 py-2.5 text-right font-mono text-xs text-slate-300">{c.finding_count}</td>
                  <td className="px-4 py-2.5 text-right"><StatusBadge status={c.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel overflow-hidden">
          <div className="panel-title flex items-center gap-2 border-b border-slate-800 px-4 py-3">
            <ShieldCheck className="h-4 w-4 text-cyan-300" /> Most significant issues
          </div>
          {summary.top_rules.length === 0 ? (
            <p className="p-6 text-sm text-slate-400">No passive issues detected.</p>
          ) : (
            <table className="w-full text-sm">
              <tbody className="divide-y divide-slate-800/70">
                {summary.top_rules.map((r) => (
                  <tr key={r.rule_id} onClick={() => openIssue(r.rule_id)} className="cursor-pointer hover:bg-ink-800/40">
                    <td className="px-4 py-2.5"><SeverityBadge severity={r.severity} /></td>
                    <td className="py-2.5 pr-2">
                      <div className="text-slate-100">{r.title}</div>
                      <div className="font-mono text-[11px] text-slate-500">{r.rule_id}</div>
                    </td>
                    <td className="px-4 py-2.5 text-right text-xs text-slate-400">
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
