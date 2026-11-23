import { useMemo } from 'react'
import { CheckCircle2 } from 'lucide-react'
import { COVERAGE_LABEL } from '../lib/format'
import { useCatalog, usePanels } from '../lib/panels'
import { GradeBadge, SeverityBadge, StatusBadge } from './Badges'
import Drawer, { Section } from './Drawer'

const COVERAGE_HELP = {
  high: 'Most of this category is visible from HTTP responses and TLS handshakes.',
  partial: 'Some controls are visible passively; the rest needs manual testing.',
  indicators: 'Only defensive indicators are visible. A clean result does not mean the category passes.',
  manual: 'Cannot be observed passively. Always needs manual review.',
}

export default function CategoryDrawer({ audit, categoryId, onClose, onBack }) {
  const { rules, categories } = useCatalog()
  const { openIssue, openSubdomain } = usePanels()
  const aggregate = audit.summary.categories.find((c) => c.id === categoryId)
  const meta = categories[categoryId] ?? {}

  const ruleRows = useMemo(() => {
    const findings = audit.subdomains.flatMap((s) => s.findings.filter((f) => f.owasp.includes(categoryId)))
    const catalogIds = Object.values(rules).filter((r) => r.owasp.includes(categoryId)).map((r) => r.id)
    const ids = [...new Set([...catalogIds, ...findings.map((f) => f.rule_id)])]
    return ids
      .map((id) => {
        const hits = findings.filter((f) => f.rule_id === id)
        return {
          id,
          title: rules[id]?.title ?? hits[0]?.title,
          severity: rules[id]?.severity ?? hits[0]?.severity,
          count: hits.length,
          hosts: new Set(hits.map((h) => h.subdomain)).size,
        }
      })
      .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
  }, [audit, rules, categoryId])

  if (!aggregate) return null
  const triggered = ruleRows.filter((r) => r.count > 0)
  const clean = ruleRows.filter((r) => r.count === 0)

  return (
    <Drawer
      label={`OWASP ${categoryId}`}
      onClose={onClose}
      onBack={onBack}
      header={
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm text-accent-300">{categoryId}</span>
            <StatusBadge status={aggregate.status} />
          </div>
          <h2 className="mt-1 text-lg font-semibold text-white">{aggregate.name}</h2>
        </div>
      }
    >
      <Section title="What this category covers">
        {meta.description && <p className="text-sm leading-relaxed text-slate-300">{meta.description}</p>}
        <p className="mt-3 text-sm leading-relaxed text-slate-400">
          <span className="text-slate-200">Passive coverage: {COVERAGE_LABEL[aggregate.coverage]}.</span>{' '}
          {COVERAGE_HELP[aggregate.coverage]}
        </p>
        {meta.passive_scope && <p className="mt-2 text-sm leading-relaxed text-slate-400">{meta.passive_scope}</p>}
        <p className="mt-3 text-xs text-slate-500">
          {aggregate.pass_rate !== null && aggregate.pass_rate !== undefined
            ? `${Math.round(aggregate.pass_rate * 100)}% of evaluated subdomains pass this category.`
            : 'No subdomain could be evaluated for this category.'}{' '}
          Fail means a medium or higher finding; warning means low findings only.
        </p>
      </Section>

      <Section title={`Subdomains (${audit.subdomains.length})`}>
        <div className="divide-y divide-slate-800">
          {audit.subdomains.map((s) => {
            const c = s.categories.find((x) => x.id === categoryId)
            return (
              <button key={s.subdomain} onClick={() => openSubdomain(s.subdomain, categoryId)}
                className="flex w-full items-center gap-3 py-2 text-left hover:bg-ink-800/60">
                <GradeBadge grade={s.grade} size="sm" />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-sm text-slate-100">{s.subdomain}</span>
                  <span className="block truncate font-mono text-[11px] text-slate-500">
                    {!s.reachable ? 'unreachable' : c.rule_ids.length ? c.rule_ids.join(', ') : 'no findings in this category'}
                  </span>
                </span>
                {c.max_severity && <SeverityBadge severity={c.max_severity} count={c.finding_count} />}
                <StatusBadge status={c.status} compact />
              </button>
            )
          })}
        </div>
      </Section>

      <Section title={`Rules evaluated (${ruleRows.length})`}>
        {triggered.length > 0 && (
          <div className="mb-3 divide-y divide-slate-800">
            {triggered.map((r) => (
              <button key={r.id} onClick={() => openIssue(r.id)} className="flex w-full items-center gap-3 py-2 text-left hover:bg-ink-800/60">
                <SeverityBadge severity={r.severity} />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm text-slate-100">{r.title}</span>
                  <span className="block font-mono text-[11px] text-slate-500">{r.id}</span>
                </span>
                <span className="text-xs text-slate-400">{r.count} on {r.hosts} host{r.hosts === 1 ? '' : 's'}</span>
              </button>
            ))}
          </div>
        )}
        {clean.length > 0 && (
          <>
            <div className="mb-1 text-xs text-slate-500">Checked and not observed on any host</div>
            <div className="divide-y divide-slate-800">
              {clean.map((r) => (
                <button key={r.id} onClick={() => openIssue(r.id)} className="flex w-full items-center gap-3 py-2 text-left hover:bg-ink-800/60">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                  <span className="flex-1 text-sm text-slate-300">{r.title}</span>
                  <span className="font-mono text-[11px] text-slate-500">{r.id}</span>
                </button>
              ))}
            </div>
          </>
        )}
        {ruleRows.length === 0 && <p className="text-sm text-slate-400">No passive rules map to this category.</p>}
      </Section>

      {meta.manual_tests?.length > 0 && (
        <Section title="Still needs manual testing">
          <p className="mb-2 text-xs text-slate-500">A passive audit cannot cover these. Test them with authenticated, authorized manual work.</p>
          <ul className="space-y-1.5">
            {meta.manual_tests.map((t) => (
              <li key={t.title} className="flex gap-3 text-sm">
                <span className="w-28 shrink-0 font-mono text-xs leading-5 text-accent-300">{t.wstg ?? 'Review'}</span>
                <span className="text-slate-300">{t.title}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </Drawer>
  )
}
