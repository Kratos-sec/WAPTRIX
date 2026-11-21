import { useMemo } from 'react'
import { ExternalLink } from 'lucide-react'
import { calculatorUrl, cweUrl, describeVector } from '../lib/cvss'
import { shortCat } from '../lib/format'
import { useCatalog, usePanels } from '../lib/panels'
import { GradeBadge, SeverityBadge } from './Badges'
import Drawer, { Section } from './Drawer'
import FindingCard from './FindingCard'

function Stat({ label, value }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-ink-900/60 px-4 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="mt-0.5 text-xl font-bold text-white">{value}</div>
    </div>
  )
}

function Link({ href, children }) {
  return (
    <a href={href} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 break-all text-cyan-300 hover:text-cyan-200">
      <ExternalLink className="h-3 w-3 shrink-0" />{children}
    </a>
  )
}

export default function IssueDrawer({ audit, ruleId, onClose, onBack }) {
  const { rules, categories } = useCatalog()
  const { openCategory, openSubdomain } = usePanels()

  const instances = useMemo(
    () => audit.subdomains.flatMap((s) => s.findings.filter((f) => f.rule_id === ruleId)),
    [audit, ruleId],
  )
  const sample = instances[0]
  const rule = rules[ruleId] ?? (sample && {
    id: ruleId, title: sample.title, severity: sample.severity, confidence: sample.confidence, cwe: sample.cwe,
    cwe_name: sample.cwe_name, wstg: sample.wstg, owasp: sample.owasp, cvss_vector: sample.cvss_vector,
    cvss_score: sample.cvss_score, description: sample.description.split('\n\n')[0], remediation: sample.remediation,
    references: sample.references,
  })
  if (!rule) return null

  const hosts = audit.subdomains
    .map((s) => ({ sub: s, findings: s.findings.filter((f) => f.rule_id === ruleId) }))
    .filter((h) => h.findings.length)
  const reachable = audit.subdomains.filter((s) => s.reachable).length

  return (
    <Drawer
      label={`Issue ${rule.title}`}
      onClose={onClose}
      onBack={onBack}
      header={
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={rule.severity} />
            <span className="font-mono text-xs text-slate-500">{rule.id}</span>
          </div>
          <h2 className="mt-1 text-lg font-semibold text-white">{rule.title}</h2>
        </div>
      }
    >
      <div className="grid gap-3 sm:grid-cols-4">
        <Stat label="Instances" value={instances.length} />
        <Stat label="Hosts affected" value={`${hosts.length} of ${reachable}`} />
        <Stat label="CVSS v3.1 base" value={rule.cvss_score.toFixed(1)} />
        <Stat label="Confidence" value={<span className="capitalize">{rule.confidence}</span>} />
      </div>

      <Section title="What this means">
        <p className="text-sm leading-relaxed text-slate-300">{rule.description}</p>
      </Section>

      {rule.method && (
        <Section title="How WAPTrix detected it">
          <p className="text-sm leading-relaxed text-slate-300">{rule.method}</p>
          <p className="mt-2 text-xs text-slate-500">
            Module: {rule.module_name}. Confidence “{rule.confidence}”
            {rule.confidence === 'tentative' ? ' means a person should confirm this before reporting it.' : rule.confidence === 'firm' ? ' means a strong indicator, worth a quick manual look.' : ' means the issue is directly observed in the response.'}
          </p>
        </Section>
      )}

      <Section title="Fix">
        <p className="text-sm leading-relaxed text-slate-200">{rule.remediation}</p>
        {rule.references?.length > 0 && (
          <ul className="mt-3 space-y-1 text-xs">
            {rule.references.map((ref) => <li key={ref}><Link href={ref}>{ref}</Link></li>)}
          </ul>
        )}
      </Section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Classification">
          <div className="space-y-3 text-sm">
            <div>
              <div className="mb-1 text-xs text-slate-500">OWASP Top 10 (2025)</div>
              <div className="flex flex-wrap gap-2">
                {rule.owasp.map((cid) => (
                  <button key={cid} onClick={() => openCategory(cid)}
                    className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:border-cyan-500/60 hover:text-cyan-200">
                    <span className="font-mono text-cyan-300">{shortCat(cid)}</span> {categories[cid]?.name}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <div className="mb-1 text-xs text-slate-500">Weakness</div>
              <Link href={cweUrl(rule.cwe)}>{rule.cwe} {rule.cwe_name}</Link>
            </div>
            <div>
              <div className="mb-1 text-xs text-slate-500">OWASP testing guide (WSTG v4.2)</div>
              <span className="font-mono text-xs text-slate-200">{rule.wstg ?? 'No matching WSTG test'}</span>
            </div>
          </div>
        </Section>

        <Section title="CVSS v3.1 vector" right={<Link href={calculatorUrl(rule.cvss_vector)}>Open in FIRST calculator</Link>}>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
            {describeVector(rule.cvss_vector).map((m) => (
              <div key={m.key} className="flex justify-between gap-2 border-b border-slate-800/60 py-1">
                <dt className="text-slate-500">{m.name}</dt>
                <dd className="text-slate-200">{m.value}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-2 break-all font-mono text-[11px] text-slate-500">{rule.cvss_vector}</p>
        </Section>
      </div>

      <Section title={`Affected hosts (${hosts.length})`}>
        {hosts.length === 0 ? (
          <p className="text-sm text-slate-400">Not observed on any host in this audit.</p>
        ) : (
          <div className="space-y-4">
            {hosts.map(({ sub, findings }) => (
              <div key={sub.subdomain}>
                <button onClick={() => openSubdomain(sub.subdomain)} className="mb-2 flex items-center gap-2 text-left hover:text-cyan-300">
                  <GradeBadge grade={sub.grade} size="sm" />
                  <span className="font-mono text-sm text-slate-100">{sub.subdomain}</span>
                  <span className="text-xs text-slate-500">{findings.length} instance{findings.length === 1 ? '' : 's'}</span>
                </button>
                <div className="space-y-2">
                  {findings.map((f) => <FindingCard key={f.id} finding={f} defaultOpen={hosts.length === 1 && findings.length === 1} hideIssueLink />)}
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>
    </Drawer>
  )
}
