import { useState } from 'react'
import { ChevronDown, ExternalLink, Layers } from 'lucide-react'
import { cweUrl } from '../lib/cvss'
import { SEVERITY_META } from '../lib/format'
import { usePanels } from '../lib/panels'
import { SeverityBadge } from './Badges'

function VotingBreakdown({ corr }) {
  const pct = Math.min(100, Math.round(corr.score * 100))
  const tau = Math.round(corr.threshold * 100)
  return (
    <div className="rounded-md border border-slate-800 bg-ink-950/60 p-3 text-xs">
      <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="panel-title">Cross-tool voting</span>
        <span className={`font-mono ${corr.admitted ? 'text-emerald-300' : 'text-violet-300'}`}>
          C(f) = {corr.score.toFixed(2)} {corr.admitted ? '≥' : '<'} τ = {corr.threshold}
        </span>
        <span className="font-mono text-slate-500">class {corr.tag}</span>
        {corr.confirmed && <span className="chip bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/30">Actively confirmed (+γ)</span>}
        {!corr.admitted && <span className="chip bg-violet-500/10 text-violet-300 ring-1 ring-violet-500/30">Awaiting re-test</span>}
      </div>
      <div className="relative h-1.5 rounded-full bg-ink-700" aria-hidden="true">
        <div className={`h-full rounded-full ${corr.admitted ? 'bg-emerald-400' : 'bg-violet-400'}`} style={{ width: `${pct}%` }} />
        <div className="absolute -top-1 h-3.5 w-0.5 bg-slate-300" style={{ left: `${tau}%` }} title={`τ = ${corr.threshold}`} />
      </div>
      <dl className="mt-2 grid gap-x-6 gap-y-1 sm:grid-cols-3">
        <div><dt className="text-slate-500">Detected by (T)</dt><dd className="font-mono text-slate-200">{corr.detectors.join(', ') || '—'}</dd></div>
        <div><dt className="text-slate-500">Capable engines that ran (E)</dt><dd className="font-mono text-slate-300">{corr.applicable.join(', ') || '—'}</dd></div>
        <div><dt className="text-slate-500">Silent (E∖T)</dt><dd className="font-mono text-slate-400">{corr.silent.join(', ') || 'none'}</dd></div>
      </dl>
    </div>
  )
}

export default function FindingCard({ finding, showSubdomain = false, defaultOpen = false, hideIssueLink = false }) {
  const [open, setOpen] = useState(defaultOpen)
  const { openIssue } = usePanels()
  const [description, detail] = finding.description.split('\n\n')
  const corr = finding.correlation
  return (
    <div
      className="rounded-md border border-slate-800 bg-ink-900 transition-colors hover:border-slate-700"
      style={{ borderLeft: `3px solid ${SEVERITY_META[finding.severity]?.color ?? '#94a3b8'}` }}
    >
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-start gap-3 px-4 py-3 text-left" aria-expanded={open}>
        <SeverityBadge severity={finding.severity} />
        <div className="min-w-0 flex-1">
          <div className="font-medium text-slate-100">{finding.title}</div>
          <div className="mt-0.5 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[11px] text-slate-500">
            <span className="text-slate-400">{finding.rule_id}</span>
            {showSubdomain && <span className="text-accent-300/80">{finding.subdomain}</span>}
            <span>{finding.owasp.join(' · ')}</span>
            <span>{finding.cwe}</span>
            {finding.cvss_score != null && <span>CVSS {finding.cvss_score.toFixed(1)}</span>}
            {finding.sources?.length > 0 && <span className="text-slate-400">via {finding.sources.join(', ')}</span>}
            {corr && (
              <span className={corr.admitted ? 'text-emerald-300/90' : 'text-violet-300'} title="Weighted cross-tool agreement C(f), paper eq. 1">
                C(f) {corr.score.toFixed(2)}{corr.admitted ? '' : ` < τ ${corr.threshold}`}{corr.confirmed ? ' · confirmed' : ''}
              </span>
            )}
          </div>
        </div>
        <ChevronDown className={`mt-1 h-4 w-4 shrink-0 text-slate-500 transition ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="space-y-3 border-t border-slate-800 px-4 py-3 text-sm">
          <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
            <div className="flex gap-2"><dt className="text-slate-500">URL</dt><dd className="break-all font-mono text-slate-300">{finding.url}</dd></div>
            <div className="flex gap-2"><dt className="text-slate-500">Confidence</dt><dd className="capitalize text-slate-300">{finding.confidence}</dd></div>
            {finding.cwe && <div className="flex gap-2"><dt className="text-slate-500">CWE</dt><dd><a href={cweUrl(finding.cwe)} target="_blank" rel="noreferrer noopener" className="text-accent-300 hover:text-accent-200">{finding.cwe} {finding.cwe_name}</a></dd></div>}
            <div className="flex gap-2"><dt className="text-slate-500">WSTG v4.2</dt><dd className="font-mono text-slate-300">{finding.wstg ?? '—'}</dd></div>
            {finding.cvss_score != null && <div className="flex gap-2 sm:col-span-2"><dt className="text-slate-500">CVSS v3.1</dt><dd className="break-all font-mono text-slate-300">{finding.cvss_score.toFixed(1)} · {finding.cvss_vector}</dd></div>}
            {finding.sources?.length > 0 && <div className="flex gap-2 sm:col-span-2"><dt className="text-slate-500">Detected by</dt><dd className="text-slate-300">{finding.sources.join(', ')}{finding.tool_refs?.length > 0 && <span className="ml-2 font-mono text-[11px] text-slate-500">{finding.tool_refs.join(' · ')}</span>}</dd></div>}
          </dl>
          {corr && <VotingBreakdown corr={corr} />}
          <p className="leading-relaxed text-slate-300">{description}</p>
          {detail && <p className="leading-relaxed text-slate-400">{detail}</p>}
          {finding.evidence && (
            <div>
              <div className="panel-title mb-1">Evidence</div>
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-slate-800 bg-ink-950 p-3 font-mono text-[11px] leading-relaxed text-emerald-200/90">
                {finding.evidence}
              </pre>
            </div>
          )}
          <div className="rounded-md border border-accent-500/20 bg-accent-500/5 p-3">
            <div className="panel-title mb-1 text-accent-300/80">Remediation</div>
            <p className="leading-relaxed text-slate-200">{finding.remediation}</p>
          </div>
          {!hideIssueLink && (
            <button onClick={() => openIssue(finding.rule_id)} className="inline-flex items-center gap-1.5 text-xs text-accent-300 hover:text-accent-200">
              <Layers className="h-3.5 w-3.5" />Issue details, CVSS breakdown and every affected host
            </button>
          )}
          {finding.references?.length > 0 && (
            <ul className="space-y-1 text-xs">
              {finding.references.map((ref) => (
                <li key={ref}>
                  <a href={ref} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 break-all text-accent-300 hover:text-accent-200">
                    <ExternalLink className="h-3 w-3 shrink-0" />{ref}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}
