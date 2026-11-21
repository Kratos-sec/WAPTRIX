import { useEffect, useMemo, useState } from 'react'
import { ArrowRight, Info } from 'lucide-react'
import { COVERAGE_LABEL, SEVERITIES, formatDate, shortCat } from '../lib/format'
import { usePanels } from '../lib/panels'
import { GradeBadge, SeverityBadge, StatusBadge } from './Badges'
import Drawer, { KV, Section } from './Drawer'
import ExportMenu from './ExportMenu'
import FindingCard from './FindingCard'

export default function SubdomainDrawer({ audit, subdomain, initialCategory, onClose, onBack, onNotify }) {
  const sub = audit.subdomains.find((s) => s.subdomain === subdomain)
  const [category, setCategory] = useState(initialCategory ?? null)
  const [headerSource, setHeaderSource] = useState(sub?.scheme === 'http' ? 'http' : 'https')
  const { openCategory } = usePanels()

  useEffect(() => {
    setCategory(initialCategory ?? null)
  }, [initialCategory, subdomain])

  const findings = useMemo(
    () => (sub ? sub.findings.filter((f) => !category || f.owasp.includes(category)) : []),
    [sub, category],
  )

  if (!sub) return null
  const tls = sub.tls
  const observation = headerSource === 'http' ? sub.http : sub.https

  return (
    <Drawer
      label={`Details for ${sub.subdomain}`}
      onClose={onClose}
      onBack={onBack}
      header={
        <>
          <GradeBadge grade={sub.grade} size="lg" />
          <div className="min-w-0 flex-1">
            <h2 className="truncate font-mono text-lg font-semibold text-white">{sub.subdomain}</h2>
            <p className="text-xs text-slate-400">
              {sub.reachable ? `Score ${sub.score}/100 · ${sub.findings.length} findings · scanned ${formatDate(sub.scanned_at)} in ${sub.duration_ms} ms` : sub.error}
            </p>
          </div>
          <ExportMenu auditId={audit.id} subdomain={sub.subdomain} label="Export host" onNotify={onNotify} />
        </>
      }
    >
          <div className="flex flex-wrap gap-1.5">
            {SEVERITIES.map((s) => <SeverityBadge key={s} severity={s} count={sub.severity_counts[s] ?? 0} />)}
          </div>

          <Section title="OWASP Top 10 (2025) status" right={category && (
            <div className="flex gap-3 text-xs">
              <button className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200" onClick={() => openCategory(category)}>
                <Info className="h-3.5 w-3.5" />About {shortCat(category)}
              </button>
              <button className="text-slate-400 hover:text-slate-200" onClick={() => setCategory(null)}>Clear filter</button>
            </div>
          )}>
            <div className="grid gap-2 sm:grid-cols-2">
              {sub.categories.map((c) => (
                <button key={c.id} onClick={() => setCategory(category === c.id ? null : c.id)}
                  className={`flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-left text-xs transition ${category === c.id ? 'border-cyan-500/60 bg-cyan-500/10' : 'border-slate-800 hover:border-slate-700 hover:bg-ink-800/60'}`}>
                  <span className="min-w-0">
                    <span className="font-mono text-cyan-300">{shortCat(c.id)}</span>{' '}
                    <span className="text-slate-200">{c.name}</span>
                    <span className="block text-[10px] text-slate-500">{COVERAGE_LABEL[c.coverage]} coverage · {c.finding_count} finding(s)</span>
                  </span>
                  <StatusBadge status={c.status} compact />
                </button>
              ))}
            </div>
          </Section>

          <div className="grid gap-4 lg:grid-cols-2">
            <Section title="Endpoint">
              <dl>
                <KV label="Reachable">{sub.reachable ? `yes (${sub.scheme?.toUpperCase()})` : 'no'}</KV>
                <KV label="Final URL">{sub.final_url}</KV>
                <KV label="Status">{sub.status_code}</KV>
                <KV label="Resolved IPs">{sub.ip_addresses?.join(', ')}</KV>
                <KV label="HTTP → HTTPS">{sub.https_redirect === null || sub.https_redirect === undefined ? 'n/a' : sub.https_redirect ? 'redirects' : 'NO redirect'}</KV>
                {sub.http?.redirect_chain?.length > 0 && (
                  <KV label="HTTP chain">
                    {sub.http.redirect_chain.map((hop) => (
                      <span key={hop.url} className="block">
                        {hop.status_code} {hop.url} <ArrowRight className="inline h-3 w-3" /> {hop.location}
                      </span>
                    ))}
                  </KV>
                )}
                {sub.error && <KV label="Notes">{sub.error}</KV>}
              </dl>
            </Section>

            <Section title="TLS posture">
              {!tls ? <p className="text-xs text-slate-500">Not inspected.</p> : tls.error ? (
                <p className="text-xs text-red-300">{tls.error}</p>
              ) : (
                <dl>
                  <KV label="Protocol">{tls.protocol}</KV>
                  <KV label="Cipher">{tls.cipher} ({tls.cipher_bits} bits)</KV>
                  <KV label="Legacy accepted">
                    {tls.legacy_protocols_accepted?.length ? <span className="text-red-300">{tls.legacy_protocols_accepted.join(', ')}</span>
                      : tls.legacy_probe === 'completed' ? 'none' : `undetermined (${tls.legacy_probe})`}
                  </KV>
                  <KV label="Subject">{tls.cert_subject}</KV>
                  <KV label="Issuer">{tls.cert_issuer}{tls.self_signed ? ' (self-signed)' : ''}</KV>
                  <KV label="Expires">
                    <span className={(tls.days_to_expiry ?? 0) < 30 ? 'text-orange-300' : ''}>{formatDate(tls.cert_not_after)} ({tls.days_to_expiry} days)</span>
                  </KV>
                  <KV label="SAN">{tls.san?.join(', ')}</KV>
                  <KV label="Hostname / trust">
                    <span className={tls.hostname_match === false || tls.trusted === false ? 'text-red-300' : 'text-emerald-300'}>
                      {tls.hostname_match ? 'match' : 'mismatch'} · {tls.trusted ? 'trusted' : tls.trusted === false ? 'untrusted' : 'unknown'}
                    </span>
                    {tls.verify_error && <span className="block text-slate-400">{tls.verify_error}</span>}
                  </KV>
                </dl>
              )}
            </Section>
          </div>

          {(sub.https?.status_code || sub.http?.status_code) && (
            <Section title="Captured response headers" right={
              <div className="flex gap-1 text-xs">
                {['https', 'http'].map((src) => (
                  <button key={src} onClick={() => setHeaderSource(src)} disabled={!sub[src]?.status_code}
                    className={`rounded-md px-2 py-1 uppercase ${headerSource === src ? 'bg-ink-700 text-cyan-300' : 'text-slate-400 hover:text-slate-200 disabled:opacity-40'}`}>
                    {src}
                  </button>
                ))}
              </div>
            }>
              {observation?.status_code ? (
                <pre className="max-h-72 overflow-auto rounded-md border border-slate-800 bg-ink-950 p-3 font-mono text-[11px] leading-relaxed">
                  <span className="text-slate-500">{`GET ${observation.final_url} → ${observation.status_code} (${observation.elapsed_ms} ms, ${observation.body_bytes} bytes)\n`}</span>
                  {Object.entries(observation.headers).map(([k, v]) => (
                    <span key={k}><span className="text-cyan-300">{k}</span>: <span className="text-slate-300">{v}</span>{'\n'}</span>
                  ))}
                </pre>
              ) : (
                <p className="text-xs text-slate-500">{observation?.error ?? 'No response captured.'}</p>
              )}
            </Section>
          )}

          <Section title={`Findings${category ? ` · ${category}` : ''} (${findings.length})`}>
            <div className="space-y-2">
              {findings.length === 0 && <p className="text-sm text-slate-400">No passive issues in this view.</p>}
              {findings.map((f) => <FindingCard key={f.id} finding={f} />)}
            </div>
          </Section>
    </Drawer>
  )
}
