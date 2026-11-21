import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  FlaskConical,
  Loader2,
  Plus,
  Radar,
  ShieldCheck,
  Trash2,
  XCircle,
} from 'lucide-react'
import { api } from './lib/api'
import { formatDate } from './lib/format'
import { CatalogContext, PanelContext } from './lib/panels'
import CategoryDrawer from './components/CategoryDrawer'
import ExportMenu from './components/ExportMenu'
import FindingsExplorer from './components/FindingsExplorer'
import IssueDrawer from './components/IssueDrawer'
import NewAuditPanel from './components/NewAuditPanel'
import Overview from './components/Overview'
import RulesCatalog from './components/RulesCatalog'
import SubdomainDrawer from './components/SubdomainDrawer'
import SubdomainTable from './components/SubdomainTable'

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'subdomains', label: 'Subdomains' },
  { id: 'findings', label: 'Findings' },
  { id: 'rules', label: 'Rule catalog' },
]

function Toast({ toast, onClose }) {
  useEffect(() => {
    if (!toast) return undefined
    const t = setTimeout(onClose, 5000)
    return () => clearTimeout(t)
  }, [toast, onClose])
  if (!toast) return null
  const Icon = toast.type === 'error' ? XCircle : toast.type === 'warning' ? AlertTriangle : CheckCircle2
  const tone = toast.type === 'error' ? 'border-red-500/40 text-red-200' : toast.type === 'warning' ? 'border-amber-500/40 text-amber-100' : 'border-emerald-500/40 text-emerald-100'
  return (
    <div className={`fixed bottom-5 right-5 z-50 flex max-w-md items-start gap-2 rounded-lg border bg-ink-850 px-4 py-3 text-sm shadow-2xl ${tone}`} role="status">
      <Icon className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{toast.message}</span>
    </div>
  )
}

function EmptyState({ onDemo, onNew, busy, backendDown }) {
  return (
    <div className="mx-auto mt-16 max-w-2xl text-center">
      <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-2xl bg-cyan-500/10 ring-1 ring-cyan-500/30">
        <Radar className="h-8 w-8 text-cyan-300" />
      </div>
      <h1 className="text-2xl font-bold text-white">Passive OWASP Top 10 (2025) compliance, per subdomain</h1>
      <p className="mx-auto mt-3 max-w-xl text-sm leading-relaxed text-slate-400">
        WAPTrix inspects headers, TLS, cookies, CORS, disclosure, forms and security metadata using only read-only GET
        requests and TLS handshakes, then maps every finding to CWE, WSTG v4.2, CVSS v3.1 and OWASP Top 10 (2025).
      </p>
      {backendDown && (
        <p className="mx-auto mt-4 max-w-md rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">
          API not reachable. Start it with <code className="font-mono">uvicorn app.main:app --port 8000</code> in <code className="font-mono">backend/</code>.
        </p>
      )}
      <div className="mt-6 flex justify-center gap-3">
        <button className="btn-primary" onClick={onDemo} disabled={busy || backendDown}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <FlaskConical className="h-4 w-4" />}Load demo audit
        </button>
        <button className="btn-ghost" onClick={onNew} disabled={backendDown}><Plus className="h-4 w-4" />New audit</button>
      </div>
    </div>
  )
}

export default function App() {
  const [health, setHealth] = useState(null)
  const [backendDown, setBackendDown] = useState(false)
  const [audits, setAudits] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [audit, setAudit] = useState(null)
  const [tab, setTab] = useState('overview')
  const [panels, setPanels] = useState([])
  const [catalog, setCatalog] = useState({ rules: {}, categories: {} })
  const [showNew, setShowNew] = useState(false)
  const [busy, setBusy] = useState(false)
  const [toast, setToast] = useState(null)
  const pollRef = useRef(null)

  const notify = useCallback((t) => setToast(t), [])
  const closeToast = useCallback(() => setToast(null), [])

  const refreshList = useCallback(async () => {
    const list = await api.listAudits()
    setAudits(list)
    return list
  }, [])

  useEffect(() => {
    api.health()
      .then((h) => { setHealth(h); return refreshList() })
      .then((list) => { if (list?.length) setSelectedId(list[0].id) })
      .catch(() => setBackendDown(true))
    Promise.all([api.rules(), api.categories()])
      .then(([rules, categories]) => setCatalog({
        rules: Object.fromEntries(rules.map((r) => [r.id, r])),
        categories: Object.fromEntries(categories.map((c) => [c.id, c])),
      }))
      .catch(() => {})
  }, [refreshList])

  useEffect(() => setPanels([]), [selectedId])

  useEffect(() => {
    clearTimeout(pollRef.current)
    if (!selectedId) { setAudit(null); return undefined }
    let cancelled = false
    const load = async () => {
      try {
        const data = await api.getAudit(selectedId)
        if (cancelled) return
        setAudit(data)
        if (data.status === 'running') {
          pollRef.current = setTimeout(load, 1500)
        } else {
          refreshList()
          if (data.status === 'failed') notify({ type: 'error', message: `Audit failed: ${data.error}` })
        }
      } catch (err) {
        if (!cancelled) notify({ type: 'error', message: err.message })
      }
    }
    load()
    return () => { cancelled = true; clearTimeout(pollRef.current) }
  }, [selectedId, refreshList, notify])

  async function loadDemo() {
    setBusy(true)
    try {
      const demo = await api.loadDemo()
      await refreshList()
      setSelectedId(demo.id)
      setTab('overview')
      notify({ type: 'success', message: 'Demo audit loaded (offline synthetic data).' })
    } catch (err) {
      notify({ type: 'error', message: err.message })
    } finally {
      setBusy(false)
    }
  }

  async function startAudit(body) {
    setBusy(true)
    try {
      const created = await api.createAudit(body)
      setShowNew(false)
      await refreshList()
      setSelectedId(created.id)
      setTab('overview')
      const rejected = created.scope_rejections.length
      notify({ type: rejected ? 'warning' : 'success', message: `Audit started on ${created.targets.length} target(s)${rejected ? `; ${rejected} input(s) rejected by scope guard` : ''}.` })
    } finally {
      setBusy(false)
    }
  }

  async function removeAudit() {
    if (!audit || !window.confirm(`Delete audit ${audit.authorization_ref} (${audit.id})? This cannot be undone.`)) return
    try {
      await api.deleteAudit(audit.id)
      const list = await refreshList()
      setSelectedId(list[0]?.id ?? null)
      notify({ type: 'success', message: 'Audit deleted.' })
    } catch (err) {
      notify({ type: 'error', message: err.message })
    }
  }

  const pushPanel = useCallback((panel) => setPanels((stack) => [...stack, panel]), [])
  const backPanel = useCallback(() => setPanels((stack) => stack.slice(0, -1)), [])
  const closePanels = useCallback(() => setPanels([]), [])
  const panelApi = useMemo(() => ({
    openSubdomain: (subdomain, category) => pushPanel({ type: 'subdomain', subdomain, category }),
    openIssue: (ruleId) => pushPanel({ type: 'issue', ruleId }),
    openCategory: (categoryId) => pushPanel({ type: 'category', categoryId }),
  }), [pushPanel])
  const openSubdomain = panelApi.openSubdomain
  const panel = panels[panels.length - 1]
  const onBack = panels.length > 1 ? backPanel : undefined
  const completed = audit?.status === 'completed'

  return (
    <CatalogContext.Provider value={catalog}>
    <PanelContext.Provider value={panelApi}>
    <div className="min-h-screen bg-[radial-gradient(ellipse_at_top,rgba(34,211,238,0.07),transparent_55%)]">
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-ink-950/85 backdrop-blur">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-3 px-4 py-3 sm:px-6">
          <div className="mr-2 flex items-center gap-2.5">
            <ShieldCheck className="h-7 w-7 text-cyan-300" />
            <div>
              <div className="text-base font-extrabold tracking-tight text-white">WAP<span className="text-cyan-300">Trix</span></div>
              <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Passive audit · OWASP 2025</div>
            </div>
          </div>

          {audits.length > 0 && (
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-slate-500" />
              <select className="input w-auto max-w-[22rem] py-1.5" value={selectedId ?? ''} onChange={(e) => setSelectedId(e.target.value)} aria-label="Select audit">
                {audits.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.authorization_ref} · {formatDate(a.created_at)} · {a.status === 'completed' ? `${a.grade} (${a.overall_score ?? '—'})` : a.status}{a.demo ? ' · demo' : ''}
                  </option>
                ))}
              </select>
              {audit && <button className="btn-ghost p-2" onClick={removeAudit} title="Delete audit" aria-label="Delete audit"><Trash2 className="h-4 w-4" /></button>}
            </div>
          )}

          <div className="ml-auto flex items-center gap-2">
            {health && (
              <span className="hidden items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/5 px-2 py-1 text-[11px] text-emerald-300 md:inline-flex">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />API v{health.version} · passive{health.pdf_engine ? '' : ' · PDF→HTML'}
              </span>
            )}
            {completed && <ExportMenu auditId={audit.id} label="Export audit" onNotify={notify} />}
            <button className="btn-ghost" onClick={loadDemo} disabled={busy || backendDown}><FlaskConical className="h-4 w-4" /><span className="hidden sm:inline">Load demo</span></button>
            <button className="btn-primary" onClick={() => setShowNew(true)} disabled={backendDown}><Plus className="h-4 w-4" />New audit</button>
          </div>
        </div>
        {completed && (
          <nav className="mx-auto flex max-w-[1500px] gap-1 px-4 sm:px-6" aria-label="Sections">
            {TABS.map((t) => (
              <button key={t.id} className={`tab ${tab === t.id ? 'tab-active' : ''}`} onClick={() => setTab(t.id)}>{t.label}</button>
            ))}
          </nav>
        )}
      </header>

      <main className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6">
        {!audit && <EmptyState onDemo={loadDemo} onNew={() => setShowNew(true)} busy={busy} backendDown={backendDown} />}

        {audit?.status === 'running' && (
          <div className="panel mx-auto mt-10 max-w-xl p-8 text-center">
            <Loader2 className="mx-auto h-8 w-8 animate-spin text-cyan-300" />
            <h2 className="mt-4 text-lg font-semibold text-white">Passive audit in progress</h2>
            <p className="mt-1 text-sm text-slate-400">Authorization {audit.authorization_ref}</p>
            {audit.progress && (
              <>
                <div className="mt-5 h-2 overflow-hidden rounded-full bg-ink-700">
                  <div className="h-full rounded-full bg-cyan-400 transition-all" style={{ width: `${(100 * audit.progress.done) / Math.max(audit.progress.total, 1)}%` }} />
                </div>
                <p className="mt-2 font-mono text-xs text-slate-400">
                  {audit.progress.done}/{audit.progress.total} subdomains{audit.progress.current ? ` · last: ${audit.progress.current}` : ''}
                </p>
              </>
            )}
          </div>
        )}

        {audit?.status === 'failed' && (
          <div className="panel mx-auto mt-10 max-w-xl border-red-500/40 p-8 text-center">
            <XCircle className="mx-auto h-8 w-8 text-red-400" />
            <h2 className="mt-4 text-lg font-semibold text-white">Audit failed</h2>
            <p className="mt-1 text-sm text-red-200">{audit.error}</p>
          </div>
        )}

        {completed && (
          <>
            <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
              <div>
                <h1 className="text-xl font-bold text-white">
                  {audit.authorization_ref}
                  {audit.demo && <span className="ml-2 rounded-md bg-violet-500/15 px-2 py-0.5 align-middle text-xs font-semibold text-violet-300 ring-1 ring-violet-500/40">DEMO DATA</span>}
                </h1>
                <p className="text-xs text-slate-500">
                  Audit <span className="font-mono">{audit.id}</span> · started {formatDate(audit.created_at)} · completed {formatDate(audit.completed_at)} · engine v{audit.engine_version}
                </p>
              </div>
            </div>

            {audit.scope_rejections.length > 0 && (
              <div className="mb-5 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm text-amber-100">
                <AlertTriangle className="mr-1.5 inline h-4 w-4 text-amber-300" />
                Scope guard rejected {audit.scope_rejections.length} input(s):{' '}
                {audit.scope_rejections.map((r) => (
                  <span key={r.input} className="mr-3 font-mono text-xs text-amber-200/90">{r.input} <span className="text-amber-200/60">({r.reason})</span></span>
                ))}
              </div>
            )}

            {tab === 'overview' && <Overview audit={audit} onSelectSubdomain={openSubdomain} />}
            {tab === 'subdomains' && <SubdomainTable audit={audit} onSelect={openSubdomain} />}
            {tab === 'findings' && <FindingsExplorer audit={audit} />}
            {tab === 'rules' && <RulesCatalog />}
          </>
        )}
      </main>

      <footer className="mx-auto max-w-[1500px] px-6 pb-8 text-center text-[11px] text-slate-600">
        WAPTrix performs strictly passive, read-only inspection. Only audit systems you are authorized to test.
      </footer>

      {panel && completed && panel.type === 'subdomain' && (
        <SubdomainDrawer key={panels.length} audit={audit} subdomain={panel.subdomain} initialCategory={panel.category}
          onClose={closePanels} onBack={onBack} onNotify={notify} />
      )}
      {panel && completed && panel.type === 'issue' && (
        <IssueDrawer key={panels.length} audit={audit} ruleId={panel.ruleId} onClose={closePanels} onBack={onBack} />
      )}
      {panel && completed && panel.type === 'category' && (
        <CategoryDrawer key={panels.length} audit={audit} categoryId={panel.categoryId} onClose={closePanels} onBack={onBack} />
      )}
      {showNew && <NewAuditPanel onSubmit={startAudit} onClose={() => setShowNew(false)} busy={busy} />}
      <Toast toast={toast} onClose={closeToast} />
    </div>
    </PanelContext.Provider>
    </CatalogContext.Provider>
  )
}
