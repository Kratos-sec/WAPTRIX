import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, FlaskConical, Globe2, Loader2, Menu, Moon, Plus, Sun, Trash2, X, XCircle } from 'lucide-react'
import { api } from './lib/api'
import { formatDate } from './lib/format'
import { CatalogContext, PanelContext } from './lib/panels'
import { useTheme } from './lib/theme'
import { GradeBadge } from './components/Badges'
import CategoryDrawer from './components/CategoryDrawer'
import ExportMenu from './components/ExportMenu'
import FindingsExplorer from './components/FindingsExplorer'
import IssueDrawer from './components/IssueDrawer'
import LiveRun from './components/LiveRun'
import NewAuditPanel from './components/NewAuditPanel'
import Overview from './components/Overview'
import RulesCatalog from './components/RulesCatalog'
import SubdomainDrawer from './components/SubdomainDrawer'
import SubdomainTable from './components/SubdomainTable'
import WorkflowView from './components/WorkflowView'

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'subdomains', label: 'Subdomains' },
  { id: 'findings', label: 'Findings' },
  { id: 'workflow', label: 'Workflow' },
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
  const tone = toast.type === 'error' ? 'text-red-300' : toast.type === 'warning' ? 'text-amber-300' : 'text-emerald-300'
  return (
    <div className="fixed bottom-5 right-5 z-50 flex max-w-md items-start gap-2.5 rounded-lg border border-slate-800 bg-ink-900 px-4 py-3 text-[13px] text-slate-200 shadow-float" role="status">
      <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${tone}`} />
      <span>{toast.message}</span>
    </div>
  )
}

function Logo() {
  return (
    <svg viewBox="0 0 32 32" className="h-6 w-6 shrink-0" aria-hidden="true">
      <rect width="32" height="32" rx="7" className="fill-accent-500" />
      <path d="M16 6.5 8.5 9.5v5.6c0 4.8 3.2 8.7 7.5 10.4 4.3-1.7 7.5-5.6 7.5-10.4V9.5L16 6.5Z" fill="none" stroke="#fff" strokeWidth="1.8" />
      <path d="M12.5 16h7M16 12.5v7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  )
}

function AuditListEntry({ item, selected, onSelect }) {
  const running = item.status === 'running'
  const failed = item.status === 'failed'
  return (
    <button onClick={() => onSelect(item.id)} aria-current={selected ? 'true' : undefined}
      className={`nav-item items-start gap-3 py-2 ${selected ? 'nav-item-active' : ''}`}>
      {running ? (
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-accent-500/10 text-accent-300"><Loader2 className="h-3.5 w-3.5 animate-spin" /></span>
      ) : failed ? (
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-red-500/10 text-red-300"><XCircle className="h-3.5 w-3.5" /></span>
      ) : (
        <GradeBadge grade={item.grade} size="sm" />
      )}
      <span className="min-w-0 flex-1">
        <span className="block truncate font-medium">{item.authorization_ref}</span>
        <span className="block truncate text-[11px] text-slate-500">
          {formatDate(item.created_at)}
          {item.status === 'completed' && <>, {item.total_findings} findings</>}
          {running && ', running'}
          {failed && ', failed'}
        </span>
      </span>
      {item.demo && <span className="mt-0.5 rounded bg-violet-500/10 px-1 text-[10px] font-medium text-violet-300">demo</span>}
    </button>
  )
}

function Sidebar({ audits, selectedId, onSelect, onNew, onDemo, busy, backendDown, health, theme, onToggleTheme, open, onClose }) {
  return (
    <>
      {open && <div className="fixed inset-0 z-30 bg-black/40 lg:hidden" onClick={onClose} aria-hidden="true" />}
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-[264px] flex-col border-r border-slate-800 bg-ink-950 transition-transform lg:sticky lg:top-0 lg:z-auto lg:h-screen lg:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}
        aria-label="Audits">
        <div className="flex items-center gap-2.5 px-4 pb-3 pt-4">
          <Logo />
          <span className="text-[15px] font-semibold tracking-tight text-slate-100">WAPTrix</span>
          <button className="ml-auto rounded-md p-1.5 text-slate-400 hover:bg-ink-800 lg:hidden" onClick={onClose} aria-label="Close menu"><X className="h-4 w-4" /></button>
        </div>
        <div className="px-3 pb-3">
          <button className="btn-primary w-full justify-center" onClick={onNew} disabled={backendDown}><Plus className="h-4 w-4" />New audit</button>
        </div>

        <div className="flex items-center justify-between px-4 pb-1 pt-3">
          <h2 className="text-xs font-medium text-slate-500">Audit history</h2>
          {audits.length > 0 && <span className="font-mono text-[11px] text-slate-500">{audits.length}</span>}
        </div>
        <nav className="min-h-0 flex-1 space-y-0.5 overflow-y-auto px-2 pb-3">
          {audits.length === 0 && (
            <p className="px-2 py-3 text-xs leading-relaxed text-slate-500">Audits you run show up here.</p>
          )}
          {audits.map((a) => (
            <AuditListEntry key={a.id} item={a} selected={a.id === selectedId} onSelect={(id) => { onSelect(id); onClose() }} />
          ))}
        </nav>

        <div className="space-y-1 border-t border-slate-800 p-2">
          <button className="nav-item" onClick={() => onDemo('acme')} disabled={busy || backendDown} title="Synthetic five-host estate, built offline">
            {busy ? <Loader2 className="h-4 w-4 animate-spin text-slate-400" /> : <FlaskConical className="h-4 w-4 text-slate-400" />}Load ACME demo
          </button>
          <button className="nav-item" onClick={() => onDemo('testbeds')} disabled={busy || backendDown} title="Recorded passive run against badssl.com, vulnweb and other public test beds">
            <Globe2 className="h-4 w-4 text-slate-400" />Load test-bed demo
          </button>
          <button className="nav-item" onClick={onToggleTheme}>
            {theme === 'dark' ? <Sun className="h-4 w-4 text-slate-400" /> : <Moon className="h-4 w-4 text-slate-400" />}
            {theme === 'dark' ? 'Light theme' : 'Dark theme'}
          </button>
          <div className="flex items-center gap-2 px-2 py-1.5 text-[11px] text-slate-500">
            <span className={`h-1.5 w-1.5 rounded-full ${backendDown ? 'bg-red-400' : health ? 'bg-emerald-400' : 'bg-slate-500'}`} />
            {backendDown ? 'API unreachable' : health ? <>API v{health.version}{health.pdf_engine ? '' : ', HTML reports only'}</> : 'Connecting to API'}
          </div>
        </div>
      </aside>
    </>
  )
}

function EmptyState({ onDemo, onNew, busy, backendDown }) {
  return (
    <div className="mx-auto mt-[12vh] max-w-xl">
      <h1 className="text-[28px] font-semibold leading-tight tracking-tight text-slate-100">Audit a web estate against the OWASP Top 10 (2025)</h1>
      <p className="mt-3 text-[15px] leading-relaxed text-slate-400">
        Give WAPTrix a list of hosts. It reads headers, TLS, cookies, CORS, forms and disclosure with read-only requests,
        then grades every host and maps each finding to CWE, WSTG v4.2 and CVSS v3.1. Active scanners run only when you opt in.
      </p>
      {backendDown && (
        <div className="mt-5 rounded-md border border-red-500/30 bg-red-500/5 p-3 text-[13px] text-red-200">
          The API isn't reachable. Start it from <code className="font-mono">backend/</code> with{' '}
          <code className="font-mono">uvicorn app.main:app --port 8000</code>, or run <code className="font-mono">docker compose up</code>.
        </div>
      )}
      <div className="mt-6 flex flex-wrap gap-2">
        <button className="btn-primary" onClick={onNew} disabled={backendDown}><Plus className="h-4 w-4" />New audit</button>
        <button className="btn-ghost" onClick={() => onDemo('acme')} disabled={busy || backendDown}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <FlaskConical className="h-4 w-4" />}Load ACME demo
        </button>
        <button className="btn-ghost" onClick={() => onDemo('testbeds')} disabled={busy || backendDown}>
          <Globe2 className="h-4 w-4" />Load test-bed demo
        </button>
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
  const [navOpen, setNavOpen] = useState(false)
  const [theme, toggleTheme] = useTheme()
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

  async function loadDemo(dataset = 'acme') {
    setBusy(true)
    try {
      const demo = await api.loadDemo(dataset)
      await refreshList()
      setSelectedId(demo.id)
      setTab('overview')
      notify({ type: 'success', message: dataset === 'testbeds'
        ? 'Test-bed demo loaded: a recorded passive run against public test sites.'
        : 'ACME demo loaded: synthetic data, no network access.' })
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

  const activeMode = audit?.request?.active && audit?.request?.active_tools?.length > 0

  return (
    <CatalogContext.Provider value={catalog}>
    <PanelContext.Provider value={panelApi}>
    <div className="flex min-h-screen bg-ink-950">
      <Sidebar audits={audits} selectedId={selectedId} onSelect={setSelectedId} onNew={() => setShowNew(true)} onDemo={loadDemo}
        busy={busy} backendDown={backendDown} health={health} theme={theme} onToggleTheme={toggleTheme}
        open={navOpen} onClose={() => setNavOpen(false)} />

      <div className="flex min-w-0 flex-1 flex-col lg:py-2 lg:pr-2">
        <div className="flex min-h-0 flex-1 flex-col bg-ink-900 lg:rounded-xl lg:border lg:border-slate-800">
          <div className="flex items-center gap-2 border-b border-slate-800 px-4 py-2.5 lg:hidden">
            <button className="rounded-md p-1.5 text-slate-300 hover:bg-ink-800" onClick={() => setNavOpen(true)} aria-label="Open audit history"><Menu className="h-5 w-5" /></button>
            <Logo />
            <span className="font-semibold text-slate-100">WAPTrix</span>
          </div>

          {completed && (
            <header className="sticky top-0 z-20 border-b border-slate-800 bg-ink-900/95 px-5 pt-5 backdrop-blur sm:px-8 lg:rounded-t-xl">
              <div className="flex flex-wrap items-start gap-x-6 gap-y-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h1 className="truncate text-xl font-semibold tracking-tight text-slate-100">{audit.authorization_ref}</h1>
                    {audit.demo && <span className="chip bg-violet-500/10 text-violet-300">Demo data</span>}
                    <span className={`chip ${activeMode ? 'bg-red-500/10 text-red-300' : 'bg-emerald-500/10 text-emerald-300'}`}>
                      {activeMode ? 'Active scan' : 'Passive only'}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-slate-500">
                    Completed {formatDate(audit.completed_at)}, engine v{audit.engine_version}, ID <span className="font-mono">{audit.id.slice(0, 8)}</span>
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <ExportMenu auditId={audit.id} label="Export" onNotify={notify} />
                  <button className="btn-ghost px-2" onClick={removeAudit} title="Delete audit" aria-label="Delete audit"><Trash2 className="h-4 w-4" /></button>
                </div>
              </div>
              <nav className="-mb-px mt-3 flex gap-5 overflow-x-auto" aria-label="Sections">
                {TABS.map((t) => (
                  <button key={t.id} className={`tab shrink-0 ${tab === t.id ? 'tab-active' : ''}`} onClick={() => setTab(t.id)} aria-current={tab === t.id ? 'page' : undefined}>{t.label}</button>
                ))}
              </nav>
            </header>
          )}

          <main className="flex-1 px-5 py-6 sm:px-8">
            {!audit && <EmptyState onDemo={loadDemo} onNew={() => setShowNew(true)} busy={busy} backendDown={backendDown} />}

            {audit?.status === 'running' && <LiveRun audit={audit} />}

            {audit?.status === 'failed' && (
              <div className="mx-auto mt-[10vh] max-w-xl">
                <XCircle className="h-6 w-6 text-red-300" />
                <h2 className="mt-3 text-lg font-semibold text-slate-100">Audit {audit.authorization_ref} failed</h2>
                <p className="mt-1 font-mono text-[13px] text-red-300">{audit.error}</p>
                <p className="mt-3 text-[13px] text-slate-400">Check the targets and scope, then start a new audit.</p>
                <button className="btn-ghost mt-4" onClick={() => setShowNew(true)}><Plus className="h-4 w-4" />New audit</button>
              </div>
            )}

            {completed && (
              <div className="mx-auto max-w-[1360px]">
                {audit.scope_rejections.length > 0 && (
                  <div className="mb-5 rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-[13px] text-amber-200">
                    <AlertTriangle className="mr-1.5 inline h-4 w-4 text-amber-300" />
                    The scope guard rejected {audit.scope_rejections.length} input{audit.scope_rejections.length === 1 ? '' : 's'}:{' '}
                    {audit.scope_rejections.map((r) => (
                      <span key={r.input} className="mr-3 font-mono text-xs">{r.input} <span className="opacity-70">({r.reason})</span></span>
                    ))}
                  </div>
                )}

                {tab === 'overview' && <Overview audit={audit} onSelectSubdomain={openSubdomain} />}
                {tab === 'subdomains' && <SubdomainTable audit={audit} onSelect={openSubdomain} />}
                {tab === 'findings' && <FindingsExplorer audit={audit} />}
                {tab === 'workflow' && <WorkflowView audit={audit} />}
                {tab === 'rules' && <RulesCatalog />}
              </div>
            )}
          </main>

          <footer className="px-5 pb-5 text-[11px] text-slate-500 sm:px-8">
            Passive and read-only by default. Active scanners run only on explicit opt-in, inside declared scope domains. Audit only systems you're authorized to test.
          </footer>
        </div>
      </div>

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
