import { useEffect, useRef, useState } from 'react'
import { FileUp, Loader2, Play, ShieldAlert, Swords, Wrench, X } from 'lucide-react'
import { api } from '../lib/api'

const DEFAULT_OPTIONS = {
  concurrency: 5, requests_per_second: 2, timeout: 10, include_metadata: true, allow_private: false,
  tool_timeout: 600, retest_rounds: 1, max_endpoints: 5,
}

// Adapter name -> registry entry that reports its availability (zap-active is served by the ZAP daemon).
const PASSIVE_TOOLS = [['whatweb', 'whatweb'], ['sslyze', 'sslyze'], ['testssl', 'testssl'], ['retire', 'retire'], ['zap', 'zap']]
const ACTIVE_TOOLS = [['nmap', 'nmap'], ['nuclei', 'nuclei'], ['nikto', 'nikto'], ['wapiti', 'wapiti'], ['sqlmap', 'sqlmap'], ['zap-active', 'zap']]

function ToolPicker({ tools, registry, selected, onToggle, tone = 'cyan' }) {
  return (
    <div className="grid gap-1.5 sm:grid-cols-2">
      {tools.map(([name, entry]) => {
        const info = registry?.[entry]
        const available = registry ? Boolean(info?.available) : true
        return (
          <label key={name} title={info?.purpose}
            className={`flex items-start gap-2 rounded-md border px-2.5 py-1.5 text-xs ${available ? 'border-slate-800 hover:border-slate-700' : 'border-slate-800/60 opacity-50'}`}>
            <input type="checkbox" className={`mt-0.5 ${tone === 'red' ? 'accent-red-400' : 'accent-cyan-400'}`}
              checked={selected.includes(name)} disabled={!available} onChange={() => onToggle(name)} />
            <span className="min-w-0">
              <span className="font-mono text-slate-100">{name}</span>
              <span className="ml-1.5 text-[10px] text-slate-500">
                {!registry ? '' : available ? (info?.version ? `v${info.version}` : 'available') : 'not installed'}
              </span>
            </span>
          </label>
        )
      })}
    </div>
  )
}

function parseTargets(text) {
  return [...new Set(
    text
      .split(/[\s,;]+/)
      .map((t) => t.trim())
      .filter((t) => t && !t.startsWith('#')),
  )]
}

export default function NewAuditPanel({ onSubmit, onClose, busy }) {
  const [targets, setTargets] = useState('')
  const [authRef, setAuthRef] = useState('')
  const [scope, setScope] = useState('')
  const [options, setOptions] = useState(DEFAULT_OPTIONS)
  const [attested, setAttested] = useState(false)
  const [error, setError] = useState(null)
  const [registry, setRegistry] = useState(null)
  const [tools, setTools] = useState([])
  const [active, setActive] = useState(false)
  const [activeTools, setActiveTools] = useState([])
  const [activeAttested, setActiveAttested] = useState(false)
  const fileRef = useRef(null)

  useEffect(() => {
    api.tools()
      .then((list) => setRegistry(Object.fromEntries(list.map((t) => [t.name, t]))))
      .catch(() => setRegistry(null))
  }, [])

  const toggle = (setter) => (name) => setter((list) => (list.includes(name) ? list.filter((t) => t !== name) : [...list, name]))
  const scopeDomains = parseTargets(scope)
  const activeOn = active && activeTools.length > 0
  const activeBlocked = active && (activeTools.length === 0 || scopeDomains.length === 0 || !activeAttested)

  const parsed = parseTargets(targets)

  async function handleFile(event) {
    const file = event.target.files?.[0]
    if (!file) return
    const text = await file.text()
    setTargets((prev) => (prev ? `${prev}\n${text}` : text))
    event.target.value = ''
  }

  async function submit(event) {
    event.preventDefault()
    setError(null)
    try {
      await onSubmit({
        subdomains: parsed,
        authorization_ref: authRef.trim(),
        scope_domains: scopeDomains,
        ...options,
        concurrency: Number(options.concurrency),
        requests_per_second: Number(options.requests_per_second),
        timeout: Number(options.timeout),
        tool_timeout: Number(options.tool_timeout),
        retest_rounds: Number(options.retest_rounds),
        max_endpoints: Number(options.max_endpoints),
        tools,
        active: activeOn,
        active_tools: activeOn ? activeTools : [],
      })
    } catch (err) {
      setError(err.message)
    }
  }

  const setOpt = (key) => (e) =>
    setOptions((o) => ({ ...o, [key]: e.target.type === 'checkbox' ? e.target.checked : e.target.value }))

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-ink-950/80 p-4 backdrop-blur-sm sm:p-10">
      <form onSubmit={submit} className="panel w-full max-w-3xl p-6">
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white">New {activeOn ? 'active' : 'passive'} audit</h2>
            <p className="mt-1 text-sm text-slate-400">
              {activeOn ? (
                <span className="text-red-200">Active mode: the selected engines send probes and payloads to in-scope hosts.</span>
              ) : (
                <>Read-only <span className="font-mono text-slate-300">GET</span> requests and TLS handshakes only. No
                fuzzing, injection or brute-forcing.</>
              )}
            </p>
          </div>
          <button type="button" onClick={onClose} className="btn-ghost p-2" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="grid gap-4 md:grid-cols-5">
          <div className="md:col-span-3">
            <div className="mb-1 flex items-center justify-between">
              <label className="label mb-0" htmlFor="targets">Subdomains (one per line)</label>
              <button type="button" className="text-xs text-cyan-300 hover:text-cyan-200" onClick={() => fileRef.current?.click()}>
                <FileUp className="mr-1 inline h-3.5 w-3.5" />Upload .txt
              </button>
              <input ref={fileRef} type="file" accept=".txt,text/plain" className="hidden" onChange={handleFile} />
            </div>
            <textarea
              id="targets"
              className="input h-56 resize-y font-mono text-xs leading-relaxed"
              placeholder={'app.example.com\napi.example.com\nadmin.example.com'}
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              spellCheck={false}
            />
            <p className="mt-1 text-xs text-slate-500">{parsed.length} unique target(s). Wildcards are rejected.</p>
          </div>

          <div className="space-y-3 md:col-span-2">
            <div>
              <label className="label" htmlFor="authref">Authorization reference *</label>
              <input id="authref" className="input font-mono" placeholder="ENG-2026-001" value={authRef}
                onChange={(e) => setAuthRef(e.target.value)} required minLength={3} maxLength={64} />
            </div>
            <div>
              <label className="label" htmlFor="scope">Scope domains (optional)</label>
              <input id="scope" className="input font-mono" placeholder="example.com" value={scope}
                onChange={(e) => setScope(e.target.value)} />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="label" htmlFor="conc">Parallel</label>
                <input id="conc" type="number" min={1} max={20} className="input" value={options.concurrency} onChange={setOpt('concurrency')} />
              </div>
              <div>
                <label className="label" htmlFor="rps">Req/s/host</label>
                <input id="rps" type="number" min={0.1} max={10} step={0.1} className="input" value={options.requests_per_second} onChange={setOpt('requests_per_second')} />
              </div>
              <div>
                <label className="label" htmlFor="timeout">Timeout s</label>
                <input id="timeout" type="number" min={1} max={60} className="input" value={options.timeout} onChange={setOpt('timeout')} />
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" className="accent-cyan-400" checked={options.include_metadata} onChange={setOpt('include_metadata')} />
              Inspect robots.txt &amp; security.txt
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" className="accent-cyan-400" checked={options.allow_private} onChange={setOpt('allow_private')} />
              Allow private / internal IPs
            </label>
          </div>
        </div>

        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <div className="rounded-lg border border-slate-800 p-3">
            <div className="mb-2 flex items-center gap-2">
              <Wrench className="h-4 w-4 text-cyan-300" />
              <span className="panel-title">Passive tools · S2</span>
            </div>
            <p className="mb-2 text-[11px] text-slate-500">Run alongside the built-in checks. Only requests a normal visitor would make.</p>
            <ToolPicker tools={PASSIVE_TOOLS} registry={registry} selected={tools} onToggle={toggle(setTools)} />
            {registry === null && <p className="mt-2 text-[11px] text-slate-500">Tool status unavailable; the API reports unknown tools on submit.</p>}
          </div>

          <div className={`rounded-lg border p-3 ${active ? 'border-red-500/40 bg-red-500/5' : 'border-slate-800'}`}>
            <label className="mb-2 flex items-center gap-2">
              <input type="checkbox" className="accent-red-400" checked={active} onChange={(e) => setActive(e.target.checked)} />
              <Swords className={`h-4 w-4 ${active ? 'text-red-300' : 'text-slate-500'}`} />
              <span className="panel-title">Active scanning · S4 (opt-in)</span>
            </label>
            {!active ? (
              <p className="text-[11px] text-slate-500">
                Off. Turning it on lets the selected engines send probes and payloads. sqlmap runs in detection-only mode.
                You need scope domains and an explicit confirmation.
              </p>
            ) : (
              <div className="space-y-2">
                <ToolPicker tools={ACTIVE_TOOLS} registry={registry} selected={activeTools} onToggle={toggle(setActiveTools)} tone="red" />
                <div className="grid grid-cols-3 gap-2">
                  <div>
                    <label className="label" htmlFor="rounds" title="Bounded S5→S3 re-test rounds for below-τ candidates">Re-test rounds</label>
                    <input id="rounds" type="number" min={0} max={3} className="input" value={options.retest_rounds} onChange={setOpt('retest_rounds')} />
                  </div>
                  <div>
                    <label className="label" htmlFor="maxep" title="Parameterised endpoints per host for sqlmap">Endpoints/host</label>
                    <input id="maxep" type="number" min={1} max={50} className="input" value={options.max_endpoints} onChange={setOpt('max_endpoints')} />
                  </div>
                  <div>
                    <label className="label" htmlFor="tooltimeout">Tool limit s</label>
                    <input id="tooltimeout" type="number" min={10} max={3600} className="input" value={options.tool_timeout} onChange={setOpt('tool_timeout')} />
                  </div>
                </div>
                {scopeDomains.length === 0 && <p className="text-[11px] text-red-300">Set scope domains to bound the engagement.</p>}
                <label className="flex items-start gap-2 text-[11px] text-red-100">
                  <input type="checkbox" className="mt-0.5 accent-red-400" checked={activeAttested} onChange={(e) => setActiveAttested(e.target.checked)} />
                  My written authorization explicitly covers active testing (probes and injection payloads) of every listed host.
                </label>
              </div>
            )}
          </div>
        </div>

        <label className="mt-5 flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-100">
          <input type="checkbox" className="mt-0.5 accent-amber-400" checked={attested} onChange={(e) => setAttested(e.target.checked)} />
          <span>
            <ShieldAlert className="mr-1 inline h-4 w-4 text-amber-300" />
            I confirm I hold written authorization to assess every listed host under the reference above.
          </span>
        </label>

        {error && <p className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">{error}</p>}

        <div className="mt-5 flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className={activeOn ? 'btn bg-red-500 text-white hover:bg-red-400' : 'btn-primary'}
            disabled={busy || !attested || activeBlocked || parsed.length === 0 || authRef.trim().length < 3}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Start {activeOn ? 'active' : 'passive'} audit
          </button>
        </div>
      </form>
    </div>
  )
}
