import { useRef, useState } from 'react'
import { FileUp, Loader2, Play, ShieldAlert, X } from 'lucide-react'

const DEFAULT_OPTIONS = { concurrency: 5, requests_per_second: 2, timeout: 10, include_metadata: true, allow_private: false }

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
  const fileRef = useRef(null)

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
        scope_domains: parseTargets(scope),
        ...options,
        concurrency: Number(options.concurrency),
        requests_per_second: Number(options.requests_per_second),
        timeout: Number(options.timeout),
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
            <h2 className="text-lg font-semibold text-white">New passive audit</h2>
            <p className="mt-1 text-sm text-slate-400">
              Read-only <span className="font-mono text-slate-300">GET</span> requests and TLS handshakes only. No
              fuzzing, injection or brute-forcing.
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
          <button type="submit" className="btn-primary" disabled={busy || !attested || parsed.length === 0 || authRef.trim().length < 3}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Start passive audit
          </button>
        </div>
      </form>
    </div>
  )
}
