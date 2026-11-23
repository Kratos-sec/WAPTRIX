// The six-stage assessment workflow (paper Section III-C, Fig. 3), mirrored from the backend Stage enum.
export const STAGES = [
  { id: 'S1', name: 'Scope & authorisation', blurb: 'Authorisation record, in-scope hosts, request budget' },
  { id: 'S2', name: 'Passive reconnaissance', blurb: 'DNS, read-only GETs, TLS, built-in checks, passive tools' },
  { id: 'S3', name: 'Application map', blurb: 'URL tree and parameter inventory from observed content' },
  { id: 'S4', name: 'Phase controllers', blurb: 'Active engines against the map, under the rate governor' },
  { id: 'S5', name: 'Correlation', blurb: 'Cross-tool voting (eq. 1); below-τ candidates re-enter S3' },
  { id: 'S6', name: 'Risk & report', blurb: 'Per-host scoring, grading and the engagement summary' },
]

export const STAGE_STATUS = {
  completed: { label: 'Done', dot: 'bg-emerald-400', text: 'text-emerald-300', ring: 'ring-emerald-500/40 bg-emerald-500/10' },
  skipped: { label: 'Skipped', dot: 'bg-slate-500', text: 'text-slate-400', ring: 'ring-slate-600/50 bg-slate-500/5' },
  failed: { label: 'Failed', dot: 'bg-red-400', text: 'text-red-300', ring: 'ring-red-500/40 bg-red-500/10' },
  started: { label: 'Running', dot: 'bg-accent-400 animate-pulse', text: 'text-accent-300', ring: 'ring-accent-500/50 bg-accent-500/10' },
  info: { label: 'Info', dot: 'bg-sky-400', text: 'text-sky-300', ring: 'ring-sky-500/40 bg-sky-500/10' },
  pending: { label: 'Pending', dot: 'bg-slate-700', text: 'text-slate-500', ring: 'ring-slate-800 bg-transparent' },
}

export function formatMs(ms) {
  if (ms === null || ms === undefined) return '—'
  if (ms < 1000) return `${ms} ms`
  const s = ms / 1000
  return s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`
}

export function formatCounts(counts) {
  return Object.entries(counts ?? {}).map(([k, v]) => `${k} ${v}`).join(' · ')
}

// Live stage state from a (possibly partial) run log. Hosts run concurrently, so a stage is "started" while
// any host/round still has it open; otherwise it takes its worst finished status (failed > done > skipped).
const RANK = { skipped: 0, completed: 1, failed: 2 }
export function liveStageState(events) {
  const open = {}
  const finished = {}
  for (const e of events) {
    if (e.status === 'info') continue
    const key = `${e.subdomain ?? ''}|${e.round}`
    open[e.stage] ??= new Set()
    if (e.status === 'started') {
      open[e.stage].add(key)
    } else {
      open[e.stage].delete(key)
      if (finished[e.stage] === undefined || RANK[e.status] > RANK[finished[e.stage]]) finished[e.stage] = e.status
    }
  }
  const state = {}
  for (const { id } of STAGES) {
    if (open[id]?.size) state[id] = 'started'
    else if (finished[id]) state[id] = finished[id]
  }
  return state
}
