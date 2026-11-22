import { useMemo, useState } from 'react'
import { STAGES, STAGE_STATUS, formatCounts, formatMs } from '../lib/stages'

function time(at) {
  return new Date(at).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

// Run log viewer: every stage transition, filterable by host and stage. Hides "started" rows by default.
export default function RunLog({ events, maxHeight = 'max-h-[28rem]', follow = false }) {
  const [host, setHost] = useState('')
  const [stage, setStage] = useState('')
  const [showStarts, setShowStarts] = useState(false)
  const hosts = useMemo(() => [...new Set(events.map((e) => e.subdomain).filter(Boolean))].sort(), [events])

  const rows = events.filter((e) =>
    (showStarts || e.status !== 'started')
    && (!host || e.subdomain === host || (host === '__engagement' && !e.subdomain))
    && (!stage || e.stage === stage))
  const shown = follow ? rows.slice(-200).reverse() : rows

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
        <select className="input w-auto py-1 text-xs" value={host} onChange={(e) => setHost(e.target.value)} aria-label="Filter by host">
          <option value="">All hosts</option>
          <option value="__engagement">Engagement-wide</option>
          {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <select className="input w-auto py-1 text-xs" value={stage} onChange={(e) => setStage(e.target.value)} aria-label="Filter by stage">
          <option value="">All stages</option>
          {STAGES.map((s) => <option key={s.id} value={s.id}>{s.id} {s.name}</option>)}
        </select>
        <label className="flex items-center gap-1.5 text-slate-400">
          <input type="checkbox" className="accent-cyan-400" checked={showStarts} onChange={(e) => setShowStarts(e.target.checked)} />
          Show stage starts
        </label>
        <span className="ml-auto font-mono text-slate-500">{rows.length} event(s){follow ? ' · newest first' : ''}</span>
      </div>
      <div className={`${maxHeight} overflow-auto rounded-md border border-slate-800 bg-ink-950`}>
        {shown.length === 0 ? (
          <p className="p-4 text-xs text-slate-500">No events in this view.</p>
        ) : (
          <table className="w-full text-[11px]">
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {shown.map((e) => {
                const meta = STAGE_STATUS[e.status] ?? STAGE_STATUS.info
                return (
                  <tr key={e.seq} className="align-top">
                    <td className="whitespace-nowrap px-2 py-1.5 text-slate-500">{time(e.at)}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-cyan-300">
                      {e.stage}{e.round > 0 && <span className="ml-1 text-violet-300" title="Re-test round">r{e.round}</span>}
                    </td>
                    <td className={`whitespace-nowrap px-2 py-1.5 ${meta.text}`}>{meta.label.toLowerCase()}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-slate-300">{e.subdomain ?? <span className="text-slate-500">engagement</span>}</td>
                    <td className="px-2 py-1.5 text-slate-400">
                      {e.detail && <span className="block break-words text-slate-300">{e.detail}</span>}
                      {Object.keys(e.counts ?? {}).length > 0 && <span className="block">{formatCounts(e.counts)}</span>}
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-right text-slate-500">{e.duration_ms != null ? formatMs(e.duration_ms) : ''}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
