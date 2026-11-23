import { STAGES, STAGE_STATUS, formatCounts, formatMs } from '../lib/stages'

// Six-step workflow stepper. `state` maps stage id -> status; `summaries` (optional) adds per-stage totals.
export default function StageTimeline({ state = {}, summaries = [], compact = false }) {
  const byStage = Object.fromEntries(summaries.map((s) => [s.stage, s]))
  return (
    <ol className={`grid gap-2 ${compact ? 'grid-cols-3 sm:grid-cols-6' : 'sm:grid-cols-2 lg:grid-cols-6'}`}>
      {STAGES.map((stage) => {
        const status = state[stage.id] ?? byStage[stage.id]?.status ?? 'pending'
        const meta = STAGE_STATUS[status] ?? STAGE_STATUS.pending
        const summary = byStage[stage.id]
        return (
          <li key={stage.id} className={`rounded-lg px-3 py-2.5 text-left ring-1 ${meta.ring}`} title={stage.blurb}>
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 shrink-0 rounded-full ${meta.dot}`} />
              <span className="font-mono text-xs font-semibold text-slate-200">{stage.id}</span>
              <span className={`ml-auto text-[11px] font-medium ${meta.text}`}>{meta.label}</span>
            </div>
            <div className={`mt-1 font-medium text-slate-100 ${compact ? 'text-[11px] leading-tight' : 'text-sm'}`}>{stage.name}</div>
            {!compact && (
              <div className="mt-1 text-[11px] leading-snug text-slate-500">
                {summary ? (
                  <>
                    <span className="font-mono text-slate-400">
                      {summary.hosts ? `${summary.hosts} host${summary.hosts === 1 ? '' : 's'} · ` : ''}
                      {summary.runs > 1 ? `${summary.runs} runs · ` : ''}{formatMs(summary.duration_ms)}
                    </span>
                    {Object.keys(summary.counts ?? {}).length > 0 && <span className="block">{formatCounts(summary.counts)}</span>}
                  </>
                ) : stage.blurb}
              </div>
            )}
          </li>
        )
      })}
    </ol>
  )
}
