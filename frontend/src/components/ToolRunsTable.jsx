import { formatMs } from '../lib/stages'

function outcome(run) {
  if (run.error?.startsWith('skipped')) return { text: run.error, cls: 'text-slate-500' }
  if (run.timed_out) return { text: 'timed out', cls: 'text-orange-300' }
  if (run.error) return { text: run.error, cls: 'text-red-300' }
  return { text: `exit ${run.exit_code ?? 0}`, cls: 'text-emerald-300' }
}

// Every external tool invocation: which stage and re-test round it belonged to, and what it targeted.
export default function ToolRunsTable({ runs, showSubdomain = false }) {
  if (!runs.length) return <p className="text-xs text-slate-500">No external tools ran.</p>
  return (
    <div className="overflow-auto rounded-md border border-slate-800">
      <table className="w-full text-[11px]">
        <thead className="bg-ink-900 text-left text-slate-500">
          <tr>
            {showSubdomain && <th className="px-2 py-1.5 font-medium">Host</th>}
            <th className="px-2 py-1.5 font-medium">Tool</th>
            <th className="px-2 py-1.5 font-medium">Stage</th>
            <th className="px-2 py-1.5 font-medium">Target</th>
            <th className="px-2 py-1.5 font-medium">Outcome</th>
            <th className="px-2 py-1.5 text-right font-medium">Findings</th>
            <th className="px-2 py-1.5 text-right font-medium">Time</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60 font-mono">
          {runs.map((run, i) => {
            const o = outcome(run)
            return (
              <tr key={`${run.subdomain ?? ''}-${run.tool}-${run.target_url ?? ''}-${run.round}-${i}`} className="align-top">
                {showSubdomain && <td className="whitespace-nowrap px-2 py-1.5 text-cyan-300/80">{run.subdomain}</td>}
                <td className="whitespace-nowrap px-2 py-1.5 text-slate-100">{run.tool}</td>
                <td className="whitespace-nowrap px-2 py-1.5 text-cyan-300">
                  {run.stage ?? '—'}{run.round > 0 && <span className="ml-1 text-violet-300" title="Re-test round">r{run.round}</span>}
                </td>
                <td className="max-w-[18rem] break-all px-2 py-1.5 text-slate-400">{run.target_url ?? '—'}</td>
                <td className={`max-w-[16rem] break-words px-2 py-1.5 ${o.cls}`} title={run.stderr_tail || undefined}>{o.text}</td>
                <td className="px-2 py-1.5 text-right text-slate-200">{run.finding_count}</td>
                <td className="whitespace-nowrap px-2 py-1.5 text-right text-slate-500">{formatMs(Math.round((run.duration_s ?? 0) * 1000))}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
