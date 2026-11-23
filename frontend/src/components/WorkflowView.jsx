import { useMemo } from 'react'
import { GitBranch, RotateCcw, Scale, Workflow } from 'lucide-react'
import FindingCard from './FindingCard'
import RunLog from './RunLog'
import StageTimeline from './StageTimeline'
import ToolRunsTable from './ToolRunsTable'

function Stat({ label, value, sub }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-ink-900/60 px-4 py-3">
      <div className="panel-title">{label}</div>
      <div className="mt-1 text-xl font-bold text-white">{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-slate-500">{sub}</div>}
    </div>
  )
}

// "Workflow" tab: how the six-stage assessment actually ran — stages, voting outcome, re-test loop, tools, log.
export default function WorkflowView({ audit }) {
  const stats = useMemo(() => {
    const subs = audit.subdomains
    const admitted = subs.flatMap((s) => s.findings)
    const queued = subs.flatMap((s) => s.retest_queue ?? [])
    const runs = subs.flatMap((s) => (s.tool_runs ?? []).map((r) => ({ ...r, subdomain: s.subdomain })))
    const maps = subs.filter((s) => s.app_map)
    return {
      admitted: admitted.length,
      confirmed: admitted.filter((f) => f.correlation?.confirmed).length,
      corroborated: admitted.filter((f) => (f.correlation?.detectors?.length ?? f.sources?.length ?? 0) > 1).length,
      queued,
      runs,
      endpoints: maps.reduce((n, s) => n + s.app_map.endpoints.length, 0),
      parameterised: maps.reduce((n, s) => n + s.app_map.endpoints.filter((e) => e.params.length).length, 0),
      retestHosts: subs.filter((s) => s.retest_rounds_run > 0).length,
      retestRounds: subs.reduce((n, s) => n + (s.retest_rounds_run ?? 0), 0),
      tau: [...admitted, ...queued].find((f) => f.correlation)?.correlation.threshold,
    }
  }, [audit])

  const hasLog = (audit.run_log ?? []).length > 0

  return (
    <div className="space-y-5">
      <section className="panel p-4">
        <div className="mb-3 flex items-center gap-2">
          <Workflow className="h-4 w-4 text-accent-300" />
          <h2 className="panel-title">Six-stage assessment workflow</h2>
        </div>
        {hasLog ? (
          <StageTimeline summaries={audit.stages ?? []} />
        ) : (
          <p className="text-sm text-slate-400">
            This audit has no stage log. It was recorded before the stage scheduler existed, or it is demo data.
          </p>
        )}
      </section>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Admitted findings" value={stats.admitted}
          sub={`${stats.corroborated} corroborated by >1 engine · ${stats.confirmed} actively confirmed`} />
        <Stat label="Awaiting re-test" value={stats.queued.length}
          sub={stats.tau != null ? `C(f) below τ = ${stats.tau}` : 'Below the voting threshold'} />
        <Stat label="Re-test loop" value={stats.retestRounds}
          sub={`round(s) on ${stats.retestHosts} host(s)`} />
        <Stat label="Application map" value={stats.endpoints}
          sub={`endpoints · ${stats.parameterised} with parameters`} />
      </div>

      <section className="panel p-4">
        <div className="mb-3 flex items-center gap-2">
          <RotateCcw className="h-4 w-4 text-violet-300" />
          <h2 className="panel-title">Re-test queue ({stats.queued.length})</h2>
        </div>
        <p className="mb-3 text-xs leading-relaxed text-slate-400">
          Candidates whose weighted agreement C(f) stayed below τ after every re-test round. They are not reported as
          findings and do not affect scores. Each one needs either an engine that can confirm it, or a manual check.
        </p>
        {stats.queued.length === 0 ? (
          <p className="text-sm text-slate-500">Nothing is waiting for re-test.</p>
        ) : (
          <div className="space-y-2">
            {stats.queued.map((f) => <FindingCard key={`${f.subdomain}-${f.id}`} finding={f} showSubdomain />)}
          </div>
        )}
      </section>

      <section className="panel p-4">
        <div className="mb-3 flex items-center gap-2">
          <GitBranch className="h-4 w-4 text-accent-300" />
          <h2 className="panel-title">Tool runs ({stats.runs.length})</h2>
        </div>
        <ToolRunsTable runs={stats.runs} showSubdomain />
      </section>

      {hasLog && (
        <section className="panel p-4">
          <div className="mb-3 flex items-center gap-2">
            <Scale className="h-4 w-4 text-accent-300" />
            <h2 className="panel-title">Run log</h2>
          </div>
          <RunLog events={audit.run_log} />
        </section>
      )}
    </div>
  )
}
