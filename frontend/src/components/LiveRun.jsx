import { useEffect, useRef, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { api } from '../lib/api'
import { STAGES, liveStageState } from '../lib/stages'
import RunLog from './RunLog'
import StageTimeline from './StageTimeline'

// Running-audit view: overall progress, live S1–S6 stepper and the run log, polled incrementally.
export default function LiveRun({ audit }) {
  const [events, setEvents] = useState([])
  const cursor = useRef(0)

  useEffect(() => {
    cursor.current = 0
    setEvents([])
    let cancelled = false
    let timer
    const poll = async () => {
      try {
        const fresh = await api.auditLog(audit.id, cursor.current)
        if (cancelled) return
        if (fresh.length) {
          cursor.current = fresh[fresh.length - 1].seq
          setEvents((prev) => [...prev, ...fresh])
        }
      } catch {
        /* transient: keep polling */
      }
      if (!cancelled) timer = setTimeout(poll, 1500)
    }
    poll()
    return () => { cancelled = true; clearTimeout(timer) }
  }, [audit.id])

  const progress = audit.progress
  const stage = STAGES.find((s) => s.id === progress?.stage)
  const activeMode = audit.request?.active && audit.request?.active_tools?.length > 0

  return (
    <div className="mx-auto mt-6 max-w-5xl space-y-4">
      <div className="panel p-6">
        <div className="flex flex-wrap items-center gap-4">
          <Loader2 className="h-7 w-7 animate-spin text-cyan-300" />
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-semibold text-white">{activeMode ? 'Active' : 'Passive'} audit in progress</h2>
            <p className="text-sm text-slate-400">
              Authorization {audit.authorization_ref}
              {stage && <> · now in <span className="font-mono text-cyan-300">{stage.id}</span> {stage.name}{progress.stage_host ? ` on ${progress.stage_host}` : ''}</>}
            </p>
          </div>
          {progress && (
            <p className="font-mono text-xs text-slate-400">
              {progress.done}/{progress.total} subdomains{progress.current ? ` · last: ${progress.current}` : ''}
            </p>
          )}
        </div>
        {progress && (
          <div className="mt-4 h-2 overflow-hidden rounded-full bg-ink-700">
            <div className="h-full rounded-full bg-cyan-400 transition-all" style={{ width: `${(100 * progress.done) / Math.max(progress.total, 1)}%` }} />
          </div>
        )}
        <div className="mt-5">
          <StageTimeline state={liveStageState(events)} compact />
        </div>
      </div>
      <div className="panel p-4">
        <div className="panel-title mb-3">Live run log</div>
        <RunLog events={events} follow maxHeight="max-h-80" />
      </div>
    </div>
  )
}
