import { GRADE_META, SEVERITY_META, STATUS_META } from '../lib/format'

export function SeverityBadge({ severity, count }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.info
  return (
    <span className={`chip ${meta.chip}`}>
      {meta.label}
      {count !== undefined && <span className="font-mono">{count}</span>}
    </span>
  )
}

export function StatusBadge({ status, compact = false }) {
  const meta = STATUS_META[status] ?? STATUS_META.manual_review
  return (
    <span className="chip text-slate-300">
      <span className={`h-2 w-2 rounded-full ${meta.dot}`} />
      {compact ? meta.short : meta.label}
    </span>
  )
}

export function GradeBadge({ grade, size = 'md' }) {
  const cls = GRADE_META[grade] ?? GRADE_META['N/A']
  const sizing = size === 'lg' ? 'h-14 w-14 rounded-lg text-3xl' : size === 'sm' ? 'h-7 min-w-7 rounded-md px-1 text-[13px]' : 'h-8 min-w-8 rounded-md px-1.5 text-sm'
  return (
    <span className={`inline-flex shrink-0 items-center justify-center font-semibold ${sizing} ${cls}`}>
      {grade}
    </span>
  )
}
