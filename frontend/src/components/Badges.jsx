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
    <span className={`chip ring-1 ${meta.cell}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {compact ? meta.short : meta.label}
    </span>
  )
}

export function GradeBadge({ grade, size = 'md' }) {
  const cls = GRADE_META[grade] ?? GRADE_META['N/A']
  const sizing = size === 'lg' ? 'h-14 w-14 text-3xl' : size === 'sm' ? 'h-6 min-w-6 px-1 text-xs' : 'h-8 min-w-8 px-1.5 text-sm'
  return (
    <span className={`inline-flex items-center justify-center rounded-lg font-extrabold ring-1 ${sizing} ${cls}`}>
      {grade}
    </span>
  )
}
