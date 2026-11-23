export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_META = {
  critical: { label: 'Critical', color: '#e11d48', chip: 'bg-rose-500/15 text-rose-300' },
  high: { label: 'High', color: '#ef4444', chip: 'bg-red-500/10 text-red-300' },
  medium: { label: 'Medium', color: '#f97316', chip: 'bg-orange-500/10 text-orange-300' },
  low: { label: 'Low', color: '#eab308', chip: 'bg-yellow-500/10 text-yellow-300' },
  info: { label: 'Info', color: '#3b82f6', chip: 'bg-sky-500/10 text-sky-300' },
}

export const STATUS_META = {
  pass: { label: 'Pass', short: 'Pass', cell: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/25', dot: 'bg-emerald-400' },
  warning: { label: 'Warning', short: 'Warn', cell: 'bg-yellow-500/15 text-yellow-300 ring-yellow-500/30', dot: 'bg-yellow-400' },
  fail: { label: 'Fail', short: 'Fail', cell: 'bg-red-500/15 text-red-300 ring-red-500/30', dot: 'bg-red-400' },
  manual_review: { label: 'Manual review', short: 'Manual', cell: 'bg-slate-500/10 text-slate-400 ring-slate-500/20', dot: 'bg-slate-500' },
}

export const GRADE_META = {
  A: 'text-emerald-300 bg-emerald-500/15',
  B: 'text-lime-300 bg-lime-500/15',
  C: 'text-yellow-300 bg-yellow-500/15',
  D: 'text-orange-300 bg-orange-500/15',
  F: 'text-red-300 bg-red-500/15',
  'N/A': 'text-slate-400 bg-slate-500/10',
}

export const COVERAGE_LABEL = {
  high: 'High',
  partial: 'Partial',
  indicators: 'Indicators only',
  manual: 'Manual only',
}

export function scoreColor(score) {
  if (score === null || score === undefined) return '#94a3b8'
  if (score >= 90) return '#10b981'
  if (score >= 80) return '#84cc16'
  if (score >= 70) return '#eab308'
  if (score >= 60) return '#f97316'
  return '#ef4444'
}

export function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function shortCat(id) {
  return id.split(':')[0]
}

export function allFindings(audit) {
  return (audit?.subdomains ?? []).flatMap((s) => s.findings)
}
