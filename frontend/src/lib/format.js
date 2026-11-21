export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_META = {
  critical: { label: 'Critical', color: '#f43f5e', chip: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/40' },
  high: { label: 'High', color: '#f87171', chip: 'bg-red-500/15 text-red-300 ring-1 ring-red-500/40' },
  medium: { label: 'Medium', color: '#fb923c', chip: 'bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/40' },
  low: { label: 'Low', color: '#facc15', chip: 'bg-yellow-500/10 text-yellow-200 ring-1 ring-yellow-500/30' },
  info: { label: 'Info', color: '#60a5fa', chip: 'bg-sky-500/10 text-sky-300 ring-1 ring-sky-500/30' },
}

export const STATUS_META = {
  pass: { label: 'Pass', short: 'PASS', cell: 'bg-emerald-500/20 text-emerald-300 ring-emerald-500/40', dot: 'bg-emerald-400' },
  warning: { label: 'Warning', short: 'WARN', cell: 'bg-yellow-500/15 text-yellow-200 ring-yellow-500/40', dot: 'bg-yellow-400' },
  fail: { label: 'Fail', short: 'FAIL', cell: 'bg-red-500/20 text-red-300 ring-red-500/40', dot: 'bg-red-400' },
  manual_review: { label: 'Manual Review', short: 'MANUAL', cell: 'bg-slate-500/15 text-slate-300 ring-slate-500/30', dot: 'bg-slate-400' },
}

export const GRADE_META = {
  A: 'text-emerald-300 bg-emerald-500/15 ring-emerald-500/40',
  B: 'text-lime-300 bg-lime-500/15 ring-lime-500/40',
  C: 'text-yellow-200 bg-yellow-500/15 ring-yellow-500/40',
  D: 'text-orange-300 bg-orange-500/15 ring-orange-500/40',
  F: 'text-red-300 bg-red-500/15 ring-red-500/40',
  'N/A': 'text-slate-400 bg-slate-500/10 ring-slate-500/30',
}

export const COVERAGE_LABEL = {
  high: 'High',
  partial: 'Partial',
  indicators: 'Indicators only',
  manual: 'Manual only',
}

export function scoreColor(score) {
  if (score === null || score === undefined) return '#64748b'
  if (score >= 90) return '#34d399'
  if (score >= 80) return '#a3e635'
  if (score >= 70) return '#facc15'
  if (score >= 60) return '#fb923c'
  return '#f87171'
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
