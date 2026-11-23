const BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '')

async function request(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, {
    headers: options.body ? { 'Content-Type': 'application/json' } : undefined,
    ...options,
  })
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const payload = await response.json()
      if (typeof payload.detail === 'string') detail = payload.detail
      else if (Array.isArray(payload.detail)) {
        detail = payload.detail.map((d) => `${(d.loc || []).slice(1).join('.')}: ${d.msg}`).join('; ')
      }
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail)
  }
  if (response.status === 204) return null
  return response.json()
}

export const api = {
  health: () => request('/api/health'),
  categories: () => request('/api/owasp'),
  rules: () => request('/api/rules'),
  listAudits: () => request('/api/audits'),
  getAudit: (id) => request(`/api/audits/${encodeURIComponent(id)}`),
  auditLog: (id, after = 0) => request(`/api/audits/${encodeURIComponent(id)}/log?after=${after}`),
  tools: () => request('/api/tools'),
  createAudit: (body) => request('/api/audits', { method: 'POST', body: JSON.stringify(body) }),
  deleteAudit: (id) => request(`/api/audits/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  loadDemo: (dataset = 'acme') => request(`/api/demo?dataset=${dataset}`, { method: 'POST' }),
  exportUrl: (id, format, subdomain) => {
    const params = new URLSearchParams({ format })
    if (subdomain) params.set('subdomain', subdomain)
    return `${BASE}/api/audits/${encodeURIComponent(id)}/export?${params}`
  },
}

export async function downloadExport(id, format, subdomain) {
  const response = await fetch(api.exportUrl(id, format, subdomain))
  if (!response.ok) {
    let detail = `${response.status}`
    try {
      detail = (await response.json()).detail ?? detail
    } catch {
      /* ignore */
    }
    throw new Error(detail)
  }
  const disposition = response.headers.get('content-disposition') || ''
  const match = disposition.match(/filename="([^"]+)"/)
  const filename = match ? match[1] : `waptrix-report.${format}`
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
  return { filename, fallback: response.headers.get('x-waptrix-fallback') }
}
