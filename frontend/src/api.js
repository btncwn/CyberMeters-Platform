const BASE =
  import.meta.env.VITE_API_BASE_URL ||
  'https://cybermeters-platform.ttrnn47.workers.dev/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  /** GET /api/scans */
  getScans: () => request('/scans'),

  /** GET /api/scans/:id */
  getScan: (id) => request(`/scans/${id}`),

  /** GET /api/scans/:id/report */
  getScanReport: (id) => request(`/scans/${id}/report`),

  /** GET /api/domain/:domain/history */
  getDomainHistory: (domain) => request(`/domain/${encodeURIComponent(domain)}/history`),

  /** POST /api/scan  body: { domain } */
  createScan: (domain) =>
    request('/scan', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    }),
}
