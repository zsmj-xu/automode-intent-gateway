const TOKEN_KEY = 'automode.adminToken'

export class AuthError extends Error {
  constructor() {
    super('admin authentication required')
    this.name = 'AuthError'
  }
}

export function getAdminToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) || ''
  } catch {
    return ''
  }
}

export function setAdminToken(token: string): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token)
    else localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* storage unavailable: token lives only for this page view */
  }
}

let unauthorizedHandler: (() => void) | null = null

/** Register a callback fired whenever the admin API returns 401. */
export function onUnauthorized(handler: (() => void) | null): void {
  unauthorizedHandler = handler
}

export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getAdminToken()
  const response = await fetch(path, {
    ...options,
    headers: {
      'accept': 'application/json',
      'content-type': 'application/json',
      ...(token ? { 'x-automode-admin-token': token } : {}),
      ...(options?.headers || {}),
    },
  })
  if (response.status === 401) {
    unauthorizedHandler?.()
    throw new AuthError()
  }
  if (!response.ok) {
    const message = (await response.text()) || `HTTP ${response.status}`
    throw new Error(message)
  }
  return response.status === 204 ? (undefined as T) : response.json()
}

export const post = <T>(path: string, body: unknown) =>
  api<T>(path, { method: 'POST', body: JSON.stringify(body) })

export const patch = <T>(path: string, body: unknown) =>
  api<T>(path, { method: 'PATCH', body: JSON.stringify(body) })

export const put = <T>(path: string, body: unknown) =>
  api<T>(path, { method: 'PUT', body: JSON.stringify(body) })

export const del = <T>(path: string) => api<T>(path, { method: 'DELETE' })

export async function fetchEvents(params: {
  limit?: number
  offset?: number
  source_id?: string
  is_historical?: boolean
  processing_status?: string
  association_status?: string
} = {}) {
  const query = new URLSearchParams()
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  if (params.offset !== undefined) query.set('offset', String(params.offset))
  if (params.source_id) query.set('source_id', params.source_id)
  if (params.is_historical !== undefined) query.set('is_historical', params.is_historical ? '1' : '0')
  if (params.processing_status) query.set('processing_status', params.processing_status)
  if (params.association_status) query.set('association_status', params.association_status)
  const q = query.toString()
  return api<{ data: import('./types').EventItem[]; total: number }>(`/api/events${q ? `?${q}` : ''}`)
}

export async function fetchEventDetail(eventId: string) {
  return api<import('./types').EventItem>(`/api/events/${encodeURIComponent(eventId)}`)
}

export async function retryEvent(eventId: string) {
  return post<{ status: string; event_id: string }>(`/api/events/${encodeURIComponent(eventId)}/retry`, {})
}

export async function fetchSources() {
  return api<{ data: import('./types').SourceItem[] }>('/api/sources')
}

export async function createSource(source: Partial<import('./types').SourceItem>) {
  return post<{ data: import('./types').SourceItem }>('/api/sources', source)
}

export async function updateSource(sourceId: string, source: Partial<import('./types').SourceItem>) {
  return put<{ data: import('./types').SourceItem }>(`/api/sources/${encodeURIComponent(sourceId)}`, source)
}

export async function deleteSource(sourceId: string) {
  return del<{ status: string }>(`/api/sources/${encodeURIComponent(sourceId)}`)
}

export async function fetchSystemStats() {
  return api<import('./types').SystemStats>('/api/stats')
}
