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

export const del = <T>(path: string) => api<T>(path, { method: 'DELETE' })
