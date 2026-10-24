import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('./components/EChart', () => ({ default: () => <div data-testid="chart" /> }))

const TOKEN = '\u27e6CERB:0123456789abcdef\u27e7'
const now = Date.now() / 1000

const agent = {
  agent_id: 'support-bot', name: 'support-bot', status: 'connected', state: 'connected', sdk_version: '0.6.0',
  first_seen_at: null, last_seen_at: null, disconnected_at: null, disconnected_by: null,
  calls: 1, blocked: 0, cost_usd: 0, pending_approvals: 0,
}
const spanOf = () => ({
  span_id: 'sp-1', trace_id: 'trace-1', span_type: 'tool_call', timestamp: now - 5, latency_ms: 10,
  input_data: { tool: 'send_email' }, output_data: { to: TOKEN }, security_checks: [], blocked: false,
  block_reason: null, cost_usd: 0, input_tokens: 1, output_tokens: 1, created_at: null, detection_layer: null,
  ml_score: null, llm_score: null, llm_reason: null, model: null,
})

type Cfg = { enabled: boolean; ready: boolean; can_manage: boolean; max_ttl_seconds: number; min_reason_length: number }
let cfg: Cfg
let incidents: unknown[]
let available: string[]
let calls: { method: string; path: string; body: unknown }[]

beforeAll(() => {
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  Element.prototype.scrollIntoView = () => {}
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const path = String(url).split('?')[0]
    const method = init?.method || 'GET'
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ method, path, body })
    const ok = (d: unknown) => new Response(JSON.stringify(d), { status: 200 })
    if (path === '/api/incidents/config') return ok(cfg)
    if (path === '/api/incidents' && method === 'GET') return ok({ incidents })
    if (path === '/api/incidents' && method === 'POST') return ok({ incident_id: 'inc_1' })
    if (path === '/api/incidents/available') return ok({ available })
    if (path === '/api/incidents/reveal') return ok({ incident_id: 'inc_1', token: body.token, value: 'alice@example.com' })
    if (path.endsWith('/close')) return ok({ status: 'purged' })
    if (path === '/api/agents') return ok({ agents: [agent], counts: { connected: 1, idle: 0, offline: 0, disconnected: 0 }, total: 1 })
    if (path === '/api/traces/trace-1') return ok([spanOf()])
    if (path === '/api/auth/me') return ok({ authenticated: true, type: 'human', user: { email: 'a@b.c', display_name: null, role: 'admin', org_id: 'o' } })
    if (path === '/api/audit/trail') return ok([])
    if (path === '/api/audit/summary') return ok({ total: 0, blocked: 0, flagged: 0, allowed: 0, high_risk: 0, critical: 0, require_approval: 0, affected_agents: 0 })
    if (path === '/api/approvals') return ok({ approvals: [], count: 0, counts: { pending: 0, approved: 0, rejected: 0 } })
    return new Response(JSON.stringify({ error: 'nf' }), { status: 404 })
  }))
})

beforeEach(() => {
  cfg = { enabled: true, ready: true, can_manage: true, max_ttl_seconds: 86400, min_reason_length: 10 }
  incidents = []
  available = []
  calls = []
})

// App.tsx crée son QueryClient au niveau du module : sans module neuf, la config
// d'un test resterait en cache pour les suivants. On remonte donc toute
// l'application (React et Testing Library compris, une seule copie de React) à
// chaque test.
let disposers: (() => void)[] = []
afterEach(() => { disposers.forEach((d) => d()); disposers = [] })

async function mount(hash: string) {
  vi.resetModules()
  const rtl = await import('@testing-library/react')
  const { default: App } = await import('./App')
  window.location.hash = hash
  rtl.render(<App />)
  disposers.push(() => rtl.cleanup())
  return rtl
}

describe('incident capture UI', () => {
  it('explains how to enable it when the collector has it off', async () => {
    cfg = { ...cfg, enabled: false, ready: false, can_manage: false }
    const { screen } = await mount('#/settings?tab=incidents')
    expect(await screen.findByText('Incident capture is off')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /open capture/i })).toBeNull()
  })

  it('flags a missing master key instead of offering controls', async () => {
    cfg = { ...cfg, ready: false, can_manage: false }
    const { screen } = await mount('#/settings?tab=incidents')
    expect(await screen.findByText(/master key is missing or invalid/i)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /open capture/i })).toBeNull()
  })

  it('hides every control from non-admins', async () => {
    cfg = { ...cfg, can_manage: false }
    const { screen } = await mount('#/settings?tab=incidents')
    expect(await screen.findByText('Admin role required')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /open capture/i })).toBeNull()
  })

  it('opens a capture only with a real reason, then posts agent, ttl and reason', async () => {
    const { screen, fireEvent, waitFor } = await mount('#/settings?tab=incidents')
    fireEvent.click(await screen.findByRole('button', { name: 'Open capture' }))
    const buttons = await screen.findAllByRole('button', { name: 'Open capture' })
    const submit = buttons[buttons.length - 1]
    expect((submit as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(screen.getByPlaceholderText(/investigating/i), { target: { value: 'too short' } })
    expect((submit as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(screen.getByPlaceholderText(/investigating/i), { target: { value: 'Suspected customer data leak SEC-142' } })
    expect((submit as HTMLButtonElement).disabled).toBe(false)
    fireEvent.click(submit)
    await waitFor(() => expect(calls.find((c) => c.method === 'POST' && c.path === '/api/incidents')).toBeTruthy())
    const sent = calls.find((c) => c.method === 'POST' && c.path === '/api/incidents')!.body as Record<string, unknown>
    expect(sent).toEqual({ agent_id: 'support-bot', ttl_seconds: 21600, reason: 'Suspected customer data leak SEC-142' })
  })

  it('needs two clicks to destroy evidence, then asks for purge', async () => {
    incidents = [{ id: 'inc_1', agent_id: 'support-bot', status: 'open', reason: 'leak', opened_by: 'a@b.c', created_at: now - 60, expires_at: now + 3600, closed_at: null, sealed_values: 4 }]
    const { screen, fireEvent, waitFor } = await mount('#/settings?tab=incidents')
    const btn = await screen.findByRole('button', { name: 'Destroy now' })
    fireEvent.click(btn)
    expect(calls.some((c) => c.path.endsWith('/close'))).toBe(false)
    fireEvent.click(await screen.findByRole('button', { name: 'Click again to destroy' }))
    await waitFor(() => expect(calls.some((c) => c.path === '/api/incidents/inc_1/close')).toBe(true))
    expect(calls.find((c) => c.path.endsWith('/close'))!.body).toEqual({ purge: true })
  })

  it('reveals a sealed value from a span only after a reason, and shows what was audited', async () => {
    available = [TOKEN]
    const { screen, fireEvent } = await mount('#/feed?trace=trace-1')
    expect(await screen.findByText(/can be reopened/i)).toBeTruthy()
    expect(screen.queryByText('alice@example.com')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: `Reveal ${TOKEN}` }))
    const confirm = await screen.findByRole('button', { name: 'Reveal value' })
    expect((confirm as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Reason for revealing'), { target: { value: 'legal request ref 4521' } })
    fireEvent.click(confirm)
    expect(await screen.findByText('alice@example.com')).toBeTruthy()
    expect(screen.getByText(/this access was audited/i)).toBeTruthy()
    const sent = calls.find((c) => c.path === '/api/incidents/reveal')!.body
    expect(sent).toEqual({ token: TOKEN, reason: 'legal request ref 4521' })
    fireEvent.click(screen.getByRole('button', { name: 'Hide now' }))
    expect(screen.queryByText('alice@example.com')).toBeNull()
  })

  it('shows nothing in the trace drawer when there is no evidence', async () => {
    available = []
    const { screen } = await mount('#/feed?trace=trace-1')
    await screen.findByText('Output')
    expect(screen.queryByText(/can be reopened/i)).toBeNull()
  })

  it('never even asks for evidence when the user is not an admin', async () => {
    cfg = { ...cfg, can_manage: false }
    available = [TOKEN]
    const { screen } = await mount('#/feed?trace=trace-1')
    await screen.findByText('Output')
    expect(screen.queryByText(/can be reopened/i)).toBeNull()
    expect(calls.some((c) => c.path === '/api/incidents/available')).toBe(false)
  })
})
