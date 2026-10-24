import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { get, post } from './api'

/* Capture d'incident (Secure Evidence Recovery) : formes réelles des réponses
 * de collector/api/incidents.py. Aucune valeur sensible n'est jamais mise en
 * cache : la valeur révélée vit uniquement dans l'état du composant. */

export interface IncidentConfig {
  enabled: boolean
  ready: boolean
  can_manage: boolean
  max_ttl_seconds: number
  min_reason_length: number
}

export interface Incident {
  id: string
  agent_id: string
  status: 'open' | 'closed' | 'purged'
  reason: string | null
  opened_by: string | null
  created_at: number
  expires_at: number
  closed_at: number | null
  sealed_values: number
}

export type IncidentPhase = 'capturing' | 'stopped' | 'expired' | 'destroyed'

export const TOKEN_PATTERN = '\u27e6CERB:[0-9a-f]{16}\u27e7'

export function extractTokens(text: string): string[] {
  const found = text.match(new RegExp(TOKEN_PATTERN, 'g')) || []
  return [...new Set(found)].slice(0, 200)
}

export function phaseOf(i: Incident, nowSec = Date.now() / 1000): IncidentPhase {
  if (i.status === 'purged') return 'destroyed'
  if (i.expires_at <= nowSec) return 'expired'
  return i.status === 'open' ? 'capturing' : 'stopped'
}

export function remaining(expiresAt: number, nowSec = Date.now() / 1000): string {
  const s = Math.floor(expiresAt - nowSec)
  if (s <= 0) return 'expired'
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (h > 0) return `${h} h ${m} min`
  if (m > 0) return `${m} min`
  return `${s}s`
}

export const useIncidentConfig = () =>
  useQuery({
    queryKey: ['incident-config'],
    queryFn: () => get<IncidentConfig>('/api/incidents/config'),
    staleTime: 30_000,
    retry: false,
  })

export const useIncidents = (enabled: boolean) =>
  useQuery({
    queryKey: ['incidents'],
    queryFn: () => get<{ incidents: Incident[] }>('/api/incidents'),
    enabled,
    refetchInterval: 5000,
    placeholderData: keepPreviousData,
  })

/** Parmi ces tokens, lesquels ont une preuve scellée encore rouvrable ? */
export const useAvailableTokens = (tokens: string[], enabled: boolean) =>
  useQuery({
    queryKey: ['incident-available', tokens.join(',')],
    queryFn: () => post<{ available: string[] }>('/api/incidents/available', { tokens }),
    enabled: enabled && tokens.length > 0,
    staleTime: 15_000,
    retry: false,
  })
