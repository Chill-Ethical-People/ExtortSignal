import type { ActorAIAnalysis, AIConnectionTest, AIProvider, Alert, AlertIntelligenceContext, AlertStatus, BulkEnrichmentResult, Claim, Client, DashboardSummary, DirectSitesOverview, DlsTarget, IntelligenceAIAnalysis, IntelligenceAnalysisScope, IntelligenceResponse, NewClient, NotificationDraft, RuntimeSettings, RuntimeSettingsUpdate, SourceHealth, ThreatActorProfile, VictimDigestResult } from "./types";

const headers = { "Content-Type": "application/json" };

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, options);
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail || `Request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  dashboard: () => request<DashboardSummary>("/api/v1/dashboard"),
  clients: () => request<Client[]>("/api/v1/clients"),
  claims: () => request<Claim[]>("/api/v1/claims"),
  alerts: () => request<Alert[]>("/api/v1/alerts"),
  sources: () => request<SourceHealth[]>("/api/v1/sources"),
  runtimeSettings: () => request<RuntimeSettings>("/api/v1/settings/runtime"),
  updateRuntimeSettings: (payload: RuntimeSettingsUpdate) =>
    request<RuntimeSettings>("/api/v1/settings/runtime", {
      method: "PUT",
      headers,
      body: JSON.stringify(payload)
    }),
  aiProviders: () => request<AIProvider[]>("/api/v1/ai/providers"),
  saveAIProviderCredential: (providerId: string, apiKey: string) =>
    request<AIProvider>(`/api/v1/ai/providers/${encodeURIComponent(providerId)}/credential`, {
      method: "PUT",
      headers,
      body: JSON.stringify({ api_key: apiKey })
    }),
  clearAIProviderCredential: (providerId: string) =>
    request<AIProvider>(`/api/v1/ai/providers/${encodeURIComponent(providerId)}/credential`, {
      method: "DELETE"
    }),
  testAIProvider: () => request<AIConnectionTest>("/api/v1/ai/test", { method: "POST" }),
  intelligence: (filters: { days: number; query?: string; actor?: string; country?: string; industry?: string; publication_status?: string; page?: number }) => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== "" && value !== undefined) params.set(key, String(value));
    });
    return request<IntelligenceResponse>(`/api/v1/intelligence?${params.toString()}`);
  },
  analyzeThreatActor: (actor: string, days = 90) =>
    request<ActorAIAnalysis>(`/api/v1/intelligence/actors/${encodeURIComponent(actor)}/ai-analysis?days=${days}`, { method: "POST" }),
  actorProfiles: (days = 365) =>
    request<ThreatActorProfile[]>(`/api/v1/intelligence/actor-profiles?days=${days}`),
  analyzeIntelligence: (scope: IntelligenceAnalysisScope, value: string, days = 90) => {
    const params = new URLSearchParams({ scope, value, days: String(days) });
    return request<IntelligenceAIAnalysis>(`/api/v1/intelligence/ai-analysis?${params.toString()}`, { method: "POST" });
  },
  enrichVictim: (claimId: string) =>
    request<Claim>(`/api/v1/claims/${encodeURIComponent(claimId)}/ai-enrichment`, { method: "POST" }),
  enrichNewVictims: (limit = 25) =>
    request<BulkEnrichmentResult>("/api/v1/claims/ai-enrichment/bulk", {
      method: "POST",
      headers,
      body: JSON.stringify({ limit })
    }),
  saveSMTPPassword: (password: string) =>
    request<{ configured: boolean }>("/api/v1/settings/smtp-password", {
      method: "PUT",
      headers,
      body: JSON.stringify({ password })
    }),
  clearSMTPPassword: () => request<{ configured: boolean }>("/api/v1/settings/smtp-password", { method: "DELETE" }),
  sendVictimDigest: () => request<VictimDigestResult>("/api/v1/notifications/victim-digest/send", { method: "POST" }),
  directSites: (query = "") => request<DirectSitesOverview>(`/api/v1/direct-sites?query=${encodeURIComponent(query)}`),
  syncDirectSites: () => request<{ received: number; created: number }>("/api/v1/direct-sites/sync", { method: "POST" }),
  updateDirectSite: (id: string, capture_enabled: boolean) =>
    request<DlsTarget>(`/api/v1/direct-sites/${id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ capture_enabled })
    }),
  updateDirectSitesBulk: (target_ids: string[], capture_enabled: boolean) =>
    request<{ requested: number; updated: number; capture_enabled: boolean }>("/api/v1/direct-sites/bulk", {
      method: "PATCH",
      headers,
      body: JSON.stringify({ target_ids, capture_enabled })
    }),
  queueCapture: (id: string) => request(`/api/v1/direct-sites/${id}/capture`, { method: "POST" }),
  createClient: (payload: NewClient) =>
    request<Client>("/api/v1/clients", {
      method: "POST",
      headers,
      body: JSON.stringify(payload)
    }),
  updateClient: (id: string, payload: NewClient) =>
    request<Client>(`/api/v1/clients/${id}`, {
      method: "PUT",
      headers,
      body: JSON.stringify(payload)
    }),
  updateAlert: (id: string, status: AlertStatus, note = "") =>
    request<Alert>(`/api/v1/alerts/${id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ status, note })
    }),
  notificationDraft: (id: string) => request<NotificationDraft>(`/api/v1/alerts/${id}/notification-draft`),
  aiNotificationDraft: (id: string) => request<NotificationDraft>(`/api/v1/alerts/${id}/notification-draft/ai`, { method: "POST" }),
  alertIntelligenceContext: (id: string) => request<AlertIntelligenceContext>(`/api/v1/alerts/${id}/intelligence-context`),
  collect: () => request<{ results: unknown[] }>("/api/v1/collect", { method: "POST" }),
  backfill: (startYear = 2015) =>
    request<{ start_year: number; received: number; created: number; results: Array<{ source: string; coverage: string; received?: number; created?: number; error?: string; truncated_partitions?: string[] }> }>(
      `/api/v1/backfill?start_year=${startYear}`,
      { method: "POST" }
    ),
  seedDemo: () => request<DashboardSummary>("/api/v1/demo/seed", { method: "POST" })
};
