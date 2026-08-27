import type {
  ActivityResponse,
  ActorAIAnalysis,
  AIConnectionTest,
  AIJob,
  AIJobHistoryResponse,
  AIJobType,
  AIProvider,
  Alert,
  AlertAIAssessment,
  AlertIntelligenceContext,
  AlertStatus,
  BulkAlertUpdateResult,
  BulkFalsePositiveResult,
  BulkEnrichmentResult,
  CaptureJob,
  CaptureJobCleanupResult,
  Claim,
  ClaimSourceEvidence,
  Client,
  ClientDeletionResult,
  DashboardSummary,
  DirectSitesOverview,
  DlsTarget,
  IntelligenceAIAnalysis,
  IntelligenceAnalysisScope,
  IntelligenceResponse,
  NewClient,
  NotificationDraft,
  RuntimeSettings,
  RuntimeSettingsUpdate,
  SourceHealth,
  ThreatActorProfile,
  ThreatActorProfileIndexItem,
  VictimDigestResult,
} from "./types";

const headers = { "Content-Type": "application/json" };
const mutationMarker = { "X-ExtortSignal-Request": "same-origin" };

export type OperationEventDetail = {
  id: string;
  phase: "started" | "succeeded" | "failed";
  pending: string;
  success: string;
  message?: string;
};

type OperationLabels = Pick<OperationEventDetail, "pending" | "success">;
const operationTimers = new Map<string, number>();

function removeOperation(id: string) {
  const timer = operationTimers.get(id);
  if (timer) window.clearTimeout(timer);
  operationTimers.delete(id);
  const card = document.querySelector<HTMLElement>(
    `[data-operation-id="${CSS.escape(id)}"]`,
  );
  if (!card) return;
  card.classList.add("operation-toast-exit");
  const finish = () => {
    const container = card.parentElement;
    card.remove();
    if (container && !container.children.length) container.remove();
  };
  card.addEventListener("transitionend", finish, { once: true });
  window.setTimeout(finish, 320);
}

function announceOperation(detail: OperationEventDetail) {
  let container = document.querySelector<HTMLElement>(
    "[data-operation-center]",
  );
  if (!container) {
    container = document.createElement("div");
    container.dataset.operationCenter = "true";
    container.className =
      "pointer-events-none fixed right-4 top-4 z-[80] flex w-[calc(100%-2rem)] max-w-sm flex-col gap-3";
    container.setAttribute("aria-live", "polite");
    document.body.appendChild(container);
  }

  let card = container.querySelector<HTMLElement>(
    `[data-operation-id="${CSS.escape(detail.id)}"]`,
  );
  if (!card) {
    card = document.createElement("div");
    card.dataset.operationId = detail.id;
    card.className =
      "operation-toast-enter pointer-events-auto flex items-start gap-3 rounded-2xl border p-4 shadow-xl backdrop-blur";
    container.appendChild(card);
  }
  card.setAttribute("role", detail.phase === "failed" ? "alert" : "status");
  card.className = `operation-toast-enter pointer-events-auto flex items-start gap-3 rounded-2xl border p-4 shadow-xl backdrop-blur ${detail.phase === "failed" ? "border-rose-200 bg-rose-50/95 text-rose-900" : detail.phase === "succeeded" ? "border-emerald-200 bg-emerald-50/95 text-emerald-900" : "border-sky-200 bg-sky-50/95 text-sky-900"}`;
  card.replaceChildren();

  const icon = document.createElement("span");
  icon.className = `mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full text-sm font-bold ${detail.phase === "started" ? "animate-pulse" : ""}`;
  icon.textContent =
    detail.phase === "failed" ? "!" : detail.phase === "succeeded" ? "✓" : "•";
  const content = document.createElement("div");
  content.className = "min-w-0 flex-1";
  const title = document.createElement("p");
  title.className = "text-sm font-semibold";
  title.textContent =
    detail.phase === "failed"
      ? "Action failed"
      : detail.phase === "succeeded"
        ? detail.success
        : detail.pending;
  content.appendChild(title);
  if (detail.phase === "failed") {
    const message = document.createElement("p");
    message.className = "mt-1 break-words text-xs leading-5 text-rose-700";
    message.textContent =
      detail.message || "The operation could not be completed.";
    content.appendChild(message);
  }
  card.append(icon, content);

  if (detail.phase !== "started") {
    const close = document.createElement("button");
    close.type = "button";
    close.className =
      "grid h-7 w-7 shrink-0 place-items-center rounded-lg text-current/60 transition hover:bg-black/5 hover:text-current";
    close.setAttribute("aria-label", "Dismiss status");
    close.textContent = "×";
    close.addEventListener("click", () => removeOperation(detail.id), {
      once: true,
    });
    card.appendChild(close);
    const existing = operationTimers.get(detail.id);
    if (existing) window.clearTimeout(existing);
    operationTimers.set(
      detail.id,
      window.setTimeout(
        () => removeOperation(detail.id),
        detail.phase === "succeeded" ? 5_500 : 10_000,
      ),
    );
  }

  while (container.children.length > 4) container.firstElementChild?.remove();
}

async function request<T>(
  path: string,
  options?: RequestInit,
  operation?: OperationLabels,
): Promise<T> {
  const operationId = operation
    ? `${Date.now()}-${Math.random().toString(36).slice(2)}`
    : "";
  if (operation)
    announceOperation({ id: operationId, phase: "started", ...operation });
  try {
    const requestHeaders = new Headers(options?.headers);
    Object.entries(mutationMarker).forEach(([name, value]) =>
      requestHeaders.set(name, value),
    );
    const response = await fetch(path, { ...options, headers: requestHeaders });
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw new Error(
        body?.detail || `Request failed with status ${response.status}`,
      );
    }
    const result = (await response.json()) as T;
    if (operation)
      announceOperation({ id: operationId, phase: "succeeded", ...operation });
    return result;
  } catch (reason) {
    if (operation) {
      announceOperation({
        id: operationId,
        phase: "failed",
        ...operation,
        message:
          reason instanceof Error
            ? reason.message
            : "The operation could not be completed",
      });
    }
    throw reason;
  }
}

export const api = {
  dashboard: () => request<DashboardSummary>("/api/v1/dashboard"),
  clients: () => request<Client[]>("/api/v1/clients"),
  claims: () => request<Claim[]>("/api/v1/claims"),
  activity: (params: Record<string, string | number | boolean>) =>
    request<ActivityResponse>(
      `/api/v1/activity?${new URLSearchParams(Object.entries(params).map(([key, value]) => [key, String(value)])).toString()}`,
    ),
  claimSourceEvidence: (claimId: string) =>
    request<ClaimSourceEvidence>(
      `/api/v1/claims/${encodeURIComponent(claimId)}/source-evidence`,
    ),
  alerts: () => request<Alert[]>("/api/v1/alerts?limit=1000"),
  sources: () => request<SourceHealth[]>("/api/v1/sources"),
  runtimeSettings: () => request<RuntimeSettings>("/api/v1/settings/runtime"),
  updateRuntimeSettings: (payload: RuntimeSettingsUpdate) =>
    request<RuntimeSettings>(
      "/api/v1/settings/runtime",
      {
        method: "PUT",
        headers,
        body: JSON.stringify(payload),
      },
      {
        pending: "Saving monitoring settings…",
        success: "Monitoring settings saved",
      },
    ),
  aiProviders: () => request<AIProvider[]>("/api/v1/ai/providers"),
  queueAIJob: (job_type: AIJobType, payload: Record<string, unknown> = {}) =>
    request<AIJob>(
      "/api/v1/ai/jobs",
      {
        method: "POST",
        headers,
        body: JSON.stringify({ job_type, payload }),
      },
      {
        pending: "Adding AI task to the background queue…",
        success: "AI task queued; you can continue browsing",
      },
    ),
  aiJobs: (limit = 50) => request<AIJob[]>(`/api/v1/ai/jobs?limit=${limit}`),
  aiJobHistory: ({
    page = 1,
    page_size = 50,
    status = "",
    job_type = "",
    query = "",
  }: {
    page?: number;
    page_size?: number;
    status?: string;
    job_type?: string;
    query?: string;
  } = {}) => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(page_size),
    });
    if (status) params.set("status", status);
    if (job_type) params.set("job_type", job_type);
    if (query) params.set("query", query);
    return request<AIJobHistoryResponse>(
      `/api/v1/ai/jobs/history?${params.toString()}`,
    );
  },
  markAIJobSeen: (id: string) =>
    request<AIJob>(`/api/v1/ai/jobs/${encodeURIComponent(id)}/seen`, {
      method: "PATCH",
    }),
  saveAIProviderCredential: (providerId: string, apiKey: string) =>
    request<AIProvider>(
      `/api/v1/ai/providers/${encodeURIComponent(providerId)}/credential`,
      {
        method: "PUT",
        headers,
        body: JSON.stringify({ api_key: apiKey }),
      },
      { pending: "Saving API credential…", success: "API credential saved" },
    ),
  clearAIProviderCredential: (providerId: string) =>
    request<AIProvider>(
      `/api/v1/ai/providers/${encodeURIComponent(providerId)}/credential`,
      {
        method: "DELETE",
      },
      {
        pending: "Removing API credential…",
        success: "API credential removed",
      },
    ),
  testAIProvider: () =>
    request<AIConnectionTest>(
      "/api/v1/ai/test",
      { method: "POST" },
      { pending: "Testing AI connection…", success: "AI connection verified" },
    ),
  intelligence: (filters: {
    days: number;
    query?: string;
    actor?: string;
    country?: string;
    industry?: string;
    publication_status?: string;
    page?: number;
  }) => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== "" && value !== undefined) params.set(key, String(value));
    });
    return request<IntelligenceResponse>(
      `/api/v1/intelligence?${params.toString()}`,
    );
  },
  analyzeThreatActor: (actor: string, days = 90) =>
    request<ActorAIAnalysis>(
      `/api/v1/intelligence/actors/${encodeURIComponent(actor)}/ai-analysis?days=${days}`,
      { method: "POST" },
      {
        pending: "Analyzing threat actor…",
        success: "Threat-actor analysis completed",
      },
    ),
  actorProfiles: (days = 365) =>
    request<ThreatActorProfile[]>(
      `/api/v1/intelligence/actor-profiles?days=${days}&limit=500`,
    ),
  actorProfileIndex: (days = 365) =>
    request<ThreatActorProfileIndexItem[]>(
      `/api/v1/intelligence/actor-profile-index?days=${days}&limit=500`,
    ),
  actorProfile: (actor: string) =>
    request<ThreatActorProfile>(
      `/api/v1/intelligence/actor-profiles/${encodeURIComponent(actor)}`,
    ),
  syncActorProfiles: () =>
    request<{ profiles: number; source: string; source_version: string }>(
      "/api/v1/intelligence/actor-profiles/sync",
      { method: "POST" },
      {
        pending: "Synchronizing official ATT&CK profiles…",
        success: "ATT&CK profiles synchronized",
      },
    ),
  analyzeIntelligence: (
    scope: IntelligenceAnalysisScope,
    value: string,
    days = 90,
  ) => {
    const params = new URLSearchParams({ scope, value, days: String(days) });
    return request<IntelligenceAIAnalysis>(
      `/api/v1/intelligence/ai-analysis?${params.toString()}`,
      { method: "POST" },
      {
        pending: "Analyzing intelligence data…",
        success: "Intelligence analysis completed",
      },
    );
  },
  intelligenceAnalysisHistory: (limit = 20) =>
    request<IntelligenceAIAnalysis[]>(
      `/api/v1/intelligence/ai-analysis/history?limit=${limit}`,
    ),
  enrichVictim: (claimId: string) =>
    request<Claim>(
      `/api/v1/claims/${encodeURIComponent(claimId)}/ai-enrichment`,
      { method: "POST" },
      {
        pending: "Enriching victim profile…",
        success: "Victim profile enriched",
      },
    ),
  enrichNewVictims: (limit = 25) =>
    request<BulkEnrichmentResult>(
      "/api/v1/claims/ai-enrichment/bulk",
      {
        method: "POST",
        headers,
        body: JSON.stringify({ limit }),
      },
      {
        pending: "Enriching new victim profiles…",
        success: "Bulk victim enrichment completed",
      },
    ),
  saveSMTPPassword: (password: string) =>
    request<{ configured: boolean }>(
      "/api/v1/settings/smtp-password",
      {
        method: "PUT",
        headers,
        body: JSON.stringify({ password }),
      },
      {
        pending: "Saving email credential…",
        success: "Email credential saved",
      },
    ),
  clearSMTPPassword: () =>
    request<{ configured: boolean }>(
      "/api/v1/settings/smtp-password",
      { method: "DELETE" },
      {
        pending: "Removing email credential…",
        success: "Email credential removed",
      },
    ),
  sendVictimDigest: () =>
    request<VictimDigestResult>(
      "/api/v1/notifications/victim-digest/send",
      { method: "POST" },
      { pending: "Sending victim digest…", success: "Victim digest sent" },
    ),
  directSites: (query = "") =>
    request<DirectSitesOverview>(
      `/api/v1/direct-sites?query=${encodeURIComponent(query)}`,
    ),
  syncDirectSites: () =>
    request<{ received: number; created: number }>(
      "/api/v1/direct-sites/sync",
      { method: "POST" },
      {
        pending: "Synchronizing DLS catalog…",
        success: "DLS catalog synchronized",
      },
    ),
  updateDirectSite: (id: string, capture_enabled: boolean) =>
    request<DlsTarget>(
      `/api/v1/direct-sites/${id}`,
      {
        method: "PATCH",
        headers,
        body: JSON.stringify({ capture_enabled }),
      },
      {
        pending: "Updating capture permission…",
        success: "Capture permission updated",
      },
    ),
  updateDirectSitesBulk: (target_ids: string[], capture_enabled: boolean) =>
    request<{ requested: number; updated: number; capture_enabled: boolean }>(
      "/api/v1/direct-sites/bulk",
      {
        method: "PATCH",
        headers,
        body: JSON.stringify({ target_ids, capture_enabled }),
      },
      {
        pending: "Updating selected DLS sites…",
        success: "Selected DLS sites updated",
      },
    ),
  queueCapture: (id: string) =>
    request(
      `/api/v1/direct-sites/${id}/capture`,
      { method: "POST" },
      {
        pending: "Queueing evidence capture…",
        success: "Evidence capture queued",
      },
    ),
  captureScreenshotUrl: (jobId: string, pageNumber = 1) =>
    `/api/v1/capture-jobs/${encodeURIComponent(jobId)}/screenshots/${pageNumber}`,
  captureTextUrl: (jobId: string) =>
    `/api/v1/capture-jobs/${encodeURIComponent(jobId)}/text`,
  createClient: (payload: NewClient) =>
    request<Client>(
      "/api/v1/clients",
      {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      },
      {
        pending: "Adding monitored client…",
        success: "Monitored client added",
      },
    ),
  updateClient: (id: string, payload: NewClient) =>
    request<Client>(
      `/api/v1/clients/${id}`,
      {
        method: "PUT",
        headers,
        body: JSON.stringify(payload),
      },
      { pending: "Saving client profile…", success: "Client profile saved" },
    ),
  deleteClient: (id: string) =>
    request<ClientDeletionResult>(
      `/api/v1/clients/${encodeURIComponent(id)}`,
      { method: "DELETE" },
      {
        pending: "Deleting monitored client…",
        success: "Monitored client deleted",
      },
    ),
  updateAlert: (id: string, status: AlertStatus, note = "") =>
    request<Alert>(
      `/api/v1/alerts/${id}`,
      {
        method: "PATCH",
        headers,
        body: JSON.stringify({ status, note }),
      },
      { pending: "Saving alert status…", success: "Alert status saved" },
    ),
  bulkUpdateAlerts: (
    alertIds: string[],
    status: AlertStatus,
    note = "",
  ) =>
    request<BulkAlertUpdateResult>(
      "/api/v1/alerts/bulk",
      {
        method: "PATCH",
        headers,
        body: JSON.stringify({ alert_ids: alertIds, status, note }),
      },
      {
        pending: `Updating ${alertIds.length} alerts…`,
        success: `${alertIds.length} alerts updated`,
      },
    ),
  bulkMarkFalsePositive: (
    alertIds: string[],
    category: string,
    analyst_note: string,
  ) =>
    request<BulkFalsePositiveResult>(
      "/api/v1/alerts/bulk/false-positive",
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          alert_ids: alertIds,
          category,
          analyst_note,
        }),
      },
      {
        pending: `Recording ${alertIds.length} false matches…`,
        success: "False-match feedback stored",
      },
    ),
  alertAIAssessments: (id: string) =>
    request<AlertAIAssessment[]>(
      `/api/v1/alerts/${encodeURIComponent(id)}/ai-assessments`,
    ),
  notificationDraft: (id: string) =>
    request<NotificationDraft>(`/api/v1/alerts/${id}/notification-draft`),
  notificationDrafts: (id: string) =>
    request<NotificationDraft[]>(`/api/v1/alerts/${id}/notification-drafts`),
  saveNotificationDraft: (
    alertId: string,
    draftId: string,
    subject: string,
    body: string,
  ) =>
    request<NotificationDraft>(
      `/api/v1/alerts/${alertId}/notification-drafts/${draftId}`,
      {
        method: "PUT",
        headers,
        body: JSON.stringify({ subject, body }),
      },
      {
        pending: "Saving client email draft…",
        success: "Client email draft saved",
      },
    ),
  aiNotificationDraft: (id: string) =>
    request<NotificationDraft>(
      `/api/v1/alerts/${id}/notification-draft/ai`,
      { method: "POST" },
      {
        pending: "Drafting sanitized notification…",
        success: "Notification draft completed",
      },
    ),
  alertIntelligenceContext: (id: string) =>
    request<AlertIntelligenceContext>(
      `/api/v1/alerts/${id}/intelligence-context`,
    ),
  markFalsePositive: (id: string, category: string, analyst_note: string) =>
    request<{ alert: Alert; feedback: Record<string, unknown> }>(
      `/api/v1/alerts/${id}/false-positive`,
      {
        method: "POST",
        headers,
        body: JSON.stringify({ category, analyst_note }),
      },
      {
        pending: "Saving analyst feedback…",
        success: "False-positive feedback saved for future retrieval",
      },
    ),
  queueAlertCapture: (id: string) =>
    request<CaptureJob>(
      `/api/v1/alerts/${id}/capture-evidence`,
      { method: "POST" },
      {
        pending: "Queueing focused DLS evidence capture…",
        success: "Focused evidence capture queued",
      },
    ),
  clearCaptureJobs: (statuses: Array<"queued" | "failed">) =>
    request<CaptureJobCleanupResult>(
      "/api/v1/capture-jobs/clear",
      {
        method: "POST",
        headers,
        body: JSON.stringify({ statuses }),
      },
      {
        pending: "Clearing selected capture jobs…",
        success: "Capture-job list cleaned",
      },
    ),
  collect: () =>
    request<{ results: unknown[] }>(
      "/api/v1/collect",
      { method: "POST" },
      {
        pending: "Testing public sources…",
        success: "Public source test completed",
      },
    ),
  backfill: (startYear = 2015) =>
    request<{
      start_year: number;
      received: number;
      created: number;
      results: Array<{
        source: string;
        coverage: string;
        received?: number;
        created?: number;
        error?: string;
        truncated_partitions?: string[];
      }>;
    }>(
      `/api/v1/backfill?start_year=${startYear}`,
      { method: "POST" },
      {
        pending: "Synchronizing source history…",
        success: "Source history synchronized",
      },
    ),
  seedDemo: () =>
    request<DashboardSummary>(
      "/api/v1/demo/seed",
      { method: "POST" },
      {
        pending: "Preparing sample workspace…",
        success: "Sample workspace ready",
      },
    ),
};
