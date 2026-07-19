import {
  ArrowRight,
  Bell,
  Buildings,
  CaretDown,
  CaretLeft,
  CaretRight,
  Camera,
  ChartLineUp,
  Check,
  CheckCircle,
  ClockCounterClockwise,
  Cpu,
  Database,
  DownloadSimple,
  EnvelopeSimple,
  GlobeHemisphereWest,
  House,
  Info,
  ListMagnifyingGlass,
  MagnifyingGlass,
  Plus,
  ShieldCheck,
  SlidersHorizontal,
  SpinnerGap,
  Warning,
  X,
  XCircle
} from "@phosphor-icons/react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import { StatusPulse } from "./components/StatusPulse";
import { COUNTRY_OPTIONS, INDUSTRY_OPTIONS } from "./taxonomies";
import type { AIConnectionTest, AIProvider, Alert, AlertIntelligenceContext, AlertStatus, Claim, Client, DashboardSummary, DirectSitesOverview, DlsTarget, IntelligenceAIAnalysis, IntelligenceAnalysisScope, IntelligenceResponse, NewClient, NotificationDraft, OperatingMode, RelatedEntity, RuntimeSettings, RuntimeSettingsUpdate, SourceHealth, ThreatActorProfile } from "./types";

type Page = "home" | "intelligence" | "alerts" | "clients" | "review" | "activity" | "direct" | "sources" | "settings";

const emptyClient: NewClient = {
  canonical_name: "",
  primary_domain: "",
  description: "",
  countries: ["Hong Kong"],
  cities: [],
  industries: [],
  related_entities: [],
  priority: "standard",
  aliases: [],
  keywords: []
};

const navItems: { page: Page; label: string; icon: typeof House }[] = [
  { page: "home", label: "Home", icon: House },
  { page: "intelligence", label: "Intelligence", icon: ChartLineUp },
  { page: "alerts", label: "Alerts", icon: Bell },
  { page: "clients", label: "Clients", icon: Buildings },
  { page: "review", label: "Review", icon: ListMagnifyingGlass },
  { page: "activity", label: "Activity", icon: ClockCounterClockwise },
  { page: "direct", label: "Direct sites", icon: Camera },
  { page: "sources", label: "Sources", icon: Database },
  { page: "settings", label: "Settings", icon: SlidersHorizontal }
];

function formatTime(value?: string | null) {
  if (!value) return "Not yet";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

function sourceLabel(source: string) {
  const labels: Record<string, string> = {
    ransomlook: "RansomLook",
    ransomfeed: "RansomFeed",
    ransomware_live: "Ransomware.live",
    dls_catalog: "DLS site catalog",
  };
  return labels[source] || source;
}

function App() {
  const [page, setPage] = useState<Page>("home");
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [clients, setClients] = useState<Client[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [claims, setClaims] = useState<Claim[]>([]);
  const [sources, setSources] = useState<SourceHealth[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try { return window.localStorage.getItem("extortsignal.sidebar.collapsed") === "1"; }
    catch { return false; }
  });

  useEffect(() => {
    try { window.localStorage.setItem("extortsignal.sidebar.collapsed", sidebarCollapsed ? "1" : "0"); }
    catch { /* Local storage may be unavailable in hardened browser profiles. */ }
  }, [sidebarCollapsed]);

  const refresh = useCallback(async () => {
    try {
      const [dashboard, clientData, alertData, claimData, sourceData] = await Promise.all([
        api.dashboard(),
        api.clients(),
        api.alerts(),
        api.claims(),
        api.sources()
      ]);
      setSummary(dashboard);
      setClients(clientData);
      setAlerts(alertData);
      setClaims(claimData);
      setSources(sourceData);
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The local service could not be reached");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => void refresh(), 30_000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  if (loading) return <AppSkeleton />;
  if (error && !summary) return <ConnectionError message={error} retry={refresh} />;
  if (!clients.length) return <Onboarding onComplete={refresh} />;

  return (
    <div className="min-h-[100dvh] bg-[#f5f7f6] text-zinc-900">
      <Sidebar current={page} onNavigate={setPage} urgent={summary?.urgent_alerts ?? 0} awaitingReview={summary?.awaiting_review ?? 0} collapsed={sidebarCollapsed} onCollapsedChange={setSidebarCollapsed} />
      <main className={`min-h-[100dvh] transition-[padding] duration-200 ${sidebarCollapsed ? "md:pl-20" : "md:pl-[15.5rem]"}`}>
        <TopBar page={page} sources={sources} onRefresh={refresh} />
        {error && <InlineNotice tone="danger">Live refresh failed. Showing the last available data.</InlineNotice>}
        <div className="mx-auto max-w-[1400px] px-4 pb-16 pt-5 sm:px-6 md:px-9 md:pt-8">
          <AnimatePresence mode="wait">
            <motion.div
              key={page}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ type: "spring", stiffness: 150, damping: 22 }}
            >
              {page === "home" && summary && <Home summary={summary} onNavigate={setPage} />}
              {page === "intelligence" && <IntelligencePage onNavigate={setPage} />}
              {page === "alerts" && <AlertsPage alerts={alerts} onUpdated={refresh} />}
              {page === "clients" && <ClientsPage clients={clients} onCreated={refresh} />}
              {page === "review" && <ReviewPage alerts={alerts} onUpdated={refresh} />}
              {page === "activity" && <ActivityPage claims={claims} />}
              {page === "direct" && <DirectSitesPage />}
              {page === "sources" && <SourcesPage sources={sources} onUpdated={refresh} />}
              {page === "settings" && <SettingsPage />}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
}

function Sidebar({ current, onNavigate, urgent, awaitingReview, collapsed, onCollapsedChange }: { current: Page; onNavigate: (page: Page) => void; urgent: number; awaitingReview: number; collapsed: boolean; onCollapsedChange: (collapsed: boolean) => void }) {
  return (
    <aside className={`fixed inset-x-0 bottom-0 z-20 border-t border-zinc-200 bg-white/95 px-2 py-2 backdrop-blur transition-[width,padding] duration-200 md:inset-y-0 md:left-0 md:right-auto md:border-r md:border-t-0 md:py-5 ${collapsed ? "md:w-20 md:px-2" : "md:w-[15.5rem] md:px-4"}`}>
      <div className={`hidden md:flex ${collapsed ? "flex-col items-center gap-3" : "items-center gap-3 px-3"}`}>
        <div className="grid h-10 w-10 place-items-center rounded-xl bg-white p-1.5 shadow-sm ring-1 ring-zinc-200">
          <img src="/extortsignal-mark.svg" alt="" className="h-full w-full" />
        </div>
        {!collapsed && <div className="min-w-0 flex-1">
          <p className="font-semibold tracking-[-0.02em]">ExtortSignal</p>
          <p className="text-xs text-zinc-500">Public claim intelligence</p>
        </div>}
        <button type="button" onClick={() => onCollapsedChange(!collapsed)} className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-zinc-200 bg-white text-zinc-500 transition hover:bg-zinc-100 hover:text-zinc-900" aria-label={collapsed ? "Expand navigation" : "Collapse navigation"} title={collapsed ? "Expand navigation" : "Collapse navigation"}>{collapsed ? <CaretRight size={17} /> : <CaretLeft size={17} />}</button>
      </div>
      <nav className={`flex items-center justify-between gap-1 md:block md:space-y-1 ${collapsed ? "md:mt-5" : "md:mt-9"}`} aria-label="Main navigation">
        {navItems.map(({ page, label, icon: Icon }) => {
          const active = current === page;
          const hideOnMobile = ["review", "activity", "direct", "settings"].includes(page);
          return (
            <button
              key={page}
              type="button"
              onClick={() => onNavigate(page)}
              title={collapsed ? label : undefined}
              className={`${hideOnMobile ? "hidden md:flex" : "flex"} group relative min-h-11 min-w-11 flex-1 items-center justify-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition active:scale-[0.98] md:w-full md:flex-none ${collapsed ? "md:justify-center md:px-0" : "md:justify-start"} ${
                active ? "bg-zinc-900 text-white" : "text-zinc-600 hover:bg-zinc-100 hover:text-zinc-950"
              }`}
              aria-current={active ? "page" : undefined}
            >
              <Icon size={20} weight={active ? "fill" : "regular"} />
              {!collapsed && <span className="hidden md:inline">{label}</span>}
              {page === "alerts" && urgent > 0 && (
                <span className={`absolute grid min-h-5 min-w-5 place-items-center rounded-full bg-rose-600 px-1 text-[10px] font-bold text-white ${collapsed ? "right-0 top-0" : "right-1 top-0.5 md:static md:ml-auto"}`}>
                  {urgent}
                </span>
              )}
              {page === "review" && awaitingReview > 0 && (
                <span className={`absolute grid min-h-5 min-w-5 place-items-center rounded-full bg-amber-500 px-1 text-[10px] font-bold text-zinc-950 ${collapsed ? "right-0 top-0" : "right-1 top-0.5 md:static md:ml-auto"}`}>
                  {awaitingReview}
                </span>
              )}
            </button>
          );
        })}
      </nav>
      <div className={`absolute bottom-5 hidden rounded-2xl border border-zinc-200 bg-zinc-50 md:block ${collapsed ? "left-3 right-3 p-3" : "left-4 right-4 p-3"}`} title={collapsed ? "Monitoring active · Public claims are allegations until independently confirmed." : undefined}>
        <div className={`flex items-center text-xs font-semibold text-zinc-700 ${collapsed ? "justify-center" : "gap-2"}`}>
          <StatusPulse />{!collapsed && "Monitoring active"}
        </div>
        {!collapsed && <p className="mt-1.5 text-xs leading-relaxed text-zinc-500">Public claims are allegations until independently confirmed.</p>}
      </div>
    </aside>
  );
}

function TopBar({ page, sources, onRefresh }: { page: Page; sources: SourceHealth[]; onRefresh: () => Promise<void> }) {
  const [refreshing, setRefreshing] = useState(false);
  const working = sources.filter((source) => source.status === "working").length;
  const activeSources = sources.filter((source) => source.status !== "needs_configuration").length;
  const title = navItems.find((item) => item.page === page)?.label ?? "Home";
  const runRefresh = async () => {
    setRefreshing(true);
    await onRefresh();
    setRefreshing(false);
  };
  return (
    <header className="sticky top-0 z-10 border-b border-zinc-200/80 bg-[#f5f7f6]/90 px-4 py-4 backdrop-blur sm:px-6 md:px-9">
      <div className="mx-auto flex max-w-[1400px] items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight md:text-2xl">{title}</h1>
          <p className="hidden text-sm text-zinc-500 sm:block">Defensive monitoring of public ransomware claims</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-zinc-900 p-1.5 shadow-sm ring-1 ring-zinc-700/10" title="Chill Ethical People">
            <img src="/chill-ethical-capybara-on-dark.svg" alt="Chill Ethical People" className="h-full w-full" />
          </div>
          <button type="button" onClick={() => void runRefresh()} className="button-secondary">
            <SpinnerGap className={refreshing ? "animate-spin" : ""} size={18} />
            <span className="hidden sm:inline">{working}/{activeSources} active sources working</span>
            <span className="sm:hidden">Refresh</span>
          </button>
        </div>
      </div>
    </header>
  );
}

function Home({ summary, onNavigate }: { summary: DashboardSummary; onNavigate: (page: Page) => void }) {
  const enabledSources = summary.sources.filter((source) => source.status !== "needs_configuration");
  const allWorking = enabledSources.length > 0 && enabledSources.every((source) => source.status === "working");
  return (
    <div className="space-y-9">
      <section className="grid gap-5 lg:grid-cols-[1.65fr_1fr]">
        <div className="overflow-hidden rounded-[2rem] bg-zinc-900 p-7 text-white shadow-[0_24px_55px_-30px_rgba(24,24,27,0.55)] md:p-9">
          <div className="flex items-center gap-2 text-sm text-zinc-300">
            <StatusPulse tone={summary.urgent_alerts ? "danger" : "healthy"} />
            {summary.urgent_alerts ? "Attention needed" : "Monitoring is active"}
          </div>
          <div className="mt-12 max-w-2xl">
            <p className="text-5xl font-semibold tracking-[-0.055em] md:text-7xl">{summary.urgent_alerts}</p>
            <h2 className="mt-3 text-2xl font-medium tracking-tight md:text-3xl">urgent client {summary.urgent_alerts === 1 ? "match" : "matches"}</h2>
            <p className="mt-3 max-w-[52ch] text-sm leading-relaxed text-zinc-400 md:text-base">
              Every result is a public threat-actor allegation. Review the evidence before contacting a client or escalating an incident.
            </p>
          </div>
          <div className="mt-8 flex flex-wrap gap-3"><button type="button" onClick={() => onNavigate("alerts")} className="inline-flex items-center gap-2 rounded-xl bg-white px-4 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-zinc-100 active:scale-[0.98]">Review urgent alerts <ArrowRight size={18} /></button>{summary.awaiting_review > 0 && <button type="button" onClick={() => onNavigate("review")} className="inline-flex items-center gap-2 rounded-xl bg-amber-400 px-4 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-amber-300 active:scale-[0.98]"><ListMagnifyingGlass size={18} />{summary.awaiting_review} requiring human review<ArrowRight size={18} /></button>}</div>
        </div>
        <div className="rounded-[2rem] border border-zinc-200 bg-white p-7 shadow-[0_20px_45px_-32px_rgba(24,24,27,0.25)] md:p-8">
          <div className="flex items-start justify-between">
            <div>
              <p className="eyebrow">System condition</p>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight">{allWorking ? "Sources are healthy" : "A source needs attention"}</h2>
            </div>
            {allWorking ? <CheckCircle className="text-teal-700" size={30} weight="duotone" /> : <Warning className="text-amber-600" size={30} weight="duotone" />}
          </div>
          <div className="mt-8 divide-y divide-zinc-100 border-y border-zinc-100">
            {summary.sources.map((source) => (
              <div key={source.source} className="flex items-center justify-between py-4">
                <div className="flex items-center gap-3">
                  <StatusPulse tone={source.status === "working" ? "healthy" : source.status === "unavailable" ? "danger" : "warning"} />
                  <div>
                    <p className="text-sm font-semibold">{sourceLabel(source.source)}</p>
                    <p className="text-xs text-zinc-500">{source.message}</p>
                  </div>
                </div>
                <span className="font-mono text-xs text-zinc-500">{source.records_received} records</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section>
        <div className="grid grid-cols-2 divide-x divide-zinc-200 border-y border-zinc-200 py-5 md:grid-cols-4">
          <Metric label="Claims today" value={summary.claims_today} />
          <Metric label="Awaiting review" value={summary.awaiting_review} />
          <Metric label="Monitored clients" value={summary.monitored_clients} />
          <Metric label="Sources online" value={summary.sources.filter((source) => source.status === "working").length} />
        </div>
      </section>

      <section className="grid gap-8 xl:grid-cols-[1.35fr_.85fr]">
        <div>
          <SectionHeading title="Latest client matches" description="The strongest links between public claims and your monitored organizations." action="View all alerts" onAction={() => onNavigate("alerts")} />
          {summary.new_alerts.length ? (
            <div className="mt-5 overflow-hidden rounded-2xl border border-zinc-200 bg-white">
              {summary.new_alerts.map((alert, index) => <AlertRow key={alert.id} alert={alert} divided={index > 0} />)}
            </div>
          ) : (
            <EmptyState title="No client matches" description="Monitoring is active. New matches will appear here with the evidence that produced them." icon={<ShieldCheck size={30} />} />
          )}
        </div>
        <div>
          <SectionHeading title="Recent activity" description="The latest claims received across all sources." action="Open activity" onAction={() => onNavigate("activity")} />
          <div className="mt-5 divide-y divide-zinc-200 border-y border-zinc-200">
            {summary.recent_claims.slice(0, 6).map((claim) => <ClaimRow key={claim.id} claim={claim} />)}
          </div>
        </div>
      </section>
    </div>
  );
}

function AlertsPage({ alerts, onUpdated }: { alerts: Alert[]; onUpdated: () => Promise<void> }) {
  const [filter, setFilter] = useState<"open" | "all" | "closed">("open");
  const [selected, setSelected] = useState<Alert | null>(null);
  const closedStatuses: AlertStatus[] = ["resolved", "dismissed"];
  const filtered = alerts.filter((alert) => filter === "all" || (filter === "open" ? !closedStatuses.includes(alert.status) : closedStatuses.includes(alert.status)));
  const statusCounts = alerts.reduce<Record<string, number>>((counts, alert) => ({ ...counts, [alert.status]: (counts[alert.status] || 0) + 1 }), {});
  return (
    <div>
      <PageIntro eyebrow="Client protection" title="Alerts" description="Review public claims that matched a monitored client, domain, or known name." />
      <div className="mt-7 grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(10rem,1fr))]">{(["new", "investigating", "client_notified", "monitoring", "resolved", "dismissed"] as AlertStatus[]).map((status) => <div key={status} className="min-w-0 rounded-2xl border border-zinc-200 bg-white p-4"><AlertStatusBadge status={status} /><p className="mt-3 font-mono text-2xl font-semibold">{statusCounts[status] || 0}</p></div>)}</div>
      <div className="mt-7 flex flex-wrap gap-2" role="group" aria-label="Alert filters">
        {(["open", "all", "closed"] as const).map((value) => (
          <button key={value} type="button" onClick={() => setFilter(value)} className={`filter-pill ${filter === value ? "filter-pill-active" : ""}`}>{value === "open" ? "Open workflow" : value === "closed" ? "Closed" : "All alerts"}</button>
        ))}
      </div>
      {filtered.length ? (
        <div className="mt-6 overflow-hidden rounded-2xl border border-zinc-200 bg-white">
          {filtered.map((alert, index) => <button type="button" className="block w-full text-left" onClick={() => setSelected(alert)} key={alert.id}><AlertRow alert={alert} divided={index > 0} /></button>)}
        </div>
      ) : <EmptyState title="Nothing needs attention" description="There are no alerts in this view. Monitoring and matching continue in the background." icon={<CheckCircle size={30} />} />}
      <AnimatePresence>{selected && <AlertDrawer alert={selected} onClose={() => setSelected(null)} onUpdated={async () => { setSelected(null); await onUpdated(); }} />}</AnimatePresence>
    </div>
  );
}

function AlertDrawer({ alert, onClose, onUpdated }: { alert: Alert; onClose: () => void; onUpdated: () => Promise<void> }) {
  const reducedMotion = useReducedMotion();
  const [working, setWorking] = useState(false);
  const [status, setStatus] = useState<AlertStatus>(alert.status);
  const [note, setNote] = useState(alert.note || "");
  const [draft, setDraft] = useState<NotificationDraft | null>(null);
  const [context, setContext] = useState<AlertIntelligenceContext | null>(null);
  const [contextLoading, setContextLoading] = useState(true);
  const [draftMode, setDraftMode] = useState<"ai" | "standard" | "">("");
  const [confirmAIDraft, setConfirmAIDraft] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    setContextLoading(true);
    void api.alertIntelligenceContext(alert.id)
      .then(setContext)
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Alert intelligence context could not be loaded"))
      .finally(() => setContextLoading(false));
  }, [alert.id]);
  const act = async (nextStatus: AlertStatus, nextNote = note) => {
    setWorking(true);
    setError("");
    try { await api.updateAlert(alert.id, nextStatus, nextNote); await onUpdated(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Alert status could not be updated"); setWorking(false); }
  };
  const openDraft = async (mode: "ai" | "standard") => {
    setWorking(true); setDraftMode(mode); setError("");
    try { setDraft(mode === "ai" ? await api.aiNotificationDraft(alert.id) : await api.notificationDraft(alert.id)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Draft could not be created"); }
    finally { setWorking(false); setDraftMode(""); }
  };
  return <>
    <motion.div className="fixed inset-0 z-30 bg-zinc-950/30 backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}>
      <motion.aside
        className="absolute inset-y-0 right-0 w-full max-w-4xl overflow-y-auto bg-[#f8faf9] p-5 shadow-2xl sm:p-8 lg:p-10"
        initial={{ x: reducedMotion ? 0 : "100%" }} animate={{ x: 0 }} exit={{ x: reducedMotion ? 0 : "100%" }}
        transition={{ type: "spring", stiffness: 160, damping: 24 }} onClick={(event) => event.stopPropagation()}
        aria-label="Alert details"
      >
        <div className="flex items-start justify-between gap-5">
          <div><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={alert.severity} /><AlertStatusBadge status={alert.status} /></div><h2 className="mt-4 text-3xl font-semibold tracking-tight">{alert.claim_title}</h2><p className="mt-2 text-zinc-500">Public ransomware claim by {alert.threat_actor}</p></div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close alert details"><X size={20} /></button>
        </div>
        <InlineNotice tone="neutral">This is an unverified threat-actor allegation, not confirmation of a breach.</InlineNotice>
        <div className="mt-7 grid gap-4 sm:grid-cols-2">
          <DetailBlock label="Matched client" value={alert.client_name} />
          <DetailBlock label="Why it matched" value={alert.reason} />
          <DetailBlock label="Confidence" value={`${alert.score} / 100`} mono />
          <DetailBlock label="Victim named / published" value={context?.published_at ? formatTime(context.published_at) : alert.published_at ? formatTime(alert.published_at) : "Not supplied by source"} />
          <DetailBlock label="Ingested locally" value={formatTime(context?.ingested_at || alert.received_at || alert.created_at)} />
        </div>
        <section className="mt-8"><p className="eyebrow">Evidence from the source</p><blockquote className="mt-3 rounded-2xl border border-zinc-200 bg-white p-5 text-sm leading-7 text-zinc-700">{alert.evidence || "The source did not include a separate description."}</blockquote></section>
        <section className="mt-8 border-t border-zinc-200 pt-7"><div className="flex items-center justify-between gap-3"><div><p className="eyebrow">Threat-actor profile</p><h3 className="mt-2 text-lg font-semibold">{alert.threat_actor}</h3></div>{context?.actor_profile && <span className="rounded-full bg-zinc-200 px-2.5 py-1 text-[10px] font-bold uppercase text-zinc-600">{context.actor_profile.confidence} data confidence</span>}</div>{contextLoading ? <div className="mt-4 flex items-center gap-2 text-sm text-zinc-500"><SpinnerGap className="animate-spin" size={17} />Building observed-activity profile…</div> : context?.actor_profile ? <div className="mt-4 rounded-2xl border border-zinc-200 bg-white p-5"><p className="text-sm leading-7 text-zinc-700">{context.actor_profile.summary}</p><div className="mt-4 grid gap-4 sm:grid-cols-2"><ProfileList title="Observed industries" items={context.actor_profile.top_industries} /><ProfileList title="Observed geographies" items={context.actor_profile.top_countries} /></div><p className="mt-4 text-[11px] leading-5 text-zinc-400">{context.actor_profile.caveat}</p></div> : <p className="mt-4 text-sm text-zinc-500">No actor profile is available for this observation period.</p>}</section>
        <section className="mt-8 border-t border-zinc-200 pt-7"><h3 className="text-lg font-semibold">Recommended next steps</h3><ol className="mt-4 space-y-3 text-sm text-zinc-600"><li className="flex gap-3"><StepNumber value="1" />Notify the client incident contact through an approved channel.</li><li className="flex gap-3"><StepNumber value="2" />Check for independent confirmation and relevant internal telemetry.</li><li className="flex gap-3"><StepNumber value="3" />Record investigation notes without treating the allegation as confirmed.</li></ol></section>
        <section className="mt-8 border-t border-zinc-200 pt-7"><h3 className="text-lg font-semibold">Workflow status</h3><div className="mt-4 grid gap-3 sm:grid-cols-[1fr_auto]"><CustomSelect ariaLabel="Workflow status" value={status} onChange={(value) => setStatus(value as AlertStatus)} options={(["new", "investigating", "client_notified", "monitoring", "resolved", "dismissed"] as AlertStatus[]).map((value) => ({ value, label: alertStatusLabel(value) }))} /><button type="button" disabled={working || status === alert.status} onClick={() => void act(status)} className="button-primary">Save status</button></div><textarea className="input mt-3 min-h-24 resize-y" value={note} onChange={(event) => setNote(event.target.value)} maxLength={500} placeholder="Investigation note or client response…" />{alert.notified_at && <p className="mt-2 text-xs text-zinc-500">Client-notified status first recorded {formatTime(alert.notified_at)}.</p>}</section>
        {error && <InlineNotice tone="danger">{error}</InlineNotice>}
        <div className="mt-8 grid grid-cols-1 gap-3 border-t border-zinc-200 pt-6 sm:grid-cols-2 lg:grid-cols-4">
          <button type="button" disabled={working} onClick={() => setConfirmAIDraft(true)} className="button-primary justify-center whitespace-nowrap">{draftMode === "ai" ? <SpinnerGap className="animate-spin" size={18} /> : <Cpu size={18} />}AI draft email</button>
          <button type="button" disabled={working} onClick={() => void openDraft("standard")} className="button-secondary justify-center whitespace-nowrap">{draftMode === "standard" ? <SpinnerGap className="animate-spin" size={18} /> : <EnvelopeSimple size={18} />}Standard draft</button>
          <button type="button" disabled={working} onClick={() => void act("investigating", note || "Investigation started")} className="button-secondary justify-center whitespace-nowrap"><Check size={18} />Start investigation</button>
          <button type="button" disabled={working} onClick={() => void act("dismissed", note || "Analyst marked this as an unrelated match")} className="button-secondary justify-center whitespace-nowrap"><XCircle size={18} />False match</button>
        </div>
      </motion.aside>
    </motion.div>
    {confirmAIDraft && <Modal title="Share sanitized alert context with the AI provider?" description="The platform replaces the monitored client identity before requesting a scenario-specific draft." onClose={() => setConfirmAIDraft(false)}><InlineNotice tone="neutral">The client name, primary domain, aliases, and direct-match references are replaced with MONITORED_CLIENT before leaving the platform. The real client name is restored locally after the draft returns.</InlineNotice><p className="mt-5 text-xs leading-5 text-zinc-500">The request still includes generalized monitoring regions and industries, the public claim, timestamps, match type, and locally observed threat-actor statistics. It never includes DLS addresses or leaked material. Choose the standard draft if no alert context may leave the platform.</p><div className="mt-6 flex flex-wrap justify-end gap-3"><button type="button" className="button-secondary" onClick={() => setConfirmAIDraft(false)}>Cancel</button><button type="button" className="button-primary" onClick={() => { setConfirmAIDraft(false); void openDraft("ai"); }}><Cpu size={18} />Continue with sanitized draft</button></div></Modal>}
    {draft && <NotificationDraftDialog draft={draft} onClose={() => setDraft(null)} onMarkNotified={async () => { await api.updateAlert(alert.id, "client_notified", note || "Analyst confirmed client notification"); setDraft(null); await onUpdated(); }} />}
  </>;
}

function NotificationDraftDialog({ draft, onClose, onMarkNotified }: { draft: NotificationDraft; onClose: () => void; onMarkNotified: () => Promise<void> }) {
  const [subject, setSubject] = useState(draft.subject);
  const [body, setBody] = useState(draft.body);
  const [copied, setCopied] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const copy = async () => {
    const content = `Subject: ${subject}\n\n${body}`;
    setError("");
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(content);
      else throw new Error("Clipboard API unavailable");
    } catch {
      const fallback = document.createElement("textarea");
      fallback.value = content;
      fallback.style.position = "fixed";
      fallback.style.opacity = "0";
      document.body.appendChild(fallback);
      fallback.focus();
      fallback.select();
      const succeeded = document.execCommand("copy");
      fallback.remove();
      if (!succeeded) {
        setError("Your browser blocked clipboard access. Select the message and copy it manually.");
        return;
      }
    }
    setCopied(true);
  };
  const openEmailApp = () => window.location.assign(`mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`);
  const markNotified = async () => {
    setWorking(true); setError("");
    try { await onMarkNotified(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Alert status could not be updated"); setWorking(false); }
  };
  return <motion.div className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-zinc-950/45 p-4 backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}><motion.div className="my-8 w-full max-w-3xl rounded-[2rem] bg-white p-6 shadow-2xl sm:p-8" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} onClick={(event) => event.stopPropagation()}><div className="flex items-start justify-between gap-4"><div><p className="eyebrow">Client communication</p><h2 className="mt-2 text-2xl font-semibold">Review notification draft</h2><p className="mt-2 text-sm text-zinc-500">{draft.disclaimer}</p></div><button type="button" className="icon-button" onClick={onClose}><X size={19} /></button></div><div className="mt-6"><Field label="Subject"><input className="input" value={subject} onChange={(event) => { setSubject(event.target.value); setCopied(false); }} /></Field></div><label className="mt-5 block"><span className="text-sm font-semibold text-zinc-800">Message</span><textarea className="input mt-2 min-h-[25rem] resize-y font-mono text-xs leading-6" value={body} onChange={(event) => { setBody(event.target.value); setCopied(false); }} /></label>{error && <InlineNotice tone="danger">{error}</InlineNotice>}<p className="mt-4 text-xs leading-5 text-zinc-500">Opening your email app does not send anything. Review the recipient and content there before sending.</p><div className="mt-6 flex flex-wrap justify-end gap-3"><button type="button" className="button-secondary" onClick={() => void copy()}>{copied ? <Check size={18} /> : <EnvelopeSimple size={18} />}{copied ? "Copied" : "Copy draft"}</button><button type="button" className="button-secondary" onClick={openEmailApp}><EnvelopeSimple size={18} />Open in email app</button><button type="button" disabled={working} className="button-primary" onClick={() => void markNotified()}>{working ? <SpinnerGap className="animate-spin" size={18} /> : <Check size={18} />}Mark as notified</button></div></motion.div></motion.div>;
}

function ClientsPage({ clients, onCreated }: { clients: Client[]; onCreated: () => Promise<void> }) {
  const [editing, setEditing] = useState<Client | null | undefined>(undefined);
  return (
    <div><div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><PageIntro eyebrow="Watchlist" title="Clients" description="Organizations, markets, industries, subsidiaries, and third parties monitored for public ransomware claims." /><button type="button" onClick={() => setEditing(null)} className="button-primary"><Plus size={18} />Add client</button></div>
      <div className="mt-8 overflow-hidden rounded-2xl border border-zinc-200 bg-white">
        {clients.map((client, index) => <div key={client.id} className={`grid gap-4 p-5 sm:grid-cols-[1.35fr_1fr_1fr_.7fr_auto] sm:items-center ${index ? "border-t border-zinc-200" : ""}`}><div><p className="font-semibold">{client.canonical_name}</p><p className="mt-1 font-mono text-xs text-zinc-500">{client.primary_domain}</p>{client.description && <p className="mt-2 line-clamp-2 text-xs leading-5 text-zinc-500">{client.description}</p>}</div><div><p className="text-sm text-zinc-700">{summarizeValues([...client.countries, ...client.cities], "Markets not set")}</p><p className="mt-1 text-xs text-zinc-500">{summarizeValues(client.industries, "Industries not set")}</p></div><div><p className="text-sm text-zinc-600">{client.related_entities.length ? `${client.related_entities.length} related ${client.related_entities.length === 1 ? "organization" : "organizations"}` : "No related organizations"}</p><p className="mt-1 text-xs text-zinc-500">{client.keywords.length ? `${client.keywords.length} alert ${client.keywords.length === 1 ? "keyword" : "keywords"}` : "No alert keywords"}</p></div><PriorityBadge priority={client.priority} /><button type="button" onClick={() => setEditing(client)} className="text-left text-sm font-semibold text-teal-800 sm:text-right">Edit profile</button></div>)}
      </div>
      <AnimatePresence>{editing !== undefined && <ClientModal client={editing} onClose={() => setEditing(undefined)} onCreated={async () => { setEditing(undefined); await onCreated(); }} />}</AnimatePresence>
    </div>
  );
}

function ClientModal({ client, onClose, onCreated }: { client: Client | null; onClose: () => void; onCreated: () => Promise<void> }) {
  const [form, setForm] = useState<NewClient>(client ? { canonical_name: client.canonical_name, primary_domain: client.primary_domain, description: client.description, countries: [...client.countries], cities: [...client.cities], industries: [...client.industries], related_entities: client.related_entities.map((entity) => ({ ...entity })), priority: client.priority, aliases: [...client.aliases], keywords: [...client.keywords] } : { ...emptyClient, countries: [...emptyClient.countries], cities: [], industries: [], related_entities: [], keywords: [] });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setSaving(true); setError("");
    try { if (client) await api.updateClient(client.id, form); else await api.createClient(form); await onCreated(); } catch (reason) { setError(reason instanceof Error ? reason.message : "Client could not be saved"); setSaving(false); }
  };
  return <Modal title={client ? "Edit monitored client" : "Add a monitored client"} description="Define the organization, operating markets, industries, and related companies that should participate in matching." onClose={onClose}><ClientForm form={form} setForm={setForm} onSubmit={submit} saving={saving} error={error} submitLabel={client ? "Save changes" : "Add client"} /></Modal>;
}

function ReviewPage({ alerts, onUpdated }: { alerts: Alert[]; onUpdated: () => Promise<void> }) {
  const reviews = alerts.filter((alert) => alert.severity === "review" && alert.status === "new");
  return <div><PageIntro eyebrow="Human verification" title="Review queue" description="Decide whether uncertain public claims refer to a monitored organization." />{reviews.length ? <div className="mt-8 space-y-5">{reviews.map((alert) => <div key={alert.id} className="rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><p className="eyebrow">Does this refer to {alert.client_name}?</p><h2 className="mt-3 text-2xl font-semibold tracking-tight">{alert.claim_title}</h2><p className="mt-3 max-w-3xl text-sm leading-7 text-zinc-600">{alert.evidence}</p><div className="mt-6 flex flex-wrap gap-3"><button type="button" className="button-primary" onClick={async () => { await api.updateAlert(alert.id, "investigating", "Analyst approved probable match"); await onUpdated(); }}><Check size={18} />Yes, investigate</button><button type="button" className="button-secondary" onClick={async () => { await api.updateAlert(alert.id, "dismissed", "Analyst rejected probable match"); await onUpdated(); }}><X size={18} />Unrelated company</button></div></div>)}</div> : <EmptyState title="Review queue is clear" description="Uncertain company-name matches will wait here for a person to verify." icon={<ListMagnifyingGlass size={30} />} />}</div>;
}

function IntelligencePage({ onNavigate }: { onNavigate: (page: Page) => void }) {
  const [days, setDays] = useState(30);
  const [query, setQuery] = useState("");
  const [actor, setActor] = useState("");
  const [country, setCountry] = useState("");
  const [industry, setIndustry] = useState("");
  const [publicationStatus, setPublicationStatus] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<IntelligenceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [analysisScope, setAnalysisScope] = useState<IntelligenceAnalysisScope>("overall");
  const [analysisValue, setAnalysisValue] = useState("");
  const [intelligenceAnalysis, setIntelligenceAnalysis] = useState<IntelligenceAIAnalysis | null>(null);
  const [analyzingIntelligence, setAnalyzingIntelligence] = useState(false);
  const [enrichingClaimId, setEnrichingClaimId] = useState("");
  const [bulkEnriching, setBulkEnriching] = useState(false);
  const [aiError, setAIError] = useState("");
  const [aiNotice, setAINotice] = useState("");
  const [actorProfiles, setActorProfiles] = useState<ThreatActorProfile[]>([]);
  const [selectedProfileActor, setSelectedProfileActor] = useState("");
  const [profileError, setProfileError] = useState("");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLoading(true);
      void api.intelligence({ days, query, actor, country, industry, publication_status: publicationStatus, page })
        .then((result) => { setData(result); setError(""); })
        .catch((reason) => setError(reason instanceof Error ? reason.message : "Intelligence could not be loaded"))
        .finally(() => setLoading(false));
    }, 220);
    return () => window.clearTimeout(timer);
  }, [days, query, actor, country, industry, publicationStatus, page]);

  useEffect(() => {
    void api.actorProfiles(days)
      .then((profiles) => {
        setActorProfiles(profiles);
        setSelectedProfileActor((current) => profiles.some((profile) => profile.actor === current) ? current : (profiles[0]?.actor ?? ""));
        setProfileError("");
      })
      .catch((reason) => setProfileError(reason instanceof Error ? reason.message : "Threat-actor profiles could not be loaded"));
  }, [days]);

  const analysisOptions = analysisScope === "actor" ? (data?.facets.actors ?? []) : analysisScope === "region" ? (data?.facets.countries ?? []) : analysisScope === "industry" ? (data?.facets.industries ?? []) : [];
  useEffect(() => {
    if (analysisScope === "overall") {
      if (analysisValue) setAnalysisValue("");
    } else if (!analysisOptions.includes(analysisValue)) {
      setAnalysisValue(analysisOptions[0] ?? "");
    }
  }, [analysisScope, analysisValue, analysisOptions]);

  const analyzeIntelligence = async () => {
    if (analysisScope !== "overall" && !analysisValue) return;
    setAnalyzingIntelligence(true); setAIError("");
    try { setIntelligenceAnalysis(await api.analyzeIntelligence(analysisScope, analysisValue, days || 365)); }
    catch (reason) { setAIError(reason instanceof Error ? reason.message : "Intelligence analysis failed"); }
    finally { setAnalyzingIntelligence(false); }
  };
  const enrichVictim = async (claimId: string) => {
    setEnrichingClaimId(claimId); setAIError(""); setAINotice("");
    try {
      const updated = await api.enrichVictim(claimId);
      setData((current) => current ? { ...current, victims: current.victims.map((claim) => claim.id === updated.id ? updated : claim) } : current);
    } catch (reason) { setAIError(reason instanceof Error ? reason.message : "Victim enrichment failed"); }
    finally { setEnrichingClaimId(""); }
  };
  const enrichNewVictims = async () => {
    setBulkEnriching(true); setAIError(""); setAINotice("");
    try {
      const result = await api.enrichNewVictims(25);
      setAINotice(`${result.enriched.toLocaleString()} new victim records enriched${result.failed ? `; ${result.failed} failed` : ""}. ${result.remaining.toLocaleString()} remain.`);
      if (result.errors.length) setAIError(result.errors.join(" · "));
      setData(await api.intelligence({ days, query, actor, country, industry, publication_status: publicationStatus, page }));
    } catch (reason) { setAIError(reason instanceof Error ? reason.message : "Bulk victim enrichment failed"); }
    finally { setBulkEnriching(false); }
  };

  const changeFilter = (setter: (value: string) => void, value: string) => { setter(value); setPage(1); };
  const maxTrend = Math.max(1, ...(data?.monthly_trend.map((item) => item.count) ?? [1]));
  return <div>
    <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end"><PageIntro eyebrow="Ransomware landscape" title="Victim intelligence" description="Explore deduplicated public ransomware claims by period, actor, geography, industry, and publication state." /><div className="flex flex-wrap gap-2" role="group" aria-label="Intelligence period">{[[30, "30 days"], [180, "6 months"], [365, "1 year"], [0, "All time"]].map(([value, label]) => <button type="button" key={value} onClick={() => { setDays(Number(value)); setPage(1); }} className={`filter-pill ${days === value ? "filter-pill-active" : ""}`}>{label}</button>)}</div></div>
    <InlineNotice tone="neutral">Records are threat-actor allegations aggregated from attributed public sources. Counts may differ from commercial platforms because proprietary telemetry is not included.</InlineNotice>
    <div className="mt-7 grid gap-3 lg:grid-cols-[1.4fr_repeat(4,1fr)]"><label className="flex min-h-12 items-center gap-3 rounded-xl border border-zinc-200 bg-white px-4"><MagnifyingGlass size={18} className="text-zinc-400" /><span className="sr-only">Search victims</span><input value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} className="w-full bg-transparent text-sm outline-none" placeholder="Search company, domain, actor…" /></label><FilterSelect label="Threat actor" value={actor} options={data?.facets.actors ?? []} onChange={(value) => changeFilter(setActor, value)} /><FilterSelect label="Country" value={country} options={data?.facets.countries ?? []} onChange={(value) => changeFilter(setCountry, value)} /><FilterSelect label="Industry" value={industry} options={data?.facets.industries ?? []} onChange={(value) => changeFilter(setIndustry, value)} /><FilterSelect label="Status" value={publicationStatus} options={data?.facets.statuses ?? []} onChange={(value) => changeFilter(setPublicationStatus, value)} /></div>
    {error && <InlineNotice tone="danger">{error}</InlineNotice>}
    <div className={`mt-7 grid gap-4 sm:grid-cols-2 xl:grid-cols-5 ${loading ? "opacity-60" : ""}`}><IntelligenceMetric label="Victim claims" value={data?.total ?? 0} helper="Deduplicated records" /><GrowthMetric growth={data?.overall_growth} basisDays={data?.growth_basis_days ?? (days || 30)} /><IntelligenceMetric label="Daily average" value={data?.daily_average ?? 0} helper="During selected period" /><IntelligenceMetric label="Active groups" value={data?.active_groups ?? 0} helper="Distinct operators" /><IntelligenceMetric label="Countries affected" value={data?.countries_affected ?? 0} helper="Known locations only" /></div>
    <div className="mt-7 grid gap-5 xl:grid-cols-[1.25fr_.75fr]"><section className="rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><div><p className="eyebrow">Attack volume</p><h3 className="mt-2 text-xl font-semibold">Monthly observations</h3></div>{data?.monthly_trend.length ? <div className="mt-8 flex h-48 items-end gap-2 border-b border-zinc-200">{data.monthly_trend.map((item) => <div key={item.month} className="group flex min-w-0 flex-1 flex-col items-center justify-end gap-2"><span className="text-[10px] font-semibold text-zinc-500 opacity-0 transition group-hover:opacity-100">{item.count}</span><div className="w-full rounded-t-lg bg-teal-700/85 transition hover:bg-teal-800" style={{ height: `${Math.max(5, item.count / maxTrend * 150)}px` }} /><span className="mb-2 hidden text-[9px] text-zinc-400 sm:block">{item.month.slice(2)}</span></div>)}</div> : <p className="mt-12 text-sm text-zinc-500">No monthly data in this period.</p>}</section><RankingCard title="Most active groups" items={data?.top_groups ?? []} /></div>
    <div className="mt-5 grid gap-5 lg:grid-cols-2"><RankingCard title="Most affected countries" items={data?.top_countries ?? []} /><RankingCard title="Most affected industries" items={data?.top_industries ?? []} /></div>
    <div className="mt-5 grid gap-5 xl:grid-cols-[1.15fr_.85fr]"><GrowthRankingCard title="Growth by threat group" description={`Latest ${data?.growth_basis_days ?? 30} days versus the preceding period.`} items={data?.group_growth ?? []} /><RegionGrowthCard items={data?.monitored_region_growth ?? []} basisDays={data?.growth_basis_days ?? 30} onEdit={() => onNavigate("settings")} /></div>
    <ThreatActorProfiles profiles={actorProfiles} selectedActor={selectedProfileActor} error={profileError} onSelect={setSelectedProfileActor} />
    <FlexibleAnalysisCard scope={analysisScope} value={analysisValue} options={analysisOptions} analysis={intelligenceAnalysis} working={analyzingIntelligence} onScope={(scope) => { setAnalysisScope(scope); setIntelligenceAnalysis(null); }} onValue={(value) => { setAnalysisValue(value); setIntelligenceAnalysis(null); }} onAnalyze={() => void analyzeIntelligence()} />
    {aiNotice && <InlineNotice tone="neutral">{aiNotice}</InlineNotice>}
    {aiError && <InlineNotice tone="danger">{aiError}</InlineNotice>}
    <VictimClaimsSection data={data} loading={loading} page={page} onPage={setPage} enrichingClaimId={enrichingClaimId} bulkEnriching={bulkEnriching} onEnrich={(claimId) => void enrichVictim(claimId)} onBulkEnrich={() => void enrichNewVictims()} />
  </div>;
}

function VictimClaimsSection({ data, loading, page, onPage, enrichingClaimId, bulkEnriching, onEnrich, onBulkEnrich }: { data: IntelligenceResponse | null; loading: boolean; page: number; onPage: (page: number) => void; enrichingClaimId: string; bulkEnriching: boolean; onEnrich: (claimId: string) => void; onBulkEnrich: () => void }) {
  return <section className="mt-8"><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><div><h3 className="text-xl font-semibold">Victim claims</h3><p className="mt-1 text-sm text-zinc-500">Source evidence plus optional AI context checked against passive public background sources.</p></div><div className="flex items-center gap-3"><button type="button" disabled={bulkEnriching || !!enrichingClaimId} onClick={onBulkEnrich} className="button-secondary whitespace-nowrap !border-violet-200 text-violet-800">{bulkEnriching ? <SpinnerGap className="animate-spin" size={17} /> : <Cpu size={17} />}{bulkEnriching ? "Checking backgrounds…" : "Enrich next 25 new"}</button>{loading && <SpinnerGap className="animate-spin text-teal-800" size={22} />}</div></div><div className="mt-5 overflow-x-auto rounded-2xl border border-zinc-200 bg-white"><table className="w-full min-w-[1050px] text-left"><thead className="border-b border-zinc-200 bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500"><tr><th className="px-5 py-4">Organization</th><th className="px-5 py-4">Country / industry</th><th className="px-5 py-4">Threat actor</th><th className="px-5 py-4">Status</th><th className="px-5 py-4">Source</th><th className="px-5 py-4 text-right">Published</th></tr></thead><tbody className="divide-y divide-zinc-100">{data?.victims.map((claim) => <tr key={claim.id} className="align-top hover:bg-zinc-50"><td className="px-5 py-4"><div className="flex items-start justify-between gap-3"><div><p className="font-semibold">{claim.title}</p><p className="mt-1 max-w-md text-xs leading-5 text-zinc-500">{claim.description || claim.domains[0] || "No source description supplied"}</p>{claim.ai_description && <div className="mt-2 max-w-md rounded-lg bg-violet-50 px-3 py-2 text-xs leading-5 text-violet-900"><span className="mr-2 font-bold uppercase tracking-wide">AI context</span>{claim.ai_description}{claim.ai_rationale && <p className="mt-1 text-[11px] text-violet-700">Match basis: {claim.ai_rationale}</p>}{claim.ai_sources.length > 0 && <div className="mt-1 flex flex-wrap gap-2">{claim.ai_sources.map((url, sourceIndex) => <a key={url} href={url} target="_blank" rel="noreferrer" className="font-semibold underline underline-offset-2">Background source {sourceIndex + 1}</a>)}</div>}</div>}</div><button type="button" disabled={!!enrichingClaimId || bulkEnriching} onClick={() => onEnrich(claim.id)} className="shrink-0 rounded-lg border border-violet-200 bg-white px-2.5 py-1.5 text-[11px] font-semibold text-violet-800 hover:bg-violet-50">{enrichingClaimId === claim.id ? <SpinnerGap className="animate-spin" size={14} /> : claim.ai_enriched_at ? "Refresh AI" : "AI enrich"}</button></div></td><td className="px-5 py-4 text-sm text-zinc-600"><p>{claim.country || claim.ai_country || "Unknown country"}{!claim.country && claim.ai_country && <span className="ml-1 rounded bg-violet-50 px-1.5 py-0.5 text-[10px] font-semibold text-violet-700">AI</span>}</p><p className="mt-1 text-xs text-zinc-500">{claim.industry || claim.ai_industry || "Unknown industry"}{!claim.industry && claim.ai_industry && <span className="ml-1 rounded bg-violet-50 px-1.5 py-0.5 font-semibold text-violet-700">AI</span>}</p>{claim.industry && claim.ai_industry && claim.industry.toLowerCase() !== claim.ai_industry.toLowerCase() && <p className="mt-1 text-[11px] text-violet-700">AI industry: {claim.ai_industry}</p>}{claim.country && claim.ai_country && claim.country.toLowerCase() !== claim.ai_country.toLowerCase() && <p className="mt-1 text-[11px] text-violet-700">AI geography: {claim.ai_country}</p>}{claim.ai_organization_type && <p className="mt-1 text-[11px] text-zinc-400">{claim.ai_organization_type} · {claim.ai_confidence ?? 0}% confidence</p>}</td><td className="px-5 py-4 text-sm font-medium">{claim.threat_actor}</td><td className="px-5 py-4"><ClaimStatus value={claim.publication_status} /></td><td className="px-5 py-4 text-sm text-zinc-600">{sourceLabel(claim.source)}</td><td className="px-5 py-4 text-right font-mono text-xs text-zinc-500">{claim.published_at ? formatTime(claim.published_at) : "Not supplied"}</td></tr>)}</tbody></table>{!loading && !data?.victims.length && <div className="p-10 text-center text-sm text-zinc-500">No claims match these filters.</div>}</div>{data && data.pages > 1 && <div className="mt-5 flex items-center justify-end gap-3"><button type="button" className="button-secondary" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button><span className="font-mono text-xs text-zinc-500">Page {page} of {data.pages}</span><button type="button" className="button-secondary" disabled={page >= data.pages} onClick={() => onPage(page + 1)}>Next</button></div>}</section>;
}

function DirectSitesPage() {
  const [query, setQuery] = useState("");
  const [data, setData] = useState<DirectSitesOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [showKaliGuide, setShowKaliGuide] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkUpdating, setBulkUpdating] = useState(false);
  const refresh = useCallback(async () => {
    setLoading(true);
    try { setData(await api.directSites(query)); setError(""); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Direct-site catalog could not be loaded"); }
    finally { setLoading(false); }
  }, [query]);
  useEffect(() => { const timer = window.setTimeout(() => void refresh(), 200); return () => window.clearTimeout(timer); }, [refresh]);
  const sync = async () => {
    setLoading(true); setNotice(""); setError("");
    try { const result = await api.syncDirectSites(); setNotice(`Catalog synchronized: ${result.received.toLocaleString()} DLS locations checked and ${result.created.toLocaleString()} added.`); await refresh(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Catalog synchronization failed"); }
  };
  const toggle = async (target: DlsTarget) => { await api.updateDirectSite(target.id, !target.capture_enabled); await refresh(); };
  const bulkUpdate = async (captureEnabled: boolean) => {
    if (!selectedIds.size) return;
    setBulkUpdating(true); setNotice(""); setError("");
    try {
      const result = await api.updateDirectSitesBulk(Array.from(selectedIds), captureEnabled);
      setNotice(`${result.updated.toLocaleString()} selected DLS ${captureEnabled ? "allowed" : "disallowed"}. No capture was started.`);
      setSelectedIds(new Set());
      await refresh();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Bulk allowlist update failed"); }
    finally { setBulkUpdating(false); }
  };
  const visibleTargets = data?.targets.slice(0, 120) ?? [];
  const selectTargets = (targets: DlsTarget[]) => setSelectedIds(new Set(targets.map((target) => target.id)));
  const toggleSelected = (targetId: string) => setSelectedIds((current) => { const next = new Set(current); if (next.has(targetId)) next.delete(targetId); else next.add(targetId); return next; });
  const queue = async (target: DlsTarget) => {
    setNotice(""); setError("");
    try { await api.queueCapture(target.id); setNotice(`Capture queued for ${target.group_name}.`); await refresh(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Capture could not be queued"); }
  };
  return <div><div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><PageIntro eyebrow="Isolated collection" title="Threat-actor sites" description="Maintain an attributed DLS catalog and select which public pages the Kali evidence worker may capture." /><div className="flex flex-wrap gap-3"><button type="button" className="button-secondary" onClick={() => setShowKaliGuide(true)}><Info size={18} />Kali setup guide</button><button type="button" className="button-primary" disabled={loading} onClick={() => void sync()}><SpinnerGap className={loading ? "animate-spin" : ""} size={18} />Synchronize catalog</button></div></div>
    {!data?.worker_configured && <InlineNotice tone="neutral"><span><strong>Kali worker connection pending.</strong> For the simplest isolation boundary, install and use the full platform directly inside the Kali VM. <button type="button" className="font-semibold text-teal-800 underline" onClick={() => setShowKaliGuide(true)}>Open the setup guide</button>.</span></InlineNotice>}
    {notice && <InlineNotice tone="neutral">{notice}</InlineNotice>}{error && <InlineNotice tone="danger">{error}</InlineNotice>}
    <div className="mt-7 grid gap-4 sm:grid-cols-3"><IntelligenceMetric label="DLS locations" value={data?.catalog_total ?? 0} helper="Maintained public catalog" /><IntelligenceMetric label="Reported available" value={data?.available ?? 0} helper="Upstream availability signal" /><IntelligenceMetric label="Capture allowlist" value={data?.capture_enabled ?? 0} helper="Explicitly approved sites" /></div>
    <label className="mt-7 flex max-w-xl items-center gap-3 rounded-xl border border-zinc-200 bg-white px-4 py-3"><MagnifyingGlass size={19} className="text-zinc-400" /><span className="sr-only">Search threat-actor sites</span><input value={query} onChange={(event) => setQuery(event.target.value)} className="w-full bg-transparent text-sm outline-none" placeholder="Search group or catalog title" /></label>
    <div className="mt-4 flex flex-col justify-between gap-3 rounded-2xl border border-zinc-200 bg-white p-4 sm:flex-row sm:items-center"><div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold text-zinc-800">{selectedIds.size.toLocaleString()} selected</span><button type="button" onClick={() => selectTargets(visibleTargets)} disabled={!visibleTargets.length || bulkUpdating} className="text-xs font-semibold text-teal-800">Select visible</button><span className="text-zinc-300">·</span><button type="button" onClick={() => selectTargets(visibleTargets.filter((target) => target.capture_enabled))} disabled={!visibleTargets.some((target) => target.capture_enabled) || bulkUpdating} className="text-xs font-semibold text-zinc-600">Select allowed</button><span className="text-zinc-300">·</span><button type="button" onClick={() => selectTargets(visibleTargets.filter((target) => !target.capture_enabled))} disabled={!visibleTargets.some((target) => !target.capture_enabled) || bulkUpdating} className="text-xs font-semibold text-zinc-600">Select disallowed</button>{selectedIds.size > 0 && <><span className="text-zinc-300">·</span><button type="button" onClick={() => setSelectedIds(new Set())} disabled={bulkUpdating} className="text-xs font-semibold text-zinc-500">Clear</button></>}</div><div className="flex flex-wrap gap-2"><button type="button" disabled={!selectedIds.size || bulkUpdating} onClick={() => void bulkUpdate(true)} className="button-primary !min-h-10 px-4 text-xs">{bulkUpdating ? <SpinnerGap className="animate-spin" size={16} /> : <Check size={16} />}Allow selected</button><button type="button" disabled={!selectedIds.size || bulkUpdating} onClick={() => void bulkUpdate(false)} className="button-secondary !min-h-10 px-4 text-xs"><XCircle size={16} />Disallow selected</button></div></div>
    <div className="mt-6 overflow-hidden rounded-2xl border border-zinc-200 bg-white">{visibleTargets.map((target, index) => <div key={target.id} className={`grid gap-4 p-5 lg:grid-cols-[auto_1.2fr_1fr_.65fr_auto] lg:items-center ${index ? "border-t border-zinc-100" : ""} ${selectedIds.has(target.id) ? "bg-teal-50/50" : ""}`}><label className="flex items-center"><input type="checkbox" checked={selectedIds.has(target.id)} onChange={() => toggleSelected(target.id)} className="h-4 w-4 rounded border-zinc-300 accent-teal-700" aria-label={`Select ${target.group_name}`} /></label><div><div className="flex flex-wrap items-center gap-2"><p className="font-semibold">{target.group_name}</p><span className={`rounded-full px-2.5 py-1 text-[10px] font-bold uppercase ${target.available ? "bg-teal-50 text-teal-800" : "bg-zinc-100 text-zinc-500"}`}>{target.available ? "reported online" : "not reported online"}</span></div><p className="mt-1 line-clamp-2 text-xs leading-5 text-zinc-500">{target.description || target.title || "No catalog description"}</p></div><div><p className="font-mono text-xs text-zinc-600">{target.address_hint}</p><p className="mt-1 text-xs text-zinc-400">Address stored locally · not clickable</p></div><div><p className="text-xs font-semibold text-zinc-700">Last capture</p><p className="mt-1 text-xs text-zinc-500">{target.last_capture_at ? formatTime(target.last_capture_at) : "Never"}</p></div><div className="flex flex-wrap gap-2 lg:justify-end"><button type="button" className={target.capture_enabled ? "button-primary" : "button-secondary"} onClick={() => void toggle(target)}>{target.capture_enabled ? <Check size={17} /> : <Plus size={17} />}{target.capture_enabled ? "Allowed" : "Allow"}</button><button type="button" className="button-secondary" disabled={!target.capture_enabled || !data?.worker_configured} onClick={() => void queue(target)}><Camera size={17} />Capture</button></div></div>)}{!loading && !visibleTargets.length && <div className="p-10 text-center text-sm text-zinc-500">No DLS locations match this search.</div>}</div>{(data?.targets.length ?? 0) > 120 && <p className="mt-3 text-xs text-zinc-500">Showing the first 120 results. Search by group to narrow the catalog.</p>}
    {!!data?.jobs.length && <section className="mt-9"><h3 className="text-xl font-semibold">Recent capture jobs</h3><div className="mt-4 divide-y divide-zinc-100 overflow-hidden rounded-2xl border border-zinc-200 bg-white">{data.jobs.map((job) => <div key={job.id} className="flex items-center justify-between gap-4 p-5"><div><p className="text-sm font-semibold">{job.group_name}</p><p className="mt-1 font-mono text-xs text-zinc-400">{job.address_hint}</p></div><div className="text-right"><p className="text-xs font-semibold uppercase text-zinc-600">{job.status}</p><p className="mt-1 text-xs text-zinc-400">{formatTime(job.requested_at)}</p></div></div>)}</div></section>}
    <AnimatePresence>{showKaliGuide && <KaliSetupGuide onClose={() => setShowKaliGuide(false)} />}</AnimatePresence>
  </div>;
}

function KaliSetupGuide({ onClose }: { onClose: () => void }) {
  return <Modal title="Recommended Kali deployment" description="Run the complete platform inside a dedicated Kali VM when direct-site capture is required. This keeps Tor, Chromium, evidence, and the GUI isolated from the host." onClose={onClose}><div className="mt-6 rounded-2xl border border-teal-200 bg-teal-50 p-5"><p className="text-sm font-semibold text-teal-900">Works with your preferred VM platform</p><p className="mt-2 text-xs leading-5 text-teal-800">Use NAT networking in VMware, VirtualBox, Parallels, UTM, or another trusted hypervisor. Keep the app bound to 127.0.0.1, take a VM snapshot, and open the GUI inside Kali. Avoid shared folders and clipboard while collecting.</p></div><ol className="mt-6 space-y-5"><li className="flex gap-3"><StepNumber value="1" /><div><p className="text-sm font-semibold">Copy the project into Kali</p><p className="mt-1 text-xs leading-5 text-zinc-500">Use SCP or a temporary read-only transfer. Place the folder under your Kali home directory, then disable the transfer mechanism.</p></div></li><li className="flex gap-3"><StepNumber value="2" /><div className="min-w-0"><p className="text-sm font-semibold">Run the one-command installer</p><pre className="mt-2 overflow-x-auto rounded-xl bg-zinc-900 p-4 font-mono text-xs text-zinc-100">chmod +x setup-kali.sh{`\n`}./setup-kali.sh --prepare-capture</pre><div className="mt-3 flex flex-wrap items-center gap-3"><a href="/downloads/setup-kali.sh" download="setup-kali.sh" className="button-secondary !min-h-10 px-4 text-xs"><DownloadSimple size={17} />Download setup-kali.sh</a><span className="text-xs text-zinc-500">Save it in the ExtortSignal project folder before running it.</span></div><p className="mt-3 text-xs leading-5 text-zinc-500">The script requests sudo only for required Kali packages and the local system service.</p></div></li><li className="flex gap-3"><StepNumber value="3" /><div><p className="text-sm font-semibold">Open the GUI inside Kali</p><p className="mt-1 font-mono text-xs text-zinc-600">http://127.0.0.1:8765</p></div></li><li className="flex gap-3"><StepNumber value="4" /><div><p className="text-sm font-semibold">Allowlist cautiously</p><p className="mt-1 text-xs leading-5 text-zinc-500">Enable only attributed sites you need. Do not authenticate, submit forms, message actors, or download leaked data.</p></div></li></ol><InlineNotice tone="neutral">The installer prepares Tor and Chromium but the automated screenshot worker is still a separate component. Until it is installed, the catalog and allowlist work, while capture jobs remain queued.</InlineNotice><div className="mt-6 flex justify-end"><button type="button" className="button-primary" onClick={onClose}><Check size={18} />Understood</button></div></Modal>;
}

type DropdownOption = { value: string; label: string };

function CustomSelect({ ariaLabel, value, options, onChange, placeholder = "Choose an option", className = "" }: { ariaLabel: string; value: string; options: DropdownOption[]; onChange: (value: string) => void; placeholder?: string; className?: string }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const selected = options.find((option) => option.value === value);
  useEffect(() => {
    const close = (event: MouseEvent) => { if (!root.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  return <div ref={root} className={`relative min-w-0 ${className}`}><button type="button" aria-label={ariaLabel} aria-haspopup="listbox" aria-expanded={open} onClick={() => setOpen(!open)} onKeyDown={(event) => { if (event.key === "Escape") setOpen(false); }} className={`input flex items-center justify-between gap-3 text-left hover:border-zinc-300 hover:bg-zinc-50 ${open ? "border-teal-700 ring-4 ring-teal-700/10" : ""}`}><span className={`min-w-0 truncate ${selected ? "text-zinc-900" : "text-zinc-500"}`}>{selected?.label ?? placeholder}</span><CaretDown size={17} className={`shrink-0 text-zinc-400 transition ${open ? "rotate-180" : ""}`} /></button>{open && <div role="listbox" aria-label={ariaLabel} className="absolute z-50 mt-2 max-h-64 min-w-full overflow-y-auto rounded-2xl border border-zinc-200 bg-white p-2 shadow-[0_20px_50px_-20px_rgba(24,24,27,.35)]">{options.map((option) => <button type="button" role="option" aria-selected={option.value === value} key={option.value} onClick={() => { onChange(option.value); setOpen(false); }} className={`flex w-full items-center justify-between gap-4 rounded-xl px-3 py-2.5 text-left text-sm transition hover:bg-teal-50 hover:text-teal-900 ${option.value === value ? "bg-teal-50 font-semibold text-teal-900" : "text-zinc-700"}`}><span className="whitespace-nowrap">{option.label}</span>{option.value === value && <Check size={15} className="shrink-0 text-teal-700" />}</button>)}</div>}</div>;
}

function FilterSelect({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) { return <CustomSelect ariaLabel={label} value={value} onChange={onChange} options={[{ value: "", label: `All ${label.toLowerCase()}s` }, ...options.map((option) => ({ value: option, label: option.replaceAll("_", " ") }))]} />; }
function IntelligenceMetric({ label, value, helper }: { label: string; value: number; helper: string }) { return <div className="rounded-2xl border border-zinc-200 bg-white p-5"><p className="text-xs font-semibold uppercase tracking-wide text-zinc-400">{label}</p><p className="mt-3 font-mono text-3xl font-semibold tracking-tight">{value.toLocaleString()}</p><p className="mt-1 text-xs text-zinc-500">{helper}</p></div>; }
function GrowthMetric({ growth, basisDays }: { growth?: IntelligenceResponse["overall_growth"]; basisDays: number }) { const positive = (growth?.change ?? 0) > 0; const negative = (growth?.change ?? 0) < 0; const label = growth?.growth_percent == null ? (growth?.current_count ? "New activity" : "No baseline") : `${growth.growth_percent > 0 ? "+" : ""}${growth.growth_percent}%`; return <div className={`rounded-2xl border p-5 ${positive ? "border-amber-200 bg-amber-50" : negative ? "border-teal-200 bg-teal-50" : "border-zinc-200 bg-white"}`}><p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">Claim growth</p><p className={`mt-3 font-mono text-3xl font-semibold tracking-tight ${positive ? "text-amber-800" : negative ? "text-teal-800" : ""}`}>{label}</p><p className="mt-1 text-xs text-zinc-500">{growth?.current_count ?? 0} vs {growth?.previous_count ?? 0} · {basisDays} days</p></div>; }
function RankingCard({ title, items }: { title: string; items: { name: string; count: number; is_monitored?: boolean }[] }) { const max = Math.max(1, ...(items.map((item) => item.count))); return <section className="rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><h3 className="text-xl font-semibold">{title}</h3><div className="mt-6 space-y-4">{items.length ? items.map((item, index) => <div key={item.name} className={item.is_monitored ? "rounded-xl bg-sky-50 p-3 ring-1 ring-sky-200" : ""}><div className="flex items-center justify-between gap-4 text-sm"><span className="truncate"><span className="mr-2 font-mono text-xs text-zinc-400">{index + 1}</span>{item.name}{item.is_monitored && <span className="ml-2 rounded-full bg-sky-100 px-2 py-0.5 text-[10px] font-bold uppercase text-sky-800">Your region</span>}</span><span className="font-mono text-xs font-semibold">{item.count.toLocaleString()}</span></div><div className="mt-2 h-1.5 overflow-hidden rounded-full bg-zinc-100"><div className={`h-full rounded-full ${item.is_monitored ? "bg-sky-600" : "bg-teal-700"}`} style={{ width: `${Math.max(4, item.count / max * 100)}%` }} /></div></div>) : <p className="text-sm text-zinc-500">No enriched data in this period.</p>}</div></section>; }
function GrowthRankingCard({ title, description, items }: { title: string; description: string; items: IntelligenceResponse["group_growth"] }) { return <section className="rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><h3 className="text-xl font-semibold">{title}</h3><p className="mt-1 text-xs text-zinc-500">{description}</p><div className="mt-6 divide-y divide-zinc-100">{items.length ? items.slice(0, 10).map((item) => <div key={item.name} className="grid grid-cols-[1fr_auto_auto] items-center gap-4 py-3"><div className="min-w-0"><p className="truncate text-sm font-semibold">{item.name}</p><p className="mt-1 text-xs text-zinc-400">{item.current_count} current · {item.previous_count} previous</p></div><span className={`font-mono text-xs font-bold ${item.change > 0 ? "text-amber-700" : item.change < 0 ? "text-teal-700" : "text-zinc-400"}`}>{item.change > 0 ? "+" : ""}{item.change}</span><GrowthBadge percent={item.growth_percent} current={item.current_count} /></div>) : <p className="py-8 text-sm text-zinc-500">No group activity in either comparison period.</p>}</div></section>; }
function RegionGrowthCard({ items, basisDays, onEdit }: { items: IntelligenceResponse["monitored_region_growth"]; basisDays: number; onEdit: () => void }) { return <section className="rounded-[2rem] border border-sky-200 bg-sky-50/50 p-6 md:p-8"><div className="flex items-start justify-between gap-4"><div><p className="eyebrow !text-sky-700">Your footprint</p><h3 className="mt-2 text-xl font-semibold">Monitored regions and cities</h3></div><button type="button" onClick={onEdit} className="text-sm font-semibold text-sky-800">Edit regions</button></div><p className="mt-2 text-xs leading-5 text-zinc-500">Highlighted from global focus regions plus client-profile markets and cities. Comparing {basisDays}-day periods.</p><div className="mt-5 space-y-3">{items.length ? items.map((item) => <div key={item.name} className="flex items-center justify-between gap-4 rounded-xl border border-sky-100 bg-white p-4"><div><p className="text-sm font-semibold">{item.name}</p><p className="mt-1 text-xs text-zinc-400">{item.current_count} current · {item.previous_count} previous · {item.count} selected</p></div><GrowthBadge percent={item.growth_percent} current={item.current_count} /></div>) : <p className="rounded-xl bg-white p-5 text-sm text-zinc-500">Choose global focus regions in Settings or add markets and cities to a client profile.</p>}</div></section>; }
function GrowthBadge({ percent, current }: { percent: number | null; current: number }) { const text = percent == null ? (current ? "New" : "—") : `${percent > 0 ? "+" : ""}${percent}%`; return <span className={`min-w-14 rounded-full px-2.5 py-1 text-center font-mono text-xs font-bold ${percent == null && current ? "bg-amber-100 text-amber-800" : (percent ?? 0) > 0 ? "bg-amber-100 text-amber-800" : (percent ?? 0) < 0 ? "bg-teal-100 text-teal-800" : "bg-zinc-100 text-zinc-500"}`}>{text}</span>; }
function ClaimStatus({ value }: { value: string }) { const leaked = value === "data_leaked"; return <span className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold capitalize ${leaked ? "bg-rose-50 text-rose-800" : "bg-amber-50 text-amber-800"}`}>{value.replaceAll("_", " ")}</span>; }

function ThreatActorProfiles({ profiles, selectedActor, error, onSelect }: { profiles: ThreatActorProfile[]; selectedActor: string; error: string; onSelect: (actor: string) => void }) {
  const profile = profiles.find((item) => item.actor === selectedActor) ?? profiles[0];
  const trend = profile?.growth_percent === null ? "New in comparison period" : `${profile && profile.growth_percent > 0 ? "+" : ""}${profile?.growth_percent ?? 0}%`;
  return <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end"><div><p className="eyebrow">Analyst profiles</p><h3 className="mt-2 text-xl font-semibold">Threat-actor overview</h3><p className="mt-2 max-w-3xl text-xs leading-5 text-zinc-500">Short profiles are generated for every actor label from locally observed claims. They do not assert identity, origin, motivation, capabilities or attribution.</p></div><div className="w-full lg:max-w-sm"><CustomSelect ariaLabel="Select threat actor profile" value={profile?.actor ?? ""} onChange={onSelect} placeholder="Select a threat actor" options={profiles.map((item) => ({ value: item.actor, label: `${item.actor} · ${item.claim_count}` }))} /></div></div>{error && <InlineNotice tone="danger">{error}</InlineNotice>}{profile ? <div className="mt-6 grid gap-5 xl:grid-cols-[1.3fr_.7fr]"><div className="rounded-2xl bg-zinc-50 p-5"><div className="flex flex-wrap items-center gap-2"><h4 className="text-lg font-semibold">{profile.actor}</h4><span className={`rounded-full px-2.5 py-1 text-[10px] font-bold uppercase ${profile.confidence === "high" ? "bg-teal-100 text-teal-800" : profile.confidence === "moderate" ? "bg-amber-100 text-amber-800" : "bg-zinc-200 text-zinc-600"}`}>{profile.confidence} data confidence</span></div><p className="mt-4 text-sm leading-7 text-zinc-700">{profile.summary}</p>{profile.possible_aliases.length > 0 && <p className="mt-3 text-xs text-amber-800"><span className="font-semibold">Possible naming variants:</span> {profile.possible_aliases.join(", ")}. Analyst confirmation required.</p>}<div className="mt-5 grid gap-4 sm:grid-cols-2"><ProfileList title="Observed victim industries" items={profile.top_industries} /><ProfileList title="Observed geographies" items={profile.top_countries} /></div><p className="mt-5 border-t border-zinc-200 pt-4 text-[11px] leading-5 text-zinc-500">{profile.caveat}</p></div><div className="rounded-2xl border border-zinc-200 p-5"><p className="text-xs font-bold uppercase tracking-wide text-zinc-400">Observed activity</p><dl className="mt-4 space-y-3 text-sm"><div className="flex justify-between gap-3"><dt className="text-zinc-500">Claims in period</dt><dd className="font-mono font-semibold">{profile.claim_count}</dd></div><div className="flex justify-between gap-3"><dt className="text-zinc-500">Current {profile.trend_basis_days} days</dt><dd className="font-mono font-semibold">{profile.current_count}</dd></div><div className="flex justify-between gap-3"><dt className="text-zinc-500">Previous period</dt><dd className="font-mono font-semibold">{profile.previous_count}</dd></div><div className="flex justify-between gap-3"><dt className="text-zinc-500">Change</dt><dd className="font-mono font-semibold">{trend}</dd></div><div className="flex justify-between gap-3"><dt className="text-zinc-500">First observed</dt><dd className="font-mono text-xs font-semibold">{formatTime(profile.first_observed_at)}</dd></div><div className="flex justify-between gap-3"><dt className="text-zinc-500">Latest observed</dt><dd className="font-mono text-xs font-semibold">{formatTime(profile.last_observed_at)}</dd></div></dl><p className="mt-5 text-[11px] leading-5 text-zinc-400">Sources: {profile.sources.map((item) => `${sourceLabel(item.name)} (${item.count})`).join(", ")}</p></div></div> : !error && <div className="mt-6 rounded-2xl border border-dashed border-zinc-200 p-6 text-sm text-zinc-500">No actor profiles are available for this period.</div>}</section>;
}

function ProfileList({ title, items }: { title: string; items: { name: string; count: number }[] }) {
  return <div><p className="text-xs font-bold uppercase tracking-wide text-zinc-400">{title}</p><div className="mt-2 flex flex-wrap gap-2">{items.length ? items.map((item) => <span key={item.name} className="rounded-full bg-white px-2.5 py-1 text-xs text-zinc-700">{item.name} · {item.count}</span>) : <span className="text-xs text-zinc-400">Not supplied</span>}</div></div>;
}

function FlexibleAnalysisCard({ scope, value, options, analysis, working, onScope, onValue, onAnalyze }: { scope: IntelligenceAnalysisScope; value: string; options: string[]; analysis: IntelligenceAIAnalysis | null; working: boolean; onScope: (scope: IntelligenceAnalysisScope) => void; onValue: (value: string) => void; onAnalyze: () => void }) {
  const scopeOptions: DropdownOption[] = [
    { value: "overall", label: "Overall ransomware trend" },
    { value: "actor", label: "By threat actor" },
    { value: "region", label: "By region" },
    { value: "industry", label: "By victim industry" },
  ];
  const targetLabels = { actor: "Choose a threat actor", region: "Choose a region", industry: "Choose a victim industry", overall: "Overall dataset" };
  const canAnalyze = scope === "overall" || Boolean(value);
  return <section className="mt-5 rounded-[2rem] border border-violet-200 bg-white p-6 md:p-8"><div className="flex min-w-0 flex-col justify-between gap-5"><div><p className="eyebrow !text-violet-700">Flexible AI-assisted analysis</p><h3 className="mt-2 text-xl font-semibold">Landscape and victim-pattern assessment</h3><p className="mt-2 max-w-3xl text-xs leading-5 text-zinc-500">Choose the whole landscape or narrow the evidence by actor, region, or victim industry. The model compares volume, growth, victim mix, geography, and concentration using stored claims only.</p></div><div className="grid min-w-0 gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]"><CustomSelect ariaLabel="Analysis scope" value={scope} onChange={(next) => onScope(next as IntelligenceAnalysisScope)} options={scopeOptions} />{scope === "overall" ? <div className="input flex items-center text-zinc-500">All locally stored claims</div> : <CustomSelect ariaLabel={targetLabels[scope]} value={value} onChange={onValue} placeholder={targetLabels[scope]} options={options.map((option) => ({ value: option, label: option }))} />}<button type="button" disabled={!canAnalyze || working} onClick={onAnalyze} className="button-primary shrink-0 whitespace-nowrap !bg-violet-700 hover:!bg-violet-800">{working ? <SpinnerGap className="animate-spin" size={18} /> : <Cpu size={18} />}{analysis ? "Refresh analysis" : "Analyze selection"}</button></div></div>{analysis ? <div className="mt-6 grid gap-5 lg:grid-cols-[1.25fr_.75fr]"><div className="rounded-2xl bg-violet-50 p-5"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full bg-white px-3 py-1 text-xs font-semibold text-violet-800">{analysis.label}</span><span className="text-xs text-violet-700">{analysis.claim_count} claims · {analysis.confidence}% AI confidence</span></div><p className="mt-4 text-sm leading-7 text-zinc-700">{analysis.summary || "The model did not provide a narrative."}</p>{analysis.patterns.length > 0 && <AnalysisList title="Observed patterns" items={analysis.patterns} />}{analysis.risk_observations.length > 0 && <AnalysisList title="Defensive observations" items={analysis.risk_observations} />}{analysis.caveats.length > 0 && <AnalysisList title="Limitations" items={analysis.caveats} muted />}</div><div className="rounded-2xl border border-zinc-200 p-5"><p className="text-xs font-bold uppercase tracking-wide text-zinc-400">Observed locally</p><dl className="mt-4 space-y-3 text-sm"><div className="flex justify-between gap-3"><dt className="text-zinc-500">Current period</dt><dd className="font-mono font-semibold">{analysis.growth.current_count}</dd></div><div className="flex justify-between gap-3"><dt className="text-zinc-500">Previous period</dt><dd className="font-mono font-semibold">{analysis.growth.previous_count}</dd></div><div className="flex justify-between gap-3"><dt className="text-zinc-500">Change</dt><dd className="font-mono font-semibold">{analysis.growth.change > 0 ? "+" : ""}{analysis.growth.change}</dd></div></dl><p className="mt-5 text-[11px] leading-5 text-zinc-400">Generated {formatTime(analysis.generated_at)} with {analysis.provider} · {analysis.model}</p></div></div> : <div className="mt-6 rounded-2xl border border-dashed border-violet-200 bg-violet-50/40 p-6 text-sm text-zinc-500">Select an analysis lens to generate a bounded assessment of the current local dataset.</div>}</section>;
}

function AnalysisList({ title, items, muted = false }: { title: string; items: string[]; muted?: boolean }) { return <div className="mt-4"><p className={`text-[11px] font-bold uppercase tracking-wide ${muted ? "text-zinc-400" : "text-violet-700"}`}>{title}</p><ul className={`mt-2 space-y-2 text-sm ${muted ? "text-zinc-500" : "text-zinc-600"}`}>{items.map((item) => <li key={item} className="flex gap-2"><span className="text-violet-500">•</span>{item}</li>)}</ul></div>; }

type ActivitySortKey = "claim" | "actor" | "country" | "published" | "ingested";
type ActivityDateFilter = "all" | "24h" | "7d" | "30d" | "missing";

function ActivityPage({ claims }: { claims: Claim[] }) {
  const [claimFilter, setClaimFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [countryFilter, setCountryFilter] = useState("");
  const [publishedFilter, setPublishedFilter] = useState<ActivityDateFilter>("all");
  const [ingestedFilter, setIngestedFilter] = useState<ActivityDateFilter>("all");
  const [sortKey, setSortKey] = useState<ActivitySortKey>("ingested");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");
  const actors = useMemo(() => Array.from(new Set(claims.map((claim) => claim.threat_actor).filter(Boolean))).sort((a, b) => a.localeCompare(b)), [claims]);
  const countries = useMemo(() => Array.from(new Set(claims.map((claim) => claim.country || "Unknown country"))).sort((a, b) => a.localeCompare(b)), [claims]);
  const dateOptions: DropdownOption[] = [{ value: "all", label: "Any date" }, { value: "24h", label: "Last 24 hours" }, { value: "7d", label: "Last 7 days" }, { value: "30d", label: "Last 30 days" }];
  const publishedOptions = [...dateOptions, { value: "missing", label: "Date not supplied" }];

  const rows = useMemo(() => {
    const now = Date.now();
    const withinDate = (value: string | null, filter: ActivityDateFilter) => {
      if (filter === "all") return true;
      if (filter === "missing") return !value;
      if (!value) return false;
      const age = now - new Date(value).getTime();
      const hours = filter === "24h" ? 24 : filter === "7d" ? 24 * 7 : 24 * 30;
      return age >= 0 && age <= hours * 60 * 60 * 1000;
    };
    const needle = claimFilter.trim().toLowerCase();
    const filtered = claims.filter((claim) => {
      const claimText = `${claim.title} ${claim.source} ${claim.domains.join(" ")}`.toLowerCase();
      return (!needle || claimText.includes(needle))
        && (!actorFilter || claim.threat_actor === actorFilter)
        && (!countryFilter || (claim.country || "Unknown country") === countryFilter)
        && withinDate(claim.published_at, publishedFilter)
        && withinDate(claim.received_at, ingestedFilter);
    });
    const values = (claim: Claim) => ({
      claim: claim.title.toLowerCase(),
      actor: claim.threat_actor.toLowerCase(),
      country: (claim.country || "Unknown country").toLowerCase(),
      published: claim.published_at ? new Date(claim.published_at).getTime() : 0,
      ingested: new Date(claim.received_at).getTime(),
    });
    return filtered.sort((left, right) => {
      const a = values(left)[sortKey];
      const b = values(right)[sortKey];
      const order = typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b));
      return sortDirection === "asc" ? order : -order;
    });
  }, [claims, claimFilter, actorFilter, countryFilter, publishedFilter, ingestedFilter, sortKey, sortDirection]);

  const sort = (key: ActivitySortKey) => {
    if (sortKey === key) setSortDirection((current) => current === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDirection(key === "published" || key === "ingested" ? "desc" : "asc"); }
  };
  const clearFilters = () => { setClaimFilter(""); setActorFilter(""); setCountryFilter(""); setPublishedFilter("all"); setIngestedFilter("all"); };
  const filtered = Boolean(claimFilter || actorFilter || countryFilter || publishedFilter !== "all" || ingestedFilter !== "all");

  return <div><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><PageIntro eyebrow="All observations" title="Activity" description="Filter and sort every displayed claim field, with separate source publication and local ingestion timestamps." /><div className="flex items-center gap-3"><span className="font-mono text-xs text-zinc-500">{rows.length.toLocaleString()} of {claims.length.toLocaleString()}</span><button type="button" onClick={clearFilters} disabled={!filtered} className="button-secondary !min-h-10 px-3 text-xs">Clear filters</button></div></div>
    <section className="mt-7 rounded-2xl border border-zinc-200 bg-white p-4"><p className="mb-3 text-xs font-bold uppercase tracking-wide text-zinc-400">Column filters</p><div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[1.35fr_.75fr_.65fr_.7fr_.7fr]"><label className="flex min-h-12 items-center gap-3 rounded-xl border border-zinc-200 bg-white px-4 focus-within:border-teal-700 focus-within:ring-4 focus-within:ring-teal-700/10"><MagnifyingGlass size={17} className="text-zinc-400" /><span className="sr-only">Filter claim column</span><input value={claimFilter} onChange={(event) => setClaimFilter(event.target.value)} className="w-full bg-transparent text-sm outline-none" placeholder="Company, source, or domain" /></label><CustomSelect ariaLabel="Filter threat actor column" value={actorFilter} onChange={setActorFilter} options={[{ value: "", label: "All threat actors" }, ...actors.map((actor) => ({ value: actor, label: actor }))]} /><CustomSelect ariaLabel="Filter country column" value={countryFilter} onChange={setCountryFilter} options={[{ value: "", label: "All countries" }, ...countries.map((country) => ({ value: country, label: country }))]} /><CustomSelect ariaLabel="Filter published column" value={publishedFilter} onChange={(value) => setPublishedFilter(value as ActivityDateFilter)} options={publishedOptions} /><CustomSelect ariaLabel="Filter ingested column" value={ingestedFilter} onChange={(value) => setIngestedFilter(value as ActivityDateFilter)} options={dateOptions} /></div></section>
    <div className="mt-5 overflow-x-auto rounded-2xl border border-zinc-200 bg-white"><div className="hidden min-w-[900px] grid-cols-[1.35fr_.75fr_.65fr_.7fr_.7fr] gap-4 border-b border-zinc-200 bg-zinc-50 px-5 py-2 md:grid"><ActivitySortHeader label="Claim" column="claim" active={sortKey} direction={sortDirection} onSort={sort} /><ActivitySortHeader label="Threat actor" column="actor" active={sortKey} direction={sortDirection} onSort={sort} /><ActivitySortHeader label="Country" column="country" active={sortKey} direction={sortDirection} onSort={sort} /><ActivitySortHeader label="Published" column="published" active={sortKey} direction={sortDirection} onSort={sort} /><ActivitySortHeader label="Ingested" column="ingested" active={sortKey} direction={sortDirection} onSort={sort} /></div>{rows.map((claim, index) => <div key={claim.id} className={`grid min-w-[900px] gap-4 p-5 md:grid-cols-[1.35fr_.75fr_.65fr_.7fr_.7fr] md:items-center ${index ? "border-t border-zinc-200" : ""}`}><div><p className="font-semibold">{claim.title}</p><p className="mt-1 text-xs text-zinc-500">{sourceLabel(claim.source)} · {claim.domains[0] || "public allegation"}</p></div><p className="text-sm text-zinc-600">{claim.threat_actor}</p><p className="text-sm text-zinc-600">{claim.country || "Unknown country"}</p><div><p className="text-[10px] font-semibold uppercase text-zinc-400 md:hidden">Published</p><p className="font-mono text-xs text-zinc-500">{claim.published_at ? formatTime(claim.published_at) : "Not supplied"}</p></div><div><p className="text-[10px] font-semibold uppercase text-zinc-400 md:hidden">Ingested</p><p className="font-mono text-xs text-zinc-500">{formatTime(claim.received_at)}</p></div></div>)}{!rows.length && <div className="p-10 text-center text-sm text-zinc-500">No activity matches all column filters.</div>}</div></div>;
}

function ActivitySortHeader({ label, column, active, direction, onSort }: { label: string; column: ActivitySortKey; active: ActivitySortKey; direction: "asc" | "desc"; onSort: (column: ActivitySortKey) => void }) {
  const selected = active === column;
  return <button type="button" onClick={() => onSort(column)} aria-label={`Sort ${label} ${selected && direction === "asc" ? "descending" : "ascending"}`} className={`flex items-center justify-between gap-2 rounded-lg px-2 py-2 text-left text-xs font-semibold uppercase tracking-wide transition hover:bg-zinc-100 ${selected ? "text-teal-800" : "text-zinc-500"}`}><span>{label}</span><CaretDown size={14} className={`transition ${selected ? "opacity-100" : "opacity-30"} ${selected && direction === "asc" ? "rotate-180" : ""}`} /></button>;
}

function SourcesPage({ sources, onUpdated }: { sources: SourceHealth[]; onUpdated: () => Promise<void> }) {
  const [collecting, setCollecting] = useState(false);
  const [backfilling, setBackfilling] = useState(false);
  const [notice, setNotice] = useState("");
  const [sourceError, setSourceError] = useState("");
  const collect = async () => {
    setCollecting(true); setSourceError(""); setNotice("");
    try { await api.collect(); await onUpdated(); }
    catch (reason) { setSourceError(reason instanceof Error ? reason.message : "Source check failed"); }
    finally { setCollecting(false); }
  };
  const backfill = async () => {
    setBackfilling(true); setSourceError(""); setNotice("");
    try {
      const result = await api.backfill(2015);
      const incomplete = result.results.filter((item) => item.error || item.truncated_partitions?.length);
      setNotice(`Checked ${result.received.toLocaleString()} source records and stored ${result.created.toLocaleString()} new claims.${incomplete.length ? ` ${incomplete.length} source${incomplete.length === 1 ? " has" : "s have"} an upstream coverage limitation; see its status card.` : " All addressable partitions completed."}`);
      await onUpdated();
    } catch (reason) { setSourceError(reason instanceof Error ? reason.message : "Historical import failed"); }
    finally { setBackfilling(false); }
  };
  const busy = collecting || backfilling;
  return <div><div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><PageIntro eyebrow="Collection status" title="Sources" description="Check whether public data providers are reachable and returning current records." /><div className="flex flex-wrap gap-3"><button type="button" className="button-secondary" disabled={busy} onClick={() => void backfill()}><ClockCounterClockwise className={backfilling ? "animate-spin" : ""} size={18} />{backfilling ? "Synchronizing history…" : "Synchronize all available"}</button><button type="button" className="button-primary" disabled={busy} onClick={() => void collect()}><SpinnerGap className={collecting ? "animate-spin" : ""} size={18} />Test active sources</button></div></div>{notice && <InlineNotice tone="neutral">{notice}</InlineNotice>}{sourceError && <InlineNotice tone="danger">{sourceError}</InlineNotice>}<div className="mt-8 grid gap-5 lg:grid-cols-2">{sources.map((source) => <div key={source.source} className="rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><div className="flex items-start justify-between gap-4"><div className="flex items-center gap-3"><StatusPulse tone={source.status === "working" ? "healthy" : source.status === "unavailable" ? "danger" : "warning"} /><div><h2 className="text-xl font-semibold">{sourceLabel(source.source)}</h2><p className="mt-1 text-sm text-zinc-500">{source.message}</p></div></div><StatusBadge status={source.status} /></div><dl className="mt-8 grid grid-cols-2 gap-5 border-t border-zinc-100 pt-6"><Stat label="Last checked" value={formatTime(source.last_checked_at)} /><Stat label="Records stored" value={String(source.records_received)} mono /></dl></div>)}</div><InlineNotice tone="neutral">Full synchronization imports RansomLook history from 2015, exhausts RansomFeed's country/year partitions, and records ransomware.live's entire free recent-victims response. Coverage limits are shown on each source card. Direct-site addresses remain restricted to the separately configured Kali capture worker.</InlineNotice></div>;
}

function SettingsPage() {
  const [runtime, setRuntime] = useState<RuntimeSettings | null>(null);
  const [form, setForm] = useState<RuntimeSettingsUpdate | null>(null);
  const [providers, setProviders] = useState<AIProvider[]>([]);
  const [saving, setSaving] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [smtpPassword, setSMTPPassword] = useState("");
  const [savingCredential, setSavingCredential] = useState(false);
  const [savingSMTP, setSavingSMTP] = useState(false);
  const [sendingDigest, setSendingDigest] = useState(false);
  const [testingAI, setTestingAI] = useState(false);
  const [aiTestResult, setAITestResult] = useState<AIConnectionTest | null>(null);
  const [aiTestError, setAITestError] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.runtimeSettings(), api.aiProviders()])
      .then(([settings, providerData]) => {
        setRuntime(settings);
        setProviders(providerData);
        setForm(settings);
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Settings could not be loaded"));
  }, []);

  if (!runtime || !form) return <div><PageIntro eyebrow="Application" title="Settings" description="Loading operational controls…" /><div className="mt-8 h-72 animate-pulse rounded-[2rem] bg-zinc-200" /></div>;
  const selectedProvider = providers.find((provider) => provider.id === form.ai_provider);
  const chooseProvider = (providerId: string) => {
    const provider = providers.find((item) => item.id === providerId);
    setApiKey("");
    setAITestResult(null); setAITestError("");
    setForm({ ...form, ai_provider: providerId, ai_model: provider?.models[0] || "", ai_base_url: provider?.base_url || "" });
  };
  const replaceProvider = (updated: AIProvider) => {
    setProviders((current) => current.map((provider) => provider.id === updated.id ? updated : provider));
  };
  const saveCredential = async () => {
    if (!selectedProvider?.api_key_env || !apiKey.trim()) return;
    setSavingCredential(true); setError(""); setNotice("");
    try {
      const updated = await api.saveAIProviderCredential(selectedProvider.id, apiKey.trim());
      replaceProvider(updated); setApiKey("");
      setNotice(`${selectedProvider.name} API key saved locally. It is ready for connection tests and enrichment.`);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "API key could not be saved"); }
    finally { setSavingCredential(false); }
  };
  const clearCredential = async () => {
    if (!selectedProvider?.api_key_env) return;
    setSavingCredential(true); setError(""); setNotice("");
    try {
      const updated = await api.clearAIProviderCredential(selectedProvider.id);
      replaceProvider(updated); setApiKey("");
      setNotice(`${selectedProvider.name} locally saved API key was removed.`);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "API key could not be removed"); }
    finally { setSavingCredential(false); }
  };
  const save = async () => {
    setSaving(true); setError(""); setNotice("");
    try {
      const updated = await api.updateRuntimeSettings(form);
      setRuntime(updated); setForm(updated);
      setNotice("Monitoring settings saved. The scheduler will use them on its next check.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Settings could not be saved"); }
    finally { setSaving(false); }
  };
  const testAI = async () => {
    setTestingAI(true); setError(""); setNotice(""); setAITestError(""); setAITestResult(null);
    try {
      if (selectedProvider?.api_key_env && apiKey.trim()) {
        const updatedProvider = await api.saveAIProviderCredential(selectedProvider.id, apiKey.trim());
        replaceProvider(updatedProvider); setApiKey("");
      }
      const updatedSettings = await api.updateRuntimeSettings(form);
      setRuntime(updatedSettings); setForm(updatedSettings);
      const result = await api.testAIProvider();
      setAITestResult(result);
      setNotice(`${result.provider} responded successfully with ${result.model}.`);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "AI connection failed";
      setAITestError(message); setError(message);
    }
    finally { setTestingAI(false); }
  };
  const saveSMTPPassword = async () => {
    if (!smtpPassword) return;
    setSavingSMTP(true); setError(""); setNotice("");
    try {
      await api.saveSMTPPassword(smtpPassword);
      setSMTPPassword("");
      setRuntime({ ...runtime, smtp_password_configured: true });
      setNotice("SMTP password saved locally.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "SMTP password could not be saved"); }
    finally { setSavingSMTP(false); }
  };
  const clearSMTPPassword = async () => {
    setSavingSMTP(true); setError(""); setNotice("");
    try {
      await api.clearSMTPPassword();
      setRuntime({ ...runtime, smtp_password_configured: false });
      setSMTPPassword("");
      setNotice("Locally saved SMTP password removed.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "SMTP password could not be removed"); }
    finally { setSavingSMTP(false); }
  };
  const sendDigest = async () => {
    setSendingDigest(true); setError(""); setNotice("");
    try {
      if (smtpPassword) {
        await api.saveSMTPPassword(smtpPassword);
        setSMTPPassword("");
        setRuntime({ ...runtime, smtp_password_configured: true });
      }
      const updated = await api.updateRuntimeSettings(form);
      setRuntime(updated); setForm(updated);
      const result = await api.sendVictimDigest();
      setNotice(result.status === "sent" ? `Digest sent to ${result.recipients.join(", ")} with ${result.count.toLocaleString()} new victim claims (${result.summary_source?.replaceAll("_", " ")} summary).` : "There are no new victims in the current digest window, so no email was sent.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Victim digest could not be sent"); }
    finally { setSendingDigest(false); }
  };
  const modes: { id: OperatingMode; title: string; description: string }[] = [
    { id: "off", title: "Off", description: "Pause all scheduled collection. Manual source checks still work." },
    { id: "passive", title: "Passive", description: "Poll public feeds and match client profiles. No actor-site visits." },
    { id: "active", title: "Active", description: "Also queue allowlisted captures for the isolated Kali worker." }
  ];
  return <div><PageIntro eyebrow="Application" title="Monitoring settings" description="Choose how ExtortSignal collects signals, when it runs, and whether an AI model assists enrichment." />
    {notice && <InlineNotice tone="neutral">{notice}</InlineNotice>}{error && <InlineNotice tone="danger">{error}</InlineNotice>}
    <section className="mt-8 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><div className="flex items-start justify-between gap-4"><div><p className="eyebrow">Collection mode</p><h3 className="mt-2 text-xl font-semibold">Control the network boundary</h3></div><span className={`rounded-full px-3 py-1 text-xs font-bold uppercase ${form.operating_mode === "active" ? "bg-amber-100 text-amber-800" : form.operating_mode === "passive" ? "bg-teal-50 text-teal-800" : "bg-zinc-100 text-zinc-600"}`}>{form.operating_mode}</span></div>
      <div className="mt-6 grid gap-3 lg:grid-cols-3">{modes.map((mode) => <button key={mode.id} type="button" onClick={() => setForm({ ...form, operating_mode: mode.id })} className={`rounded-2xl border p-5 text-left transition ${form.operating_mode === mode.id ? "border-teal-700 bg-teal-50 ring-4 ring-teal-700/10" : "border-zinc-200 hover:border-zinc-400"}`}><span className="flex items-center justify-between font-semibold">{mode.title}{form.operating_mode === mode.id && <Check size={18} className="text-teal-800" />}</span><span className="mt-2 block text-xs leading-5 text-zinc-600">{mode.description}</span></button>)}</div>
      {form.operating_mode === "active" && <div className={`mt-5 rounded-2xl p-4 text-sm ${runtime.worker_configured ? "bg-teal-50 text-teal-900" : "bg-amber-50 text-amber-900"}`}><strong>{runtime.worker_configured ? "Worker credential configured." : "Kali worker not configured."}</strong> Active mode queues only targets you enabled on Direct sites. It never opens them from the host system.</div>}
    </section>

    <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><div className="flex items-center justify-between gap-4"><div><p className="eyebrow">Scheduler</p><h3 className="mt-2 text-xl font-semibold">Automatic checks</h3><p className="mt-2 text-sm text-zinc-500">Intervals are applied without restarting the platform.</p></div><button type="button" role="switch" aria-checked={form.scheduling_enabled} onClick={() => setForm({ ...form, scheduling_enabled: !form.scheduling_enabled })} className={`relative h-7 w-12 rounded-full transition ${form.scheduling_enabled ? "bg-teal-700" : "bg-zinc-300"}`}><span className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition ${form.scheduling_enabled ? "left-6" : "left-1"}`} /></button></div>
      <div className="mt-6 grid gap-5 md:grid-cols-3"><Field label="Public feeds" helper={`Last run: ${formatTime(runtime.last_public_run_at)}`}><CustomSelect ariaLabel="Public feed interval" value={String(form.public_interval_minutes)} onChange={(value) => setForm({ ...form, public_interval_minutes: Number(value) })} options={[{ value: "1", label: "Every minute" }, { value: "2", label: "Every 2 minutes" }, { value: "5", label: "Every 5 minutes" }, { value: "15", label: "Every 15 minutes" }, { value: "60", label: "Hourly" }]} /></Field><Field label="Site catalog" helper={`Last run: ${formatTime(runtime.last_catalog_run_at)}`}><CustomSelect ariaLabel="Site catalog interval" value={String(form.catalog_interval_hours)} onChange={(value) => setForm({ ...form, catalog_interval_hours: Number(value) })} options={[{ value: "1", label: "Hourly" }, { value: "3", label: "Every 3 hours" }, { value: "6", label: "Every 6 hours" }, { value: "12", label: "Every 12 hours" }, { value: "24", label: "Daily" }]} /></Field><Field label="Active captures" helper={`Last run: ${formatTime(runtime.last_active_run_at)}`}><CustomSelect ariaLabel="Active capture interval" value={String(form.active_interval_minutes)} onChange={(value) => setForm({ ...form, active_interval_minutes: Number(value) })} options={[{ value: "5", label: "Every 5 minutes" }, { value: "15", label: "Every 15 minutes" }, { value: "30", label: "Every 30 minutes" }, { value: "60", label: "Hourly" }, { value: "360", label: "Every 6 hours" }]} /></Field></div>
      {!runtime.scheduler_process_enabled && <InlineNotice tone="danger">The scheduler process is disabled by RANSOM_MONITOR_AUTO_COLLECT. Enable it and restart before schedules can run.</InlineNotice>}
    </section>

    <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><p className="eyebrow">Geographic priorities</p><h3 className="mt-2 text-xl font-semibold">Regions to focus</h3><p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-500">These global priorities are highlighted in Intelligence in addition to markets and cities configured on individual client profiles.</p><div className="mt-6"><FocusRegionEditor values={form.focus_regions} onChange={(focus_regions) => setForm({ ...form, focus_regions })} /></div></section>

    <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><div className="flex items-center justify-between gap-4"><div className="flex items-center gap-3"><span className="grid h-11 w-11 place-items-center rounded-xl bg-violet-50 text-violet-700"><Cpu size={23} /></span><div><p className="eyebrow">Optional enrichment</p><h3 className="mt-1 text-xl font-semibold">AI provider</h3></div></div><button type="button" role="switch" aria-checked={form.ai_enabled} onClick={() => setForm({ ...form, ai_enabled: !form.ai_enabled })} className={`relative h-7 w-12 rounded-full transition ${form.ai_enabled ? "bg-violet-700" : "bg-zinc-300"}`}><span className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition ${form.ai_enabled ? "left-6" : "left-1"}`} /></button></div>
      <p className="mt-4 max-w-3xl text-sm leading-6 text-zinc-600">AI is used only as an enrichment assistant; deterministic company/domain matching remains authoritative. For an 8–16 GB machine, start with Qwen3 4B. Use Qwen3 1.7B when memory is tight, or Qwen3 8B for better extraction on a larger system.</p>
      <div className="mt-6 grid gap-5 md:grid-cols-3"><Field label="Provider"><CustomSelect ariaLabel="AI provider" value={form.ai_provider} onChange={chooseProvider} options={providers.map((provider) => ({ value: provider.id, label: provider.name }))} /></Field><Field label="Model">{selectedProvider?.models.length ? <CustomSelect ariaLabel="AI model" value={form.ai_model} onChange={(value) => setForm({ ...form, ai_model: value })} options={selectedProvider.models.map((model) => ({ value: model, label: model }))} /> : <input className="input" value={form.ai_model} onChange={(event) => setForm({ ...form, ai_model: event.target.value })} placeholder="Provider model ID" />}</Field><Field label="OpenAI-compatible endpoint"><input className="input font-mono text-xs" value={form.ai_base_url} onChange={(event) => setForm({ ...form, ai_base_url: event.target.value })} /></Field></div>
      {selectedProvider?.api_key_env && <div className="mt-5 rounded-2xl border border-violet-100 bg-violet-50/50 p-4 sm:p-5"><div className="grid gap-3 lg:grid-cols-[1fr_auto]"><Field label="API key" helper={selectedProvider.credential_configured ? "A credential is configured. Enter a new key only to replace it." : `Required for ${selectedProvider.name}.`}><input type="password" autoComplete="off" spellCheck={false} value={apiKey} onChange={(event) => setApiKey(event.target.value)} className="input font-mono text-sm" placeholder={selectedProvider.credential_configured ? "Saved key ••••••••" : `Paste ${selectedProvider.api_key_env}`} aria-label={`${selectedProvider.name} API key`} /></Field><div className="flex items-end gap-2"><button type="button" disabled={savingCredential || apiKey.trim().length < 8} onClick={() => void saveCredential()} className="button-primary whitespace-nowrap">{savingCredential ? <SpinnerGap className="animate-spin" size={17} /> : <ShieldCheck size={17} />}Save API key</button>{selectedProvider.credential_source === "local_store" && <button type="button" disabled={savingCredential} onClick={() => void clearCredential()} className="button-secondary">Clear</button>}</div></div><p className="mt-3 text-xs leading-5 text-zinc-500">Stored only on this machine in a user-restricted file. The key is never sent back to the browser or included in exports. “Test connection” also saves a key currently entered above.</p></div>}
      {selectedProvider && <div className="mt-4 flex flex-col justify-between gap-3 rounded-2xl bg-zinc-50 p-4 sm:flex-row sm:items-center"><div><p className="text-sm font-semibold">{selectedProvider.region}</p><p className="mt-1 text-xs leading-5 text-zinc-500">{selectedProvider.note}</p></div><div className="flex items-center gap-2"><span className={`shrink-0 rounded-full px-3 py-1 text-xs font-semibold ${selectedProvider.credential_configured ? "bg-teal-50 text-teal-800" : "bg-amber-100 text-amber-800"}`}>{selectedProvider.api_key_env ? (selectedProvider.credential_source === "environment" ? "Key from environment" : selectedProvider.credential_configured ? "API key saved" : "API key required") : "No API key needed"}</span><button type="button" disabled={testingAI || savingCredential} onClick={() => void testAI()} className="button-secondary !min-h-9 px-3 text-xs">{testingAI ? <SpinnerGap className="animate-spin" size={15} /> : null}Test connection</button></div></div>}
      {aiTestResult && <div className="mt-3 rounded-2xl border border-teal-200 bg-teal-50 p-4 sm:p-5"><div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start"><div className="flex items-start gap-3"><span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-full bg-teal-700 text-white"><Check size={17} /></span><div><p className="text-sm font-semibold text-teal-950">Live connection verified</p><p className="mt-1 text-xs leading-5 text-teal-800">A random challenge was returned correctly by {aiTestResult.provider}; this was a real inference request.</p></div></div><span className="shrink-0 rounded-full bg-white px-3 py-1 font-mono text-xs font-semibold text-teal-800">{aiTestResult.latency_ms.toLocaleString()} ms</span></div><div className="mt-4 grid gap-2 sm:grid-cols-3">{aiTestResult.checks.map((check, index) => <div key={check.id} className="flex items-center gap-2 rounded-xl border border-teal-200 bg-white px-3 py-2.5"><span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-teal-700 text-[10px] font-bold text-white">{index + 1}</span><span className="min-w-0 truncate text-xs font-semibold text-teal-950">{check.label}</span><Check className="ml-auto shrink-0 text-teal-700" size={15} /></div>)}</div><dl className="mt-4 grid gap-3 border-t border-teal-200/70 pt-4 text-xs sm:grid-cols-2 lg:grid-cols-4"><div><dt className="text-teal-700">Endpoint</dt><dd className="mt-1 break-all font-mono font-semibold text-teal-950">{aiTestResult.endpoint_host}</dd></div><div><dt className="text-teal-700">Configured model</dt><dd className="mt-1 break-all font-mono font-semibold text-teal-950">{aiTestResult.model}</dd></div><div><dt className="text-teal-700">Responding model</dt><dd className="mt-1 break-all font-mono font-semibold text-teal-950">{aiTestResult.upstream_model}</dd></div><div><dt className="text-teal-700">Checked</dt><dd className="mt-1 font-semibold text-teal-950">{formatTime(aiTestResult.checked_at)}</dd></div></dl></div>}
      {aiTestError && <div className="mt-3"><InlineNotice tone="danger"><span><strong>Connection test failed.</strong> {aiTestError}</span></InlineNotice></div>}
    </section>
    <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8"><div className="flex items-start justify-between gap-4"><div className="flex items-center gap-3"><span className="grid h-11 w-11 place-items-center rounded-xl bg-teal-50 text-teal-800"><EnvelopeSimple size={23} /></span><div><p className="eyebrow">Outbound notification</p><h3 className="mt-1 text-xl font-semibold">New-victim email digest</h3></div></div><button type="button" role="switch" aria-checked={form.victim_digest_enabled} onClick={() => setForm({ ...form, victim_digest_enabled: !form.victim_digest_enabled })} className={`relative h-7 w-12 shrink-0 rounded-full transition ${form.victim_digest_enabled ? "bg-teal-700" : "bg-zinc-300"}`}><span className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition ${form.victim_digest_enabled ? "left-6" : "left-1"}`} /></button></div>
      <p className="mt-4 max-w-3xl text-sm leading-6 text-zinc-600">Send a count and short summary of claims received since the previous digest. When AI is enabled it summarizes only local aggregates; otherwise ExtortSignal uses a deterministic summary. The switch enables scheduled delivery—“Send digest now” remains manual.</p>
      <div className="mt-6"><EmailRecipientEditor values={form.victim_digest_recipients} onChange={(victim_digest_recipients) => setForm({ ...form, victim_digest_recipients })} /></div>
      <div className="mt-6 grid gap-5 md:grid-cols-2 xl:grid-cols-4"><Field label="SMTP host"><input className="input font-mono text-sm" value={form.smtp_host} onChange={(event) => setForm({ ...form, smtp_host: event.target.value })} placeholder="smtp.example.com" /></Field><Field label="Port"><input type="number" min={1} max={65535} className="input" value={form.smtp_port} onChange={(event) => setForm({ ...form, smtp_port: Number(event.target.value) })} /></Field><Field label="Security"><CustomSelect ariaLabel="SMTP security" value={form.smtp_security} onChange={(value) => setForm({ ...form, smtp_security: value as RuntimeSettingsUpdate["smtp_security"] })} options={[{ value: "starttls", label: "STARTTLS" }, { value: "ssl", label: "SSL/TLS" }]} /></Field><Field label="Digest interval"><CustomSelect ariaLabel="Digest interval" value={String(form.victim_digest_interval_hours)} onChange={(value) => setForm({ ...form, victim_digest_interval_hours: Number(value) })} options={[{ value: "1", label: "Hourly" }, { value: "6", label: "Every 6 hours" }, { value: "12", label: "Every 12 hours" }, { value: "24", label: "Daily" }, { value: "168", label: "Weekly" }]} /></Field></div>
      <div className="mt-5 grid gap-5 md:grid-cols-2"><Field label="SMTP username"><input className="input" value={form.smtp_username} onChange={(event) => setForm({ ...form, smtp_username: event.target.value })} placeholder="alerts@example.com" /></Field><Field label="From address"><input type="email" className="input" value={form.smtp_from} onChange={(event) => setForm({ ...form, smtp_from: event.target.value })} placeholder="alerts@example.com" /></Field></div>
      <div className="mt-5 rounded-2xl bg-zinc-50 p-4 sm:p-5"><div className="grid gap-3 lg:grid-cols-[1fr_auto]"><Field label="SMTP password or app password" helper={runtime.smtp_password_configured ? "A password is stored locally. Enter a value only to replace it." : "Use an app password when your mailbox provider supports it."}><input type="password" autoComplete="off" value={smtpPassword} onChange={(event) => setSMTPPassword(event.target.value)} className="input font-mono text-sm" placeholder={runtime.smtp_password_configured ? "Saved password ••••••••" : "Enter SMTP password"} /></Field><div className="flex flex-wrap items-end gap-2"><button type="button" disabled={savingSMTP || !smtpPassword} onClick={() => void saveSMTPPassword()} className="button-secondary">{savingSMTP ? <SpinnerGap className="animate-spin" size={17} /> : <ShieldCheck size={17} />}Save password</button>{runtime.smtp_password_configured && <button type="button" disabled={savingSMTP} onClick={() => void clearSMTPPassword()} className="button-secondary">Clear</button>}</div></div></div>
      <div className="mt-5 flex flex-col justify-between gap-3 rounded-2xl border border-teal-100 bg-teal-50/50 p-4 sm:flex-row sm:items-center"><div><p className="text-sm font-semibold text-teal-950">Last successful digest: {formatTime(runtime.last_victim_digest_at)}</p><p className="mt-1 text-xs text-teal-800">Email is sent only to the configured recipients and never includes API or SMTP credentials.</p></div><button type="button" disabled={sendingDigest || savingSMTP} onClick={() => void sendDigest()} className="button-primary shrink-0">{sendingDigest ? <SpinnerGap className="animate-spin" size={18} /> : <EnvelopeSimple size={18} />}{sendingDigest ? "Sending…" : "Send digest now"}</button></div>
    </section>
    <div className="mt-6 flex justify-end"><button type="button" className="button-primary" disabled={saving} onClick={() => void save()}>{saving ? <SpinnerGap className="animate-spin" size={18} /> : <ShieldCheck size={18} />}Save monitoring settings</button></div>
  </div>;
}

function EmailRecipientEditor({ values, onChange }: { values: string[]; onChange: (values: string[]) => void }) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const additions = draft.split(/[,;\s]+/).map((value) => value.trim().toLowerCase()).filter((value) => value.includes("@"));
    if (additions.length) onChange(Array.from(new Set([...values, ...additions])));
    setDraft("");
  };
  return <fieldset className="rounded-2xl border border-zinc-200 bg-zinc-50/70 p-4 sm:p-5"><legend className="px-1 text-sm font-semibold text-zinc-800">Digest recipients</legend><p className="text-xs leading-5 text-zinc-500">Add one or more internal monitoring addresses. Separate multiple addresses with commas.</p><div className="mt-3 flex gap-2"><input type="email" value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); add(); } }} className="input" placeholder="soc@example.com" /><button type="button" onClick={add} disabled={!draft.includes("@")} className="button-secondary shrink-0">Add</button></div><div className="mt-3 flex min-h-7 flex-wrap gap-2">{values.length ? values.map((value) => <span key={value} className="inline-flex items-center gap-1 rounded-full bg-teal-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-teal-900">{value}<button type="button" onClick={() => onChange(values.filter((item) => item !== value))} className="grid h-6 w-6 place-items-center rounded-full hover:bg-teal-100" aria-label={`Remove recipient ${value}`}><X size={13} /></button></span>) : <span className="text-xs text-zinc-400">No digest recipients configured</span>}</div></fieldset>;
}

function Onboarding({ onComplete }: { onComplete: () => Promise<void> }) {
  const [step, setStep] = useState(1);
  const [form, setForm] = useState<NewClient>(emptyClient);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const complete = async () => { setSaving(true); setError(""); try { await api.createClient(form); await onComplete(); } catch (reason) { setError(reason instanceof Error ? reason.message : "Setup could not be completed"); setSaving(false); } };
  const demo = async () => { setSaving(true); await api.seedDemo(); await onComplete(); };
  return <div className="min-h-[100dvh] bg-[#f5f7f6] p-4 sm:p-7"><div className="mx-auto grid min-h-[calc(100dvh-2rem)] max-w-[1400px] overflow-hidden rounded-[2.5rem] border border-zinc-200 bg-white shadow-[0_30px_75px_-45px_rgba(24,24,27,0.35)] lg:grid-cols-[.85fr_1.15fr]">
    <aside className="relative overflow-hidden bg-zinc-900 p-7 text-white sm:p-10 lg:p-14"><div className="flex items-center gap-3"><div className="grid h-11 w-11 place-items-center rounded-xl bg-white p-1.5"><img src="/extortsignal-mark.svg" alt="" className="h-full w-full" /></div><div><p className="font-semibold tracking-[-0.02em]">ExtortSignal</p><p className="text-xs text-zinc-400">Early signal. Clear action.</p></div></div><div className="mt-20 max-w-md"><p className="eyebrow !text-teal-300">Start safely</p><h1 className="mt-5 text-4xl font-semibold tracking-[-0.045em] sm:text-5xl">Know when a public claim names your client.</h1><p className="mt-6 text-base leading-7 text-zinc-400">Monitor free public feeds, preserve evidence locally, and explain every match in language your whole team can understand.</p></div><div className="mt-12 space-y-4">{["No direct threat-actor access", "No stolen-data downloads", "Claims remain allegations until verified"].map((item) => <div key={item} className="flex items-center gap-3 text-sm text-zinc-300"><CheckCircle size={20} className="text-teal-400" />{item}</div>)}</div></aside>
    <main className="flex items-center p-6 sm:p-10 lg:p-16"><div className="w-full max-w-2xl"><div className="flex items-center gap-2">{[1,2,3].map((number) => <div key={number} className={`h-1.5 flex-1 rounded-full ${number <= step ? "bg-teal-700" : "bg-zinc-200"}`} />)}</div>
      {step === 1 && <div className="mt-10"><p className="eyebrow">Step 1 of 3</p><h2 className="mt-3 text-3xl font-semibold tracking-tight">Set up your first client</h2><p className="mt-3 max-w-xl text-zinc-600">You only need a company name and verified web domain. The system uses these for high-confidence matching.</p><button type="button" className="button-primary mt-8" onClick={() => setStep(2)}>Continue <ArrowRight size={18} /></button><button type="button" className="mt-8 block text-sm font-semibold text-zinc-500 underline-offset-4 hover:underline" disabled={saving} onClick={() => void demo()}>Explore with synthetic sample data</button></div>}
      {step === 2 && <div className="mt-10"><p className="eyebrow">Step 2 of 3</p><h2 className="mt-3 text-3xl font-semibold tracking-tight">Client identity</h2><ClientForm form={form} setForm={setForm} onSubmit={(event) => { event.preventDefault(); setStep(3); }} saving={false} error={error} submitLabel="Review setup" /></div>}
      {step === 3 && <div className="mt-10"><p className="eyebrow">Step 3 of 3</p><h2 className="mt-3 text-3xl font-semibold tracking-tight">Ready to monitor</h2><div className="mt-7 divide-y divide-zinc-100 rounded-2xl border border-zinc-200"><ReviewLine label="Company" value={form.canonical_name} /><ReviewLine label="Verified domain" value={form.primary_domain} mono /><ReviewLine label="Markets" value={[...form.countries, ...form.cities].join(", ") || "Not set"} /><ReviewLine label="Industries" value={form.industries.join(", ") || "Not set"} /><ReviewLine label="Related organizations" value={String(form.related_entities.length)} /><ReviewLine label="Alert keywords" value={String(form.keywords.length)} /><ReviewLine label="Priority" value={form.priority} /></div>{error && <InlineNotice tone="danger">{error}</InlineNotice>}<div className="mt-7 flex gap-3"><button type="button" className="button-secondary" onClick={() => setStep(2)}>Back</button><button type="button" disabled={saving} className="button-primary" onClick={() => void complete()}>{saving ? <SpinnerGap className="animate-spin" size={18} /> : <ShieldCheck size={18} />}Start monitoring</button></div></div>}
    </div></main>
  </div></div>;
}

function ClientForm({ form, setForm, onSubmit, saving, error, submitLabel = "Add client" }: { form: NewClient; setForm: (value: NewClient) => void; onSubmit: (event: FormEvent) => void; saving: boolean; error: string; submitLabel?: string }) {
  return <form onSubmit={onSubmit} className="mt-7 space-y-6"><Field label="Company name" helper="Use the legal or most commonly recognized name."><input required minLength={2} value={form.canonical_name} onChange={(event) => setForm({ ...form, canonical_name: event.target.value })} className="input" placeholder="Meridian Harbour Group" /></Field><Field label="Primary web domain" helper="Do not include a path. Example: company.hk"><input required value={form.primary_domain} onChange={(event) => setForm({ ...form, primary_domain: event.target.value })} className="input font-mono" placeholder="company.hk" /></Field><Field label="Company description" helper="Briefly describe what the company does, its products, brands, and customers. This gives reviewers useful context."><textarea value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} className="input min-h-28 resize-y" maxLength={2000} placeholder="Regional logistics provider serving ports and cold-chain operators across Asia…" /></Field><div className="grid gap-6 sm:grid-cols-2"><MultiSelectField label="Markets and geographies" helper="Add every country or region where this organization operates." placeholder="Add a country or region" options={COUNTRY_OPTIONS.map((country) => country.name)} values={form.countries} onChange={(countries) => setForm({ ...form, countries })} /><MultiSelectField label="Industries" helper="Select all sectors relevant to this organization." placeholder="Add an industry" options={INDUSTRY_OPTIONS} values={form.industries} onChange={(industries) => setForm({ ...form, industries })} /></div><CityEditor values={form.cities} onChange={(cities) => setForm({ ...form, cities })} /><KeywordEditor values={form.keywords} onChange={(keywords) => setForm({ ...form, keywords })} /><RelatedEntitiesEditor values={form.related_entities} onChange={(related_entities) => setForm({ ...form, related_entities })} /><Field label="Monitoring priority"><CustomSelect ariaLabel="Monitoring priority" value={form.priority} onChange={(value) => setForm({ ...form, priority: value as NewClient["priority"] })} options={[{ value: "standard", label: "Standard" }, { value: "high", label: "High" }, { value: "critical", label: "Critical" }]} /></Field>{error && <p className="text-sm font-medium text-rose-700">{error}</p>}<button type="submit" disabled={saving} className="button-primary">{saving ? <SpinnerGap className="animate-spin" size={18} /> : <Plus size={18} />}{submitLabel}</button></form>;
}

function FocusRegionEditor({ values, onChange }: { values: string[]; onChange: (values: string[]) => void }) {
  const [draft, setDraft] = useState("");
  const available = COUNTRY_OPTIONS.map((country) => country.name).filter((name) => !values.includes(name));
  const add = (value: string) => {
    const cleaned = value.trim();
    if (cleaned.length < 2 || values.includes(cleaned)) return;
    onChange([...values, cleaned].slice(0, 50));
    setDraft("");
  };
  return <div><div className="grid gap-3 md:grid-cols-2"><SearchSelect ariaLabel="Focus country or region" placeholder="Choose a country or region" options={available} onSelect={add} /><div className="flex gap-2"><input value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); add(draft); } }} className="input" placeholder="Or add a city / custom region" maxLength={120} /><button type="button" onClick={() => add(draft)} disabled={draft.trim().length < 2} className="button-secondary shrink-0">Add</button></div></div><div className="mt-4 flex min-h-8 flex-wrap gap-2">{values.length ? values.map((value) => <span key={value} className="inline-flex items-center gap-1 rounded-full bg-sky-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-sky-900">{value}<button type="button" onClick={() => onChange(values.filter((item) => item !== value))} className="grid h-6 w-6 place-items-center rounded-full hover:bg-sky-100" aria-label={`Remove focus region ${value}`}><X size={13} /></button></span>) : <span className="text-xs text-zinc-400">No global focus regions configured</span>}</div></div>;
}

function CityEditor({ values, onChange }: { values: string[]; onChange: (values: string[]) => void }) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const additions = draft.split(",").map((value) => value.trim()).filter((value) => value.length >= 2);
    if (!additions.length) return;
    onChange(Array.from(new Set([...values, ...additions])).slice(0, 50)); setDraft("");
  };
  return <fieldset className="rounded-2xl border border-zinc-200 bg-zinc-50/70 p-4 sm:p-5"><legend className="px-1 text-sm font-semibold text-zinc-800">Cities to highlight</legend><p className="text-xs leading-5 text-zinc-500">Add headquarters and operational cities. Intelligence will highlight them when a source supplies matching geography.</p><div className="mt-3 flex gap-2"><input value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); add(); } }} className="input" placeholder="Hong Kong, Singapore, London" /><button type="button" onClick={add} disabled={!draft.trim()} className="button-secondary shrink-0 px-4">Add</button></div><div className="mt-3 flex min-h-7 flex-wrap gap-2">{values.length ? values.map((value) => <span key={value} className="inline-flex items-center gap-1 rounded-full bg-sky-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-sky-900">{value}<button type="button" onClick={() => onChange(values.filter((item) => item !== value))} className="grid h-6 w-6 place-items-center rounded-full hover:bg-sky-100" aria-label={`Remove city ${value}`}><X size={13} /></button></span>) : <span className="text-xs text-zinc-400">No cities configured</span>}</div></fieldset>;
}

function MultiSelectField({ label, helper, placeholder, options, values, onChange }: { label: string; helper: string; placeholder: string; options: readonly string[]; values: string[]; onChange: (values: string[]) => void }) {
  const available = options.filter((option) => !values.includes(option));
  return <div><span className="text-sm font-semibold text-zinc-800">{label}</span><span className="mt-1 block text-xs text-zinc-500">{helper}</span><div className="mt-2"><SearchSelect ariaLabel={label} placeholder={placeholder} options={available} onSelect={(value) => onChange([...values, value])} /></div><div className="mt-3 flex min-h-7 flex-wrap gap-2">{values.length ? values.map((value) => <span key={value} className="inline-flex items-center gap-1 rounded-full bg-teal-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-teal-900">{value}<button type="button" onClick={() => onChange(values.filter((item) => item !== value))} className="grid h-6 w-6 place-items-center rounded-full hover:bg-teal-100" aria-label={`Remove ${value}`}><X size={13} /></button></span>) : <span className="text-xs text-zinc-400">None selected</span>}</div></div>;
}

function SearchSelect({ ariaLabel, placeholder, options, onSelect }: { ariaLabel: string; placeholder: string; options: readonly string[]; onSelect: (value: string) => void }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const root = useRef<HTMLDivElement>(null);
  const filtered = options.filter((option) => option.toLowerCase().includes(query.trim().toLowerCase()));
  useEffect(() => {
    const close = (event: MouseEvent) => { if (!root.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  return <div ref={root} className="relative"><button type="button" aria-label={ariaLabel} aria-haspopup="listbox" aria-expanded={open} onClick={() => setOpen(!open)} className={`input flex items-center justify-between gap-3 text-left ${open ? "border-teal-700 ring-4 ring-teal-700/10" : ""}`}><span className="text-zinc-500">{placeholder}</span><CaretDown size={17} className={`shrink-0 text-zinc-400 transition ${open ? "rotate-180" : ""}`} /></button>{open && <div className="absolute z-50 mt-2 w-full overflow-hidden rounded-2xl border border-zinc-200 bg-white p-2 shadow-[0_20px_50px_-20px_rgba(24,24,27,.35)]"><label className="flex items-center gap-2 rounded-xl bg-zinc-50 px-3"><MagnifyingGlass size={16} className="text-zinc-400" /><span className="sr-only">Search {ariaLabel}</span><input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Escape") setOpen(false); }} className="min-h-10 w-full bg-transparent text-sm outline-none" placeholder={`Search ${ariaLabel.toLowerCase()}`} /></label><div role="listbox" aria-label={ariaLabel} className="mt-1 max-h-56 overflow-y-auto p-1">{filtered.length ? filtered.map((option) => <button type="button" role="option" aria-selected="false" key={option} onClick={() => { onSelect(option); setQuery(""); setOpen(false); }} className="block w-full rounded-xl px-3 py-2.5 text-left text-sm text-zinc-700 transition hover:bg-teal-50 hover:text-teal-900">{option}</button>) : <p className="px-3 py-5 text-center text-xs text-zinc-400">No matching options</p>}</div></div>}</div>;
}

function KeywordEditor({ values, onChange }: { values: string[]; onChange: (values: string[]) => void }) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const additions = draft.split(",").map((value) => value.trim()).filter((value) => value.length >= 3);
    if (!additions.length) return;
    onChange(Array.from(new Set([...values, ...additions])).slice(0, 30));
    setDraft("");
  };
  return <fieldset className="rounded-2xl border border-zinc-200 bg-zinc-50/70 p-4 sm:p-5"><legend className="px-1 text-sm font-semibold text-zinc-800">Alert keywords</legend><p className="text-xs leading-5 text-zinc-500">Add distinctive product names, brands, locations, or business-unit phrases. Keyword-only hits are sent to human review.</p><div className="mt-3 flex gap-2"><input value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); add(); } }} className="input" placeholder="Product name or distinctive phrase" maxLength={240} /><button type="button" onClick={add} disabled={!draft.trim()} className="button-secondary shrink-0 px-4">Add</button></div><div className="mt-3 flex min-h-7 flex-wrap gap-2">{values.length ? values.map((value) => <span key={value} className="inline-flex items-center gap-1 rounded-full bg-amber-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-amber-900">{value}<button type="button" onClick={() => onChange(values.filter((item) => item !== value))} className="grid h-6 w-6 place-items-center rounded-full hover:bg-amber-100" aria-label={`Remove keyword ${value}`}><X size={13} /></button></span>) : <span className="text-xs text-zinc-400">No keyword alerts configured</span>}</div></fieldset>;
}

function RelatedEntitiesEditor({ values, onChange }: { values: RelatedEntity[]; onChange: (values: RelatedEntity[]) => void }) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [relationship, setRelationship] = useState<RelatedEntity["relationship"]>("subsidiary");
  const add = () => {
    const cleanName = name.trim();
    if (!cleanName) return;
    onChange([...values, { name: cleanName, domain: domain.trim(), relationship }]);
    setName(""); setDomain("");
  };
  return <fieldset className="rounded-2xl border border-zinc-200 bg-zinc-50/70 p-4 sm:p-5"><legend className="px-1 text-sm font-semibold text-zinc-800">Related organizations</legend><p className="text-xs leading-5 text-zinc-500">Add subsidiaries and important third parties. Their names and domains will participate in matching.</p><div className="mt-4 grid gap-3 sm:grid-cols-[.8fr_1.2fr_1fr_auto]"><CustomSelect ariaLabel="Relationship type" value={relationship} onChange={(value) => setRelationship(value as RelatedEntity["relationship"])} options={[{ value: "subsidiary", label: "Subsidiary" }, { value: "third_party", label: "Third party" }]} /><input value={name} onChange={(event) => setName(event.target.value)} className="input" placeholder="Organization name" aria-label="Related organization name" /><input value={domain} onChange={(event) => setDomain(event.target.value)} className="input font-mono" placeholder="domain.com (optional)" aria-label="Related organization domain" /><button type="button" onClick={add} disabled={!name.trim()} className="button-secondary px-3" aria-label="Add related organization"><Plus size={18} /></button></div>{values.length > 0 && <div className="mt-4 divide-y divide-zinc-200 border-y border-zinc-200">{values.map((entity, index) => <div key={`${entity.relationship}-${entity.name}-${index}`} className="flex items-center justify-between gap-4 py-3"><div><p className="text-sm font-semibold text-zinc-800">{entity.name}</p><p className="mt-1 text-xs text-zinc-500"><span className="capitalize">{entity.relationship.replace("_", " ")}</span>{entity.domain ? ` · ${entity.domain}` : ""}</p></div><button type="button" onClick={() => onChange(values.filter((_, itemIndex) => itemIndex !== index))} className="icon-button !h-9 !w-9" aria-label={`Remove ${entity.name}`}><X size={16} /></button></div>)}</div>}</fieldset>;
}

function summarizeValues(values: string[], empty: string) {
  if (!values.length) return empty;
  return values.length > 2 ? `${values.slice(0, 2).join(", ")} +${values.length - 2}` : values.join(", ");
}

function AlertRow({ alert, divided }: { alert: Alert; divided?: boolean }) { return <div className={`group grid gap-4 p-5 transition hover:bg-zinc-50 sm:grid-cols-[auto_1fr] sm:items-center lg:grid-cols-[auto_minmax(0,1.2fr)_minmax(0,1fr)_auto] ${divided ? "border-t border-zinc-200" : ""}`}><SeverityMark severity={alert.severity} /><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><p className="break-words font-semibold text-zinc-900">{alert.claim_title}</p><AlertStatusBadge status={alert.status} /></div><p className="mt-1 break-words text-xs text-zinc-500">Claim by {alert.threat_actor}</p></div><div className="min-w-0 sm:col-start-2 lg:col-start-auto"><p className="break-words text-sm font-medium text-zinc-700">{alert.client_name}</p><p className="mt-1 break-words text-xs text-zinc-500">{alert.reason}</p></div><div className="flex items-center gap-3 sm:col-start-2 lg:col-start-auto lg:justify-end"><span className="whitespace-nowrap font-mono text-xs text-zinc-500">{formatTime(alert.updated_at || alert.created_at)}</span><ArrowRight size={17} className="shrink-0 text-zinc-400 transition group-hover:translate-x-1" /></div></div>; }
function ClaimRow({ claim }: { claim: Claim }) { return <div className="py-4"><div className="flex items-start justify-between gap-4"><div><p className="text-sm font-semibold">{claim.title}</p><p className="mt-1 text-xs text-zinc-500">{claim.threat_actor} · {claim.source}</p></div><span className="font-mono text-[11px] text-zinc-400">{formatTime(claim.received_at)}</span></div></div>; }
function Metric({ label, value }: { label: string; value: number }) { return <div className="px-4 py-3 md:px-7"><p className="font-mono text-3xl font-semibold tracking-tight md:text-4xl">{value}</p><p className="mt-1 text-xs font-medium text-zinc-500 md:text-sm">{label}</p></div>; }
function SectionHeading({ title, description, action, onAction }: { title: string; description: string; action: string; onAction: () => void }) { return <div className="flex items-end justify-between gap-5"><div><h2 className="text-xl font-semibold tracking-tight">{title}</h2><p className="mt-1 max-w-xl text-sm text-zinc-500">{description}</p></div><button type="button" onClick={onAction} className="hidden text-sm font-semibold text-teal-800 sm:block">{action}</button></div>; }
function PageIntro({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) { return <div><p className="eyebrow">{eyebrow}</p><h2 className="mt-2 text-3xl font-semibold tracking-[-0.035em] md:text-4xl">{title}</h2><p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-600 md:text-base">{description}</p></div>; }
function EmptyState({ title, description, icon }: { title: string; description: string; icon: ReactNode }) { return <div className="mt-6 rounded-[2rem] border border-dashed border-zinc-300 bg-white/50 p-10 text-center"><div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-zinc-100 text-zinc-600">{icon}</div><h3 className="mt-5 font-semibold">{title}</h3><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-zinc-500">{description}</p></div>; }
function InlineNotice({ tone, children }: { tone: "danger" | "neutral"; children: ReactNode }) { return <div className={`mx-auto mt-5 flex max-w-[1400px] items-start gap-3 rounded-xl border px-4 py-3 text-sm ${tone === "danger" ? "border-rose-200 bg-rose-50 text-rose-800" : "border-zinc-200 bg-zinc-100 text-zinc-700"}`}>{tone === "danger" ? <Warning className="mt-0.5 shrink-0" size={18} /> : <Info className="mt-0.5 shrink-0" size={18} />}{children}</div>; }
function Field({ label, helper, children }: { label: string; helper?: string; children: ReactNode }) { return <label className="block"><span className="text-sm font-semibold text-zinc-800">{label}</span>{helper && <span className="mt-1 block text-xs text-zinc-500">{helper}</span>}<span className="mt-2 block">{children}</span></label>; }
function Modal({ title, description, onClose, children }: { title: string; description: string; onClose: () => void; children: ReactNode }) { return <motion.div className="fixed inset-0 z-30 grid place-items-center overflow-y-auto bg-zinc-950/30 p-4 backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}><motion.div className="my-8 w-full max-w-2xl rounded-[2rem] bg-white p-6 shadow-2xl sm:p-9" initial={{ opacity: 0, y: 24, scale: .98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 15, scale: .98 }} transition={{ type: "spring", stiffness: 170, damping: 24 }} onClick={(event) => event.stopPropagation()}><div className="flex items-start justify-between gap-4"><div><h2 className="text-2xl font-semibold tracking-tight">{title}</h2><p className="mt-2 max-w-lg text-sm leading-6 text-zinc-500">{description}</p></div><button type="button" className="icon-button" onClick={onClose} aria-label="Close"><X size={20} /></button></div>{children}</motion.div></motion.div>; }
function SeverityMark({ severity }: { severity: Alert["severity"] }) { return <span className={`grid h-10 w-10 place-items-center rounded-xl ${severity === "critical" ? "bg-rose-100 text-rose-700" : severity === "high" ? "bg-amber-100 text-amber-700" : "bg-zinc-100 text-zinc-600"}`}>{severity === "critical" ? <Warning size={20} weight="fill" /> : <ListMagnifyingGlass size={20} />}</span>; }
function SeverityBadge({ severity }: { severity: Alert["severity"] }) { return <span className={`inline-flex rounded-full px-3 py-1 text-xs font-bold uppercase tracking-wide ${severity === "critical" ? "bg-rose-100 text-rose-800" : severity === "high" ? "bg-amber-100 text-amber-800" : "bg-zinc-200 text-zinc-700"}`}>{severity}</span>; }
function PriorityBadge({ priority }: { priority: Client["priority"] }) { return <span className="w-fit rounded-full bg-zinc-100 px-3 py-1 text-xs font-semibold capitalize text-zinc-700">{priority}</span>; }
function StatusBadge({ status }: { status: SourceHealth["status"] }) { return <span className={`shrink-0 rounded-full px-3 py-1 text-xs font-semibold capitalize ${status === "working" ? "bg-teal-50 text-teal-800" : status === "unavailable" ? "bg-rose-50 text-rose-800" : "bg-amber-50 text-amber-800"}`}>{status.replaceAll("_", " ")}</span>; }
function alertStatusLabel(status: AlertStatus) { return ({ new: "New", investigating: "Investigating", client_notified: "Client notified", monitoring: "Monitoring", resolved: "Resolved", dismissed: "Dismissed" } as Record<AlertStatus, string>)[status]; }
function AlertStatusBadge({ status }: { status: AlertStatus }) { const tone = status === "new" ? "bg-rose-50 text-rose-800" : status === "investigating" ? "bg-amber-50 text-amber-800" : status === "client_notified" ? "bg-violet-50 text-violet-800" : status === "monitoring" ? "bg-sky-50 text-sky-800" : status === "resolved" ? "bg-teal-50 text-teal-800" : "bg-zinc-100 text-zinc-600"; return <span className={`inline-flex w-fit max-w-full shrink-0 items-center justify-center rounded-full px-2.5 py-1 text-center text-[10px] font-bold uppercase leading-4 tracking-wide ${tone}`}>{alertStatusLabel(status)}</span>; }
function DetailBlock({ label, value, mono }: { label: string; value: string; mono?: boolean }) { return <div className="rounded-2xl border border-zinc-200 bg-white p-4"><p className="text-xs font-semibold uppercase tracking-wide text-zinc-400">{label}</p><p className={`mt-2 text-sm font-medium text-zinc-800 ${mono ? "font-mono" : ""}`}>{value}</p></div>; }
function StepNumber({ value }: { value: string }) { return <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-zinc-900 font-mono text-xs font-bold text-white">{value}</span>; }
function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }) { return <div><dt className="text-xs font-semibold uppercase tracking-wide text-zinc-400">{label}</dt><dd className={`mt-2 text-sm font-medium text-zinc-800 ${mono ? "font-mono" : ""}`}>{value}</dd></div>; }
function SettingRow({ title, description, value }: { title: string; description: string; value: string }) { return <div className="grid gap-3 py-6 sm:grid-cols-[1.3fr_1fr_auto] sm:items-center"><div><p className="font-semibold">{title}</p><p className="mt-1 text-sm text-zinc-500">{description}</p></div><span /><span className="w-fit rounded-full bg-zinc-100 px-3 py-1 text-xs font-semibold text-zinc-700">{value}</span></div>; }
function ReviewLine({ label, value, mono }: { label: string; value: string; mono?: boolean }) { return <div className="flex items-center justify-between gap-4 px-5 py-4"><span className="text-sm text-zinc-500">{label}</span><span className={`text-right text-sm font-semibold capitalize ${mono ? "font-mono" : ""}`}>{value}</span></div>; }
function AppSkeleton() { return <div className="min-h-[100dvh] bg-[#f5f7f6] p-5 md:pl-[17rem] md:pt-8"><div className="mx-auto max-w-[1400px] animate-pulse"><div className="h-8 w-44 rounded-lg bg-zinc-200" /><div className="mt-8 grid gap-5 lg:grid-cols-[1.65fr_1fr]"><div className="h-[25rem] rounded-[2rem] bg-zinc-200" /><div className="h-[25rem] rounded-[2rem] bg-zinc-200" /></div><div className="mt-9 h-48 rounded-[2rem] bg-zinc-200" /></div></div>; }
function ConnectionError({ message, retry }: { message: string; retry: () => Promise<void> }) { return <div className="grid min-h-[100dvh] place-items-center bg-[#f5f7f6] p-5"><div className="max-w-lg rounded-[2rem] border border-zinc-200 bg-white p-9 text-center shadow-sm"><div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-rose-50 text-rose-700"><XCircle size={30} /></div><h1 className="mt-5 text-2xl font-semibold tracking-tight">Local service unavailable</h1><p className="mt-3 text-sm leading-6 text-zinc-500">{message}. Start the backend service, then try again.</p><button type="button" className="button-primary mt-6" onClick={() => void retry()}><SpinnerGap size={18} />Try again</button></div></div>; }

export default App;
