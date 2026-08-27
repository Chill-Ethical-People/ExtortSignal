import {
  ArrowRight,
  ArrowsInSimple,
  ArrowsOutSimple,
  Bell,
  Buildings,
  CalendarBlank,
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
  DotsSixVertical,
  EnvelopeSimple,
  FingerprintSimple,
  GlobeHemisphereWest,
  House,
  Info,
  ListMagnifyingGlass,
  MagnifyingGlass,
  MagnifyingGlassMinus,
  MagnifyingGlassPlus,
  Plus,
  ShieldCheck,
  SlidersHorizontal,
  SpinnerGap,
  Trash,
  Warning,
  X,
  XCircle,
} from "@phosphor-icons/react";
import { useGSAP } from "@gsap/react";
import {
  AnimatePresence,
  motion,
  useDragControls,
  useReducedMotion,
} from "framer-motion";
import gsap from "gsap";
import {
  FormEvent,
  ReactNode,
  RefObject,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { api } from "./api";
import { exportSvgAsPng } from "./chartExport";
import { StatusPulse } from "./components/StatusPulse";
import { ThreatWorldMap } from "./components/ThreatWorldMap";
import { GEOGRAPHY_OPTIONS, INDUSTRY_OPTIONS } from "./taxonomies";
import type {
  ActivityResponse,
  AIConnectionTest,
  AIJob,
  AIJobHistoryResponse,
  AIJobType,
  AIProvider,
  Alert,
  AlertAIAssessment,
  AlertIntelligenceContext,
  AlertStatus,
  CaptureJob,
  Claim,
  ClaimSourceEvidence,
  Client,
  DashboardSummary,
  DirectSitesOverview,
  DlsTarget,
  IntelligenceAIAnalysis,
  IntelligenceAnalysisScope,
  IntelligenceResponse,
  NewClient,
  NotificationDraft,
  OperatingMode,
  RelatedEntity,
  RuntimeSettings,
  RuntimeSettingsUpdate,
  SourceHealth,
  ThreatActorProfile,
  ThreatActorProfileIndexItem,
  ThreatActorProfessionalProfile,
} from "./types";

gsap.registerPlugin(useGSAP);

type Page =
  | "home"
  | "intelligence"
  | "profiles"
  | "alerts"
  | "clients"
  | "activity"
  | "direct"
  | "sources"
  | "tasks"
  | "settings";

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
  keywords: [],
};

const navItems: { page: Page; label: string; icon: typeof House }[] = [
  { page: "home", label: "Home", icon: House },
  { page: "intelligence", label: "Intelligence", icon: ChartLineUp },
  { page: "profiles", label: "Threat actors", icon: FingerprintSimple },
  { page: "alerts", label: "Alerts", icon: Bell },
  { page: "clients", label: "Clients", icon: Buildings },
  { page: "activity", label: "Activity", icon: ClockCounterClockwise },
  { page: "direct", label: "Direct sites", icon: Camera },
  { page: "sources", label: "Sources", icon: Database },
  { page: "tasks", label: "AI tasks", icon: Cpu },
  { page: "settings", label: "Settings", icon: SlidersHorizontal },
];

const AI_JOB_TYPE_LABELS: Record<AIJobType, string> = {
  intelligence_analysis: "Landscape analysis",
  actor_analysis: "Threat-actor analysis",
  actor_profile_refresh: "Actor profile update",
  victim_enrichment: "Victim enrichment",
  bulk_victim_enrichment: "Bulk victim enrichment",
  alert_assessment: "Alert assessment",
  bulk_alert_assessment: "Bulk alert assessment",
  alert_notification_draft: "Client notification draft",
  claim_awareness_draft: "Awareness email draft",
  provider_test: "AI provider test",
  victim_digest: "Victim digest",
};

function aiJobTypeLabel(type: AIJobType) {
  return AI_JOB_TYPE_LABELS[type] || type.replaceAll("_", " ");
}

function resolveProfessionalProfile(
  profile: ThreatActorProfile | null | undefined,
): ThreatActorProfessionalProfile | null {
  if (!profile) return null;
  if (profile.professional_profile) return profile.professional_profile;
  const refreshed = profile.ai_profile_refresh;
  const cti = profile.cti_profile;
  return {
    profile_schema: "ExtortSignal CTI Profile 1.0",
    profile_status: cti
      ? "sourced_profile"
      : profile.catalog_profile
        ? "catalogue_context_only"
        : "label_only",
    actor_class: cti
      ? "documented_activity_cluster"
      : profile.catalog_profile
        ? "catalogued_extortion_label"
        : "unresolved_actor_label",
    distribution: "TLP:CLEAR",
    summary:
      refreshed?.summary || profile.baseline_profile.summary || profile.summary,
    motivation: refreshed?.motivation || "",
    targeting: refreshed?.targeting || "",
    capabilities: refreshed?.capabilities || "",
    campaign_history: refreshed?.campaign_history || "",
    source_kind: refreshed
      ? "ai_refreshed"
      : cti
        ? "mitre_attack"
        : profile.catalog_profile
          ? "ransomware_live_catalog"
          : "actor_registry",
    sources: refreshed?.sources?.length
      ? refreshed.sources
      : [profile.baseline_profile.source],
    source_references: [],
    source_confidence: profile.baseline_profile.confidence,
    analytic_confidence: refreshed?.confidence ?? null,
    generated_at: refreshed?.generated_at ?? null,
    reviewed_at: profile.baseline_profile.reviewed_at ?? null,
    caveats: refreshed?.caveats ?? [],
    identity: {
      attack_id: cti?.attack_id || "",
      canonical_name: cti?.canonical_name || profile.actor,
      aliases: cti?.aliases || [],
      resolution_basis: cti
        ? cti.match_basis === "canonical_name"
          ? "MITRE ATT&CK canonical-name match"
          : "MITRE ATT&CK documented associated-name match; exact overlap is not assumed"
        : "Exact retained actor label",
      related_but_distinct: [],
    },
    technique_count: cti?.techniques.length || 0,
    software_count: cti?.software.length || 0,
    campaign_count: cti?.campaigns.length || 0,
    field_evidence: refreshed?.field_evidence ?? {},
    osint_evidence_count:
      refreshed?.osint_evidence_count ?? profile.osint_evidence?.length ?? 0,
    independent_source_count: refreshed?.independent_source_count ?? 0,
    osint_researched_at: refreshed?.osint_researched_at ?? null,
    ai_overlay_status: refreshed ? "applied" : "not_requested",
    top_techniques:
      cti?.techniques.slice(0, 10).map((item) => ({
        id: item.id,
        name: item.name,
        tactics: item.tactics,
        url: item.url,
      })) || [],
    priority_actions: [
      "Review cited actor reporting before translating narrative material into detections.",
      "Corroborate public claims with internal telemetry before escalation.",
    ],
    hunt_hypotheses: [
      "No analyst-reviewed hunt hypothesis has been retained for this fallback profile.",
    ],
    detection_coverage: {
      status: "not_assessed",
      documented_technique_count: cti?.techniques.length || 0,
      message:
        "No organization-specific detection matrix is imported into ExtortSignal.",
    },
    key_judgments: [
      "Local victim-list observations remain separate from sourced actor behavior.",
    ],
  };
}

function formatTime(value?: string | null) {
  if (!value) return "Not yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Invalid date";
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
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

function actorProfileProvenance(profile: ThreatActorProfessionalProfile) {
  if (profile.source_kind === "ai_refreshed") return "Sourced AI overlay";
  if (profile.source_kind === "static_local_curated") return "Bundled analyst dossier";
  if (profile.source_kind === "static_local_framework") return "Bundled ATT&CK baseline";
  if (profile.source_kind === "static_local_catalog") return "Bundled catalogue baseline";
  if (profile.source_kind === "static_local_label") return "Bundled label baseline";
  return "External CTI baseline";
}

function App() {
  const [page, setPage] = useState<Page>("home");
  const [showOnboarding, setShowOnboarding] = useState(() => {
    try {
      return (
        window.localStorage.getItem("extortsignal.onboarding.tour.v1") !==
        "complete"
      );
    } catch {
      return true;
    }
  });
  const [routeLoading, setRouteLoading] = useState(false);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [clients, setClients] = useState<Client[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [claims, setClaims] = useState<Claim[]>([]);
  const [sources, setSources] = useState<SourceHealth[]>([]);
  const [aiJobs, setAIJobs] = useState<AIJob[]>([]);
  const [selectedAIJob, setSelectedAIJob] = useState<AIJob | null>(null);
  const aiJobStatuses = useRef<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [loaderMinimumElapsed, setLoaderMinimumElapsed] = useState(false);
  const [showInitialLoader, setShowInitialLoader] = useState(true);
  const [error, setError] = useState("");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return (
        window.localStorage.getItem("extortsignal.sidebar.collapsed") === "1"
      );
    } catch {
      return false;
    }
  });

  useEffect(() => {
    const timer = window.setTimeout(() => setLoaderMinimumElapsed(true), 450);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(
        "extortsignal.sidebar.collapsed",
        sidebarCollapsed ? "1" : "0",
      );
    } catch {
      /* Local storage may be unavailable in hardened browser profiles. */
    }
  }, [sidebarCollapsed]);

  const refresh = useCallback(async () => {
    try {
      const [dashboard, clientData, alertData, claimData, sourceData] =
        await Promise.all([
          api.dashboard(),
          api.clients(),
          api.alerts(),
          api.claims(),
          api.sources(),
        ]);
      setSummary(dashboard);
      setClients(clientData);
      setAlerts(alertData);
      setClaims(claimData);
      setSources(sourceData);
      setError("");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "The local service could not be reached",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => void refresh(), 30_000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  useEffect(() => {
    let active = true;
    const poll = async () => {
      try {
        const jobs = await api.aiJobs(50);
        if (!active) return;
        const finishedNow = jobs.some(
          (job) =>
            ["completed", "failed"].includes(job.status) &&
            ["queued", "running"].includes(aiJobStatuses.current[job.id]),
        );
        aiJobStatuses.current = Object.fromEntries(
          jobs.map((job) => [job.id, job.status]),
        );
        setAIJobs(jobs);
        if (finishedNow) void refresh();
      } catch {
        /* Main connectivity status already reports API failures. */
      }
    };
    void poll();
    const interval = window.setInterval(() => void poll(), 2000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [refresh]);

  useEffect(() => {
    if (!routeLoading) return;
    const timer = window.setTimeout(() => setRouteLoading(false), 520);
    return () => window.clearTimeout(timer);
  }, [page, routeLoading]);

  const navigate = useCallback(
    (destination: Page) => {
      if (destination === page) return;
      setRouteLoading(true);
      setPage(destination);
    },
    [page],
  );

  const openAIJob = (job: AIJob, navigateToDestination: boolean) => {
    if (navigateToDestination) navigate(job.destination as Page);
    setSelectedAIJob(job);
    void api
      .markAIJobSeen(job.id)
      .then((updated) =>
        setAIJobs((current) =>
          current.map((item) => (item.id === updated.id ? updated : item)),
        ),
      );
  };
  const viewAIJob = (job: AIJob) => openAIJob(job, true);
  const inspectAIJob = (job: AIJob) => openAIJob(job, false);

  const completeOnboarding = useCallback((destination: Page = "home") => {
    try {
      window.localStorage.setItem(
        "extortsignal.onboarding.tour.v1",
        "complete",
      );
    } catch {
      /* The tour still closes when storage is unavailable. */
    }
    setPage(destination);
    setShowOnboarding(false);
  }, []);

  if (showInitialLoader)
    return (
      <AppLoadingScreen
        ready={!loading && loaderMinimumElapsed}
        onComplete={() => setShowInitialLoader(false)}
      />
    );
  if (error && !summary)
    return <ConnectionError message={error} retry={refresh} />;
  if (showOnboarding) return <Onboarding onComplete={completeOnboarding} />;

  return (
    <div className="min-h-[100dvh] bg-[#f5f7f6] text-zinc-900">
      <Sidebar
        current={page}
        onNavigate={navigate}
        urgent={(summary?.urgent_alerts ?? 0) + (summary?.awaiting_review ?? 0)}
        collapsed={sidebarCollapsed}
        onCollapsedChange={setSidebarCollapsed}
      />
      <main
        className={`min-h-[100dvh] w-full max-w-full overflow-x-hidden transition-[padding] duration-200 ${sidebarCollapsed ? "md:pl-20" : "md:pl-[17rem]"}`}
      >
        <TopBar
          page={page}
          sources={sources}
          onRefresh={refresh}
          onOpenGuide={() => setShowOnboarding(true)}
        />
        {error && (
          <InlineNotice tone="danger">
            Live refresh failed. Showing the last available data.
          </InlineNotice>
        )}
        <div className="relative mx-auto min-h-[calc(100dvh-6rem)] max-w-[1400px] px-4 pb-16 pt-5 sm:px-6 md:px-9 md:pt-8">
          <AnimatePresence initial={false}>
            {routeLoading && <TabLoadingScreen key={page} page={page} />}
          </AnimatePresence>
          <DashboardMotionSurface key={page} page={page}>
            {page === "home" && summary && (
              <Home summary={summary} onNavigate={navigate} />
            )}
            {page === "intelligence" && (
              <IntelligencePage onNavigate={navigate} />
            )}
            {page === "profiles" && <ActorProfilesPage />}
            {page === "alerts" && (
              <AlertsPage alerts={alerts} onUpdated={refresh} />
            )}
            {page === "clients" && (
              <ClientsPage clients={clients} onCreated={refresh} />
            )}
            {page === "activity" && <ActivityDetailPage />}
            {page === "direct" && <DirectSitesPage />}
            {page === "sources" && (
              <SourcesPage sources={sources} onUpdated={refresh} />
            )}
            {page === "tasks" && (
              <BackgroundTasksPage onView={inspectAIJob} />
            )}
            {page === "settings" && <SettingsPage />}
          </DashboardMotionSurface>
        </div>
      </main>
      <AIJobCenter
        jobs={aiJobs}
        onView={viewAIJob}
        onOpenHistory={() => navigate("tasks")}
        onDismiss={(job) => {
          void api
            .markAIJobSeen(job.id)
            .then((updated) =>
              setAIJobs((current) =>
                current.map((item) =>
                  item.id === updated.id ? updated : item,
                ),
              ),
            );
        }}
      />
      <AnimatePresence>
        {selectedAIJob && (
          <AIJobResultDialog
            job={selectedAIJob}
            onClose={() => setSelectedAIJob(null)}
            onContinue={() => {
              navigate(selectedAIJob.destination as Page);
              setSelectedAIJob(null);
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function LoadingStatusCard({
  title,
  description,
  className = "",
  iconOnly = false,
  announce = true,
}: {
  title: string;
  description?: string;
  className?: string;
  iconOnly?: boolean;
  announce?: boolean;
}) {
  const root = useRef<HTMLDivElement>(null);
  const reducedMotion = useReducedMotion();

  useGSAP(
    () => {
      if (reducedMotion) {
        gsap.set("[data-loading-status-content]", { opacity: 1, scale: 1 });
        gsap.set("[data-loading-status-dot]", { opacity: 0.55, y: 0 });
        return;
      }
      gsap.fromTo(
        "[data-loading-status-content]",
        { opacity: 0, scale: 0.98 },
        { opacity: 1, scale: 1, duration: 0.18, ease: "power2.out" },
      );
      gsap.fromTo(
        "[data-loading-status-dot]",
        { opacity: 0.25, y: 0 },
        {
          opacity: 0.9,
          y: -2,
          duration: 0.34,
          stagger: 0.1,
          repeat: -1,
          yoyo: true,
          ease: "sine.inOut",
        },
      );
    },
    { scope: root, dependencies: [reducedMotion], revertOnUpdate: true },
  );

  return (
    <div
      ref={root}
      role={announce ? "status" : undefined}
      aria-live={announce ? "polite" : undefined}
      aria-label={announce ? title : undefined}
      aria-busy={announce ? "true" : undefined}
      data-loading-status-card
      className={`loading-status-card ${className}`}
    >
      <div
        data-loading-status-content
        className={`flex rounded-2xl border border-zinc-200 bg-white shadow-[0_18px_46px_-30px_rgba(15,118,110,.5)] ${iconOnly ? "flex-col items-center gap-2.5 px-3.5 py-3" : "min-h-16 items-center gap-3 px-4 py-3.5"}`}
      >
        <span
          className={`grid shrink-0 place-items-center rounded-xl border border-teal-100 bg-teal-50 ${iconOnly ? "h-11 w-11" : "h-10 w-10"}`}
        >
          <img
            src="/extortsignal-mark.svg"
            alt=""
            className={iconOnly ? "h-7 w-7" : "h-6 w-6"}
          />
        </span>
        {!iconOnly && (
          <span className="min-w-0 flex-1 pr-2">
            <span className="block text-sm font-medium text-zinc-800">
              {title}
            </span>
            {description && (
              <span className="mt-0.5 block text-xs leading-5 text-zinc-500">
                {description}
              </span>
            )}
          </span>
        )}
        <span
          className={`${iconOnly ? "mx-auto" : "ml-auto"} flex shrink-0 items-center gap-1.5`}
          aria-hidden="true"
        >
          {[0, 1, 2].map((item) => (
            <span
              key={item}
              data-loading-status-dot
              className="h-1.5 w-1.5 rounded-full bg-teal-700"
            />
          ))}
        </span>
      </div>
      {iconOnly && <span className="sr-only">{title}</span>}
    </div>
  );
}

function TabLoadingScreen({ page }: { page: Page }) {
  const reducedMotion = useReducedMotion();
  const title = navItems.find((item) => item.page === page)?.label ?? "Dashboard";

  return (
    <motion.div
      initial={reducedMotion ? false : { opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: reducedMotion ? 0.01 : 0.16 }}
      className="absolute inset-0 z-[9] grid place-items-center bg-[#f5f7f6]/98 p-4"
    >
      <LoadingStatusCard
        title={`Loading ${title}`}
        iconOnly
      />
    </motion.div>
  );
}

function DashboardMotionSurface({
  page,
  children,
}: {
  page: Page;
  children: ReactNode;
}) {
  const root = useRef<HTMLDivElement>(null);
  const reducedMotion = useReducedMotion();

  useGSAP(
    (_context, contextSafe) => {
      const surface = root.current;
      const pageRoot = surface?.firstElementChild;
      if (!surface || !pageRoot) return;

      const blocks = Array.from(pageRoot.children).slice(0, 14);
      const cards = Array.from(
        surface.querySelectorAll<HTMLElement>(
          "section, [data-dashboard-card]",
        ),
      );
      cards.forEach((card) => card.classList.add("dashboard-card-motion"));

      if (reducedMotion) {
        gsap.set(blocks, { clearProps: "all" });
      } else {
        gsap.fromTo(
          blocks,
          { autoAlpha: 0 },
          {
            autoAlpha: 1,
            duration: 0.28,
            stagger: 0.035,
            ease: "power1.out",
            clearProps: "opacity,visibility",
          },
        );
      }

      const animatedRows = new WeakSet<Element>();
      const runRowAnimation = (rows: Element[]) => {
        const fresh = rows
          .filter((row) => !animatedRows.has(row))
          .slice(0, 14);
        fresh.forEach((row) => animatedRows.add(row));
        if (!fresh.length || reducedMotion) return;
        gsap.fromTo(
          fresh,
          { autoAlpha: 0, y: 4 },
          {
            autoAlpha: 1,
            y: 0,
            duration: 0.24,
            stagger: 0.025,
            ease: "power2.out",
            clearProps: "transform,opacity,visibility",
          },
        );
      };
      const animateRows = contextSafe
        ? contextSafe(runRowAnimation)
        : runRowAnimation;
      animateRows(
        Array.from(
          surface.querySelectorAll("tbody tr, [data-dashboard-row]"),
        ),
      );

      const observer = new MutationObserver((mutations) => {
        const rows: Element[] = [];
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (!(node instanceof Element)) return;
            if (node.matches("tbody tr, [data-dashboard-row]")) rows.push(node);
            rows.push(
              ...Array.from(
                node.querySelectorAll("tbody tr, [data-dashboard-row]"),
              ),
            );
          });
        });
        animateRows(rows);
      });
      observer.observe(surface, { childList: true, subtree: true });

      return () => {
        observer.disconnect();
        cards.forEach((card) => card.classList.remove("dashboard-card-motion"));
      };
    },
    {
      scope: root,
      dependencies: [page, reducedMotion],
      revertOnUpdate: true,
    },
  );

  return (
    <div ref={root} className="app-page-surface dashboard-motion-surface">
      {children}
    </div>
  );
}

function AIJobCenter({
  jobs,
  onView,
  onDismiss,
  onOpenHistory,
}: {
  jobs: AIJob[];
  onView: (job: AIJob) => void;
  onDismiss: (job: AIJob) => void;
  onOpenHistory: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const reducedMotion = useReducedMotion();
  const dragControls = useDragControls();
  const [position, setPosition] = useState(() => {
    try {
      return JSON.parse(
        window.localStorage.getItem("extortsignal.ai-jobs.position") ||
          '{"x":0,"y":0}',
      ) as { x: number; y: number };
    } catch {
      return { x: 0, y: 0 };
    }
  });
  const running = jobs.filter(
    (job) => job.status === "queued" || job.status === "running",
  );
  const unseen = jobs.filter(
    (job) =>
      (job.status === "completed" || job.status === "failed") && !job.seen_at,
  );
  const visible = jobs.slice(0, 3);
  if (!jobs.length) return null;
  return (
    <motion.aside
      aria-label="AI task notifications"
      drag
      dragControls={dragControls}
      dragListener={false}
      dragMomentum={false}
      dragElastic={0}
      animate={{ x: position.x, y: position.y }}
      onDragEnd={(_, info) => {
        const next = {
          x: position.x + info.offset.x,
          y: position.y + info.offset.y,
        };
        setPosition(next);
        try {
          window.localStorage.setItem(
            "extortsignal.ai-jobs.position",
            JSON.stringify(next),
          );
        } catch {
          /* Hardened profiles may disable local storage. */
        }
      }}
      className="fixed bottom-20 right-4 z-[60] w-[min(390px,calc(100vw-2rem))] md:bottom-6"
    >
      <div className="ml-auto flex w-fit items-center overflow-hidden rounded-full border border-violet-200 bg-white text-sm text-violet-900 shadow-lg">
        <button
          type="button"
          onPointerDown={(event) => dragControls.start(event)}
          className="grid min-h-11 w-10 touch-none cursor-grab place-items-center border-r border-violet-100 text-violet-400 transition hover:bg-violet-50 hover:text-violet-700 active:cursor-grabbing"
          title="Drag AI tasks"
          aria-label="Drag AI tasks floating menu"
        >
          <DotsSixVertical size={16} />
        </button>
        <button
          type="button"
          onClick={() => setExpanded((current) => !current)}
          className="flex min-h-11 items-center gap-2 px-3 font-medium transition hover:bg-violet-50"
          aria-expanded={expanded}
          aria-controls="ai-task-notifications"
        >
          <Cpu size={18} />
          AI tasks
          {running.length > 0 && (
            <span className="rounded-full bg-violet-100 px-2 py-0.5 font-mono text-xs">
              {running.length} running
            </span>
          )}
          {unseen.length > 0 && (
            <span className="rounded-full bg-teal-100 px-2 py-0.5 font-mono text-xs text-teal-800">
              {unseen.length} ready
            </span>
          )}
          <CaretDown
            size={15}
            className={`transition ${expanded ? "rotate-180" : ""}`}
          />
        </button>
      </div>
      <AnimatePresence initial={false}>
        {expanded && visible.length > 0 && (
          <motion.div
            id="ai-task-notifications"
            initial={
              reducedMotion ? false : { opacity: 0, scale: 0.97, y: 8 }
            }
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={
              reducedMotion
                ? { opacity: 0 }
                : { opacity: 0, scale: 0.98, y: 6 }
            }
            transition={{ type: "spring", stiffness: 260, damping: 25 }}
            className="mt-2 origin-bottom-right space-y-2 rounded-2xl border border-zinc-200 bg-white/95 p-2 shadow-2xl backdrop-blur"
          >
          <div className="flex items-center justify-between px-2 py-1">
            <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-500">
              Latest three tasks
            </p>
            <button
              type="button"
              className="text-xs font-medium text-violet-700 hover:text-violet-950"
              onClick={() => {
                setExpanded(false);
                onOpenHistory();
              }}
            >
              All task history
            </button>
          </div>
          {visible.map((job, index) => (
            <motion.div
              key={job.id}
              initial={reducedMotion ? false : { opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: reducedMotion ? 0 : index * 0.045 }}
              className={`rounded-xl border p-3 ${job.status === "failed" ? "border-red-200 bg-red-50" : job.status === "completed" ? "border-teal-200 bg-teal-50" : "border-violet-200 bg-violet-50"}`}
            >
              <div className="flex items-start gap-3">
                {job.status === "queued" || job.status === "running" ? (
                  <SpinnerGap
                    className="mt-0.5 shrink-0 animate-spin text-violet-700"
                    size={18}
                  />
                ) : job.status === "completed" ? (
                  <CheckCircle
                    className="mt-0.5 shrink-0 text-teal-700"
                    size={18}
                  />
                ) : (
                  <XCircle className="mt-0.5 shrink-0 text-red-700" size={18} />
                )}
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{job.title}</p>
                  <p className="mt-1 line-clamp-2 text-xs text-zinc-500">
                    {job.status === "queued"
                      ? "Waiting for the AI worker"
                      : job.status === "running"
                        ? "Running in the background—you may continue browsing"
                        : job.status === "completed"
                          ? `Completed ${formatTime(job.completed_at)}`
                          : job.error || "AI task failed"}
                  </p>
                  {job.status === "completed" || job.status === "failed" ? (
                    <button
                      type="button"
                      onClick={() => onView(job)}
                      className="mt-2 text-xs font-medium text-violet-800 underline underline-offset-2"
                    >
                      View result in {job.destination}
                    </button>
                  ) : null}
                </div>
                {(job.status === "completed" || job.status === "failed") &&
                  !job.seen_at && (
                    <button
                      type="button"
                      aria-label={`Dismiss ${job.title}`}
                      onClick={() => onDismiss(job)}
                      className="text-zinc-400 hover:text-zinc-700"
                    >
                      <X size={15} />
                    </button>
                  )}
              </div>
            </motion.div>
          ))}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.aside>
  );
}

function BackgroundTasksPage({ onView }: { onView: (job: AIJob) => void }) {
  const [history, setHistory] = useState<AIJobHistoryResponse | null>(null);
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [jobType, setJobType] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const load = async (showLoading: boolean) => {
      if (showLoading) setLoading(true);
      try {
        const result = await api.aiJobHistory({
          page,
          page_size: 25,
          status,
          job_type: jobType,
          query,
        });
        if (!active) return;
        setHistory(result);
        setError("");
        if (page > result.pages) setPage(result.pages);
      } catch (reason) {
        if (!active) return;
        setError(
          reason instanceof Error
            ? reason.message
            : "Background task history could not be loaded",
        );
      } finally {
        if (active && showLoading) setLoading(false);
      }
    };
    const timer = window.setTimeout(() => void load(true), 180);
    const interval = window.setInterval(() => void load(false), 5000);
    return () => {
      active = false;
      window.clearTimeout(timer);
      window.clearInterval(interval);
    };
  }, [jobType, page, query, status]);

  const resetFilters = () => {
    setQuery("");
    setStatus("");
    setJobType("");
    setPage(1);
  };
  const statusCounts = history?.status_counts ?? {};
  const statusCards: { key: AIJob["status"]; label: string }[] = [
    { key: "queued", label: "Queued" },
    { key: "running", label: "Running" },
    { key: "completed", label: "Completed" },
    { key: "failed", label: "Failed" },
  ];
  return (
    <div>
      <PageIntro
        eyebrow="Background operations"
        title="AI task history"
        description="Review every queued, running, completed and failed AI operation. History is retained locally and loaded in pages so the console remains responsive as records grow."
      />

      <div className="mt-7 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {statusCards.map((item) => (
          <button
            key={item.key}
            type="button"
            onClick={() => {
              setStatus(status === item.key ? "" : item.key);
              setPage(1);
            }}
            className={`rounded-2xl border bg-white p-4 text-left transition ${status === item.key ? "border-violet-400 ring-2 ring-violet-100" : "border-zinc-200 hover:border-zinc-300"}`}
          >
            <span className="text-xs text-zinc-500">{item.label}</span>
            <span className="mt-2 block font-mono text-2xl text-zinc-900">
              {statusCounts[item.key] ?? 0}
            </span>
          </button>
        ))}
      </div>

      <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-5 md:p-6">
        <div className="grid gap-3 lg:grid-cols-[minmax(220px,1fr)_240px_240px_auto]">
          <label className="relative block">
            <span className="sr-only">Search background tasks</span>
            <MagnifyingGlass
              size={17}
              className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-zinc-400"
            />
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(1);
              }}
              placeholder="Search task title…"
              className="input pl-11"
            />
          </label>
          <SearchableSelect
            ariaLabel="Filter tasks by status"
            value={status}
            onChange={(value) => {
              setStatus(value);
              setPage(1);
            }}
            searchPlaceholder="Search status…"
            options={[
              { value: "", label: "All statuses" },
              ...statusCards.map((item) => ({
                value: item.key,
                label: item.label,
              })),
            ]}
          />
          <SearchableSelect
            ariaLabel="Filter tasks by type"
            value={jobType}
            onChange={(value) => {
              setJobType(value);
              setPage(1);
            }}
            searchPlaceholder="Search task types…"
            options={[
              { value: "", label: "All task types" },
              ...Object.entries(AI_JOB_TYPE_LABELS).map(([value, label]) => ({
                value,
                label,
              })),
            ]}
          />
          <button
            type="button"
            className="button-secondary justify-center"
            onClick={resetFilters}
            disabled={!query && !status && !jobType}
          >
            <X size={17} />
            Clear
          </button>
        </div>
      </section>

      {error && <InlineNotice tone="danger">{error}</InlineNotice>}
      {loading && !history ? (
        <LoadingStatusCard
          title="Loading background task history"
          description="Retrieving retained queued, completed, and failed AI operations."
          className="mt-5 max-w-xl"
        />
      ) : history?.items.length ? (
        <div className="mt-5 space-y-3">
          <div className="flex items-center justify-between px-1 text-xs text-zinc-500">
            <span>{history.total.toLocaleString()} matching tasks</span>
            <span>
              Page {history.page} of {history.pages}
            </span>
          </div>
          {history.items.map((job) => {
            const inProgress = job.status === "queued" || job.status === "running";
            return (
              <article
                key={job.id}
                className="rounded-2xl border border-zinc-200 bg-white p-5"
              >
                <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
                  <div className="flex min-w-0 items-start gap-3">
                    <div
                      className={`mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-xl ${job.status === "failed" ? "bg-red-50 text-red-700" : job.status === "completed" ? "bg-teal-50 text-teal-700" : "bg-violet-50 text-violet-700"}`}
                    >
                      {inProgress ? (
                        <SpinnerGap size={18} className="animate-spin" />
                      ) : job.status === "completed" ? (
                        <CheckCircle size={18} />
                      ) : (
                        <XCircle size={18} />
                      )}
                    </div>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-sm font-medium text-zinc-900">
                          {job.title}
                        </h3>
                        {!job.seen_at && !inProgress && (
                          <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[10px] uppercase tracking-wide text-violet-800">
                            New result
                          </span>
                        )}
                      </div>
                      <p className="mt-1 text-xs leading-5 text-zinc-500">
                        {aiJobTypeLabel(job.job_type)} · {job.status} · requested {formatTime(job.created_at)}
                        {job.completed_at
                          ? ` · finished ${formatTime(job.completed_at)}`
                          : job.started_at
                            ? ` · started ${formatTime(job.started_at)}`
                            : ""}
                      </p>
                      {job.error && (
                        <p className="mt-2 line-clamp-2 text-xs leading-5 text-red-700">
                          {job.error}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className="rounded-full bg-zinc-100 px-3 py-1.5 text-xs text-zinc-600">
                      {job.destination}
                    </span>
                    {!inProgress && (
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={() => onView(job)}
                      >
                        <ArrowRight size={16} />
                        View result
                      </button>
                    )}
                  </div>
                </div>
              </article>
            );
          })}
          <div className="flex items-center justify-between pt-2">
            <button
              type="button"
              className="button-secondary"
              disabled={history.page <= 1}
              onClick={() => setPage((current) => Math.max(1, current - 1))}
            >
              <CaretLeft size={17} />
              Previous
            </button>
            <span className="text-xs text-zinc-500">
              Showing {(history.page - 1) * history.page_size + 1}–
              {Math.min(history.page * history.page_size, history.total)} of {history.total}
            </span>
            <button
              type="button"
              className="button-secondary"
              disabled={history.page >= history.pages}
              onClick={() => setPage((current) => current + 1)}
            >
              Next
              <CaretRight size={17} />
            </button>
          </div>
        </div>
      ) : (
        <EmptyState
          icon={<Cpu size={26} />}
          title="No matching AI tasks"
          description="Adjust the filters or queue an AI operation elsewhere in the console."
        />
      )}
    </div>
  );
}

function AIJobResultDialog({
  job,
  onClose,
  onContinue,
}: {
  job: AIJob;
  onClose: () => void;
  onContinue: () => void;
}) {
  const result = job.result ?? {};
  const strings = (value: unknown) =>
    Array.isArray(value)
      ? value.filter((item): item is string => typeof item === "string")
      : [];
  const text = (key: string) =>
    typeof result[key] === "string" ? String(result[key]) : "";
  const number = (key: string) =>
    typeof result[key] === "number" ? Number(result[key]) : 0;
  const profileOverlayApplied =
    result.overlay_status === "applied" ||
    (!result.overlay_status && number("independent_source_count") > 0);
  return (
    <Modal
      wide
      title={job.status === "failed" ? "AI task failed" : job.title}
      description={`Background task ${job.status}. Requested ${formatTime(job.created_at)}${job.completed_at ? ` · finished ${formatTime(job.completed_at)}` : ""}.`}
      onClose={onClose}
    >
      {job.status === "failed" ? (
        <InlineNotice tone="danger">
          {job.error || "The AI provider did not complete this task."}
        </InlineNotice>
      ) : job.job_type === "actor_profile_refresh" ? (
        <div className="mt-5 space-y-4">
          {profileOverlayApplied ? (
            <InlineNotice tone="neutral">
              This sourced AI overlay passed citation validation and is now
              available above the bundled local dossier.
            </InlineNotice>
          ) : (
            <InlineNotice tone="danger">
              No attributable actor-specific evidence was retained. This result
              remains in the audit history but did not replace the bundled local
              dossier.
            </InlineNotice>
          )}
          <section className="rounded-2xl bg-violet-50 p-5">
            <p className="text-sm leading-7 text-zinc-700">
              {text("summary") || "No profile summary was returned."}
            </p>
          </section>
          <div className="grid gap-3 sm:grid-cols-2">
            <ProfileText
              label="Motivation"
              value={text("motivation") || "Not established"}
            />
            <ProfileText
              label="Targeting"
              value={text("targeting") || "Not established"}
            />
            <ProfileText
              label="Capabilities"
              value={text("capabilities") || "Not established"}
            />
            <ProfileText
              label="Campaign history"
              value={text("campaign_history") || "Not established"}
            />
          </div>
          {strings(result.caveats).length > 0 && (
            <AnalysisList
              title="Attribution and data limitations"
              items={strings(result.caveats)}
              muted
            />
          )}
        </div>
      ) : job.job_type === "alert_assessment" ? (
        <AlertAssessmentView assessment={result} />
      ) : job.job_type === "bulk_alert_assessment" ? (
        <BulkAlertAssessmentResult result={result} />
      ) : job.job_type === "intelligence_analysis" ||
        job.job_type === "actor_analysis" ? (
        <div className="mt-5 space-y-4">
          <div className="rounded-2xl bg-violet-50 p-5">
            <p className="text-sm leading-7 text-zinc-700">
              {text("summary") || "No narrative was returned."}
            </p>
          </div>
          {strings(result.patterns).length > 0 && (
            <AnalysisList
              title="Observed patterns"
              items={strings(result.patterns)}
            />
          )}
          {strings(result.risk_observations).length > 0 && (
            <AnalysisList
              title="Defensive observations"
              items={strings(result.risk_observations)}
            />
          )}
          {strings(result.caveats).length > 0 && (
            <AnalysisList
              title="Limitations"
              items={strings(result.caveats)}
              muted
            />
          )}
        </div>
      ) : job.job_type === "victim_enrichment" ? (
        <div className="mt-5 space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <DetailMetric
              label="Industry"
              value={
                text("ai_industry") || text("industry") || "Not established"
              }
            />
            <DetailMetric
              label="Geography"
              value={text("ai_country") || text("country") || "Not established"}
            />
            <DetailMetric
              label="Organization type"
              value={text("ai_organization_type") || "Not established"}
            />
            <DetailMetric
              label="AI confidence"
              value={`${number("ai_confidence")}%`}
            />
          </div>
          <section className="rounded-2xl bg-violet-50 p-5">
            <p className="text-xs font-bold uppercase tracking-wide text-violet-700">
              Organization description
            </p>
            <p className="mt-3 text-sm leading-7 text-zinc-700">
              {text("ai_description") ||
                text("description") ||
                "No description returned."}
            </p>
          </section>
          <p className="text-xs text-zinc-500">
            Open the claim in Activity to review parsed incident evidence and
            supporting links.
          </p>
        </div>
      ) : job.job_type === "bulk_victim_enrichment" ? (
        <div className="mt-5 grid gap-3 sm:grid-cols-3">
          <DetailMetric label="Enriched" value={String(number("enriched"))} />
          <DetailMetric label="Failed" value={String(number("failed"))} />
          <DetailMetric label="Remaining" value={String(number("remaining"))} />
        </div>
      ) : job.job_type === "alert_notification_draft" ||
        job.job_type === "claim_awareness_draft" ? (
        <AIEmailDraftResult subject={text("subject")} body={text("body")} />
      ) : job.job_type === "provider_test" ? (
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <DetailMetric label="Status" value={text("status") || "Unknown"} />
          <DetailMetric label="Model" value={text("model") || "Not returned"} />
          <DetailMetric
            label="Provider"
            value={text("provider") || "Not returned"}
          />
          <DetailMetric label="Latency" value={`${number("latency_ms")} ms`} />
        </div>
      ) : (
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <DetailMetric label="Status" value={text("status") || "Completed"} />
          <DetailMetric label="New victims" value={String(number("count"))} />
        </div>
      )}
      <div className="mt-6 flex justify-end">
        <button type="button" className="button-primary" onClick={onContinue}>
          <ArrowRight size={17} />
          Continue in {job.destination}
        </button>
      </div>
    </Modal>
  );
}

function AlertAssessmentView({ assessment }: { assessment: unknown }) {
  const value =
    assessment && typeof assessment === "object"
      ? (assessment as Record<string, unknown>)
      : {};
  const text = (key: string) =>
    typeof value[key] === "string" ? String(value[key]) : "";
  const number = (key: string) =>
    typeof value[key] === "number" ? Number(value[key]) : 0;
  const strings = (key: string) =>
    Array.isArray(value[key])
      ? (value[key] as unknown[]).filter(
          (item): item is string => typeof item === "string",
        )
      : [];
  const victim =
    value.victim_details && typeof value.victim_details === "object"
      ? (value.victim_details as Record<string, unknown>)
      : {};
  const victimText = (key: string) =>
    typeof victim[key] === "string" ? String(victim[key]) : "";
  const pastIncidents = Array.isArray(victim.past_incidents)
    ? victim.past_incidents.length
    : 0;
  return (
    <div className="mt-5 space-y-4">
      <section className="rounded-2xl border border-violet-200 bg-violet-50/50 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs font-medium uppercase tracking-wide text-violet-700">
            AI-assisted triage
          </p>
          <span className="rounded-full bg-white px-3 py-1 font-mono text-xs text-violet-800">
            {number("confidence")}% analytic confidence
          </span>
        </div>
        <p className="mt-3 text-sm leading-7 text-zinc-700">
          {text("executive_summary") || "No executive summary was returned."}
        </p>
      </section>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <DetailMetric
          label="Named victim"
          value={victimText("name") || "Not supplied"}
        />
        <DetailMetric
          label="Industry"
          value={victimText("industry") || "Not established"}
        />
        <DetailMetric
          label="Geography"
          value={victimText("geography") || "Not established"}
        />
        <DetailMetric
          label="Organization type"
          value={victimText("organization_type") || "Not established"}
        />
      </div>
      {victimText("description") && (
        <section className="rounded-2xl border border-zinc-200 p-5">
          <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
            Organization background used
          </p>
          <p className="mt-3 text-sm leading-7 text-zinc-700">
            {victimText("description")}
          </p>
          <p className="mt-3 text-xs text-zinc-400">
            {pastIncidents} supported past incident record
            {pastIncidents === 1 ? "" : "s"} supplied to the assessment
          </p>
        </section>
      )}
      <div className="grid gap-4 lg:grid-cols-3">
        <AssessmentNarrative
          label="Named-victim profile"
          value={text("named_victim_profile")}
        />
        <AssessmentNarrative
          label="Alert relevance"
          value={text("alert_relevance")}
        />
        <AssessmentNarrative
          label="Analytic assessment"
          value={text("analytic_assessment")}
        />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {strings("recommended_actions").length > 0 && (
          <AnalysisList
            title="Recommended analyst actions"
            items={strings("recommended_actions")}
          />
        )}
        {strings("evidence_gaps").length > 0 && (
          <AnalysisList
            title="Evidence gaps"
            items={strings("evidence_gaps")}
            muted
          />
        )}
      </div>
      <p className="text-[11px] leading-5 text-zinc-400">
        {text("disclaimer") ||
          "AI-assisted triage based on retained public-source evidence; analyst review remains required."}
        {text("generated_at")
          ? ` Generated ${formatTime(text("generated_at"))}.`
          : ""}
      </p>
    </div>
  );
}

function AssessmentNarrative({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <section className="rounded-2xl border border-zinc-200 bg-white p-5">
      <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
        {label}
      </p>
      <p className="mt-3 text-sm leading-7 text-zinc-700">
        {value || "Not established from the supplied evidence."}
      </p>
    </section>
  );
}

function BulkAlertAssessmentResult({
  result,
}: {
  result: Record<string, unknown>;
}) {
  const number = (key: string) =>
    typeof result[key] === "number" ? Number(result[key]) : 0;
  const rows = Array.isArray(result.results)
    ? result.results.filter(
        (item): item is Record<string, unknown> =>
          Boolean(item) && typeof item === "object",
      )
    : [];
  return (
    <div className="mt-5 space-y-4">
      <div className="grid gap-3 sm:grid-cols-3">
        <DetailMetric label="Requested" value={String(number("requested"))} />
        <DetailMetric label="Assessed" value={String(number("assessed"))} />
        <DetailMetric label="Failed" value={String(number("failed"))} />
      </div>
      {rows.length > 0 && (
        <div className="overflow-hidden rounded-2xl border border-zinc-200">
          {rows.map((row, index) => (
            <div
              key={String(row.assessment_id || row.alert_id)}
              className={`p-4 ${index > 0 ? "border-t border-zinc-100" : ""}`}
            >
              <div className="flex items-start justify-between gap-4">
                <p className="text-sm leading-6 text-zinc-700">
                  {String(row.executive_summary || "Assessment completed")}
                </p>
                <span className="shrink-0 font-mono text-xs text-violet-700">
                  {Number(row.confidence || 0)}%
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="text-xs text-zinc-500">
        Each successful result is saved against its alert. Reopen an alert to
        review its complete named-victim assessment.
      </p>
    </div>
  );
}

function AIEmailDraftResult({
  subject,
  body,
}: {
  subject: string;
  body: string;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(`Subject: ${subject}\n\n${body}`);
    setCopied(true);
  };
  return (
    <div className="mt-5 space-y-4">
      <div className="rounded-2xl border border-zinc-200 p-5">
        <p className="text-xs font-bold uppercase tracking-wide text-zinc-400">
          Subject
        </p>
        <p className="mt-2 font-semibold">{subject}</p>
      </div>
      <pre className="max-h-[24rem] overflow-y-auto whitespace-pre-wrap rounded-2xl bg-zinc-50 p-5 font-sans text-sm leading-7 text-zinc-700">
        {body}
      </pre>
      <div className="flex flex-wrap justify-end gap-3">
        <button
          type="button"
          className="button-secondary"
          onClick={() => void copy()}
        >
          {copied ? <Check size={18} /> : <EnvelopeSimple size={18} />}
          {copied ? "Copied" : "Copy email"}
        </button>
        <button
          type="button"
          className="button-secondary"
          onClick={() =>
            window.location.assign(
              `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`,
            )
          }
        >
          <EnvelopeSimple size={18} />
          Open in email app
        </button>
      </div>
    </div>
  );
}

function Sidebar({
  current,
  onNavigate,
  urgent,
  collapsed,
  onCollapsedChange,
}: {
  current: Page;
  onNavigate: (page: Page) => void;
  urgent: number;
  collapsed: boolean;
  onCollapsedChange: (collapsed: boolean) => void;
}) {
  const reducedMotion = useReducedMotion();
  return (
    <aside
      className={`fixed inset-x-0 bottom-0 z-20 border-t border-zinc-200 bg-white px-2 py-2 transition-[width,padding] duration-200 md:inset-y-0 md:left-0 md:right-auto md:border-r md:border-t-0 md:py-5 ${collapsed ? "md:w-20 md:px-2" : "md:w-[17rem] md:px-4"}`}
    >
      <div
        className={`hidden md:flex ${collapsed ? "flex-col items-center gap-3" : "items-center gap-3 px-1"}`}
      >
        <div className="grid h-10 w-10 place-items-center rounded-xl bg-white p-1.5 shadow-sm ring-1 ring-zinc-200">
          <img src="/extortsignal-mark.svg" alt="" className="h-full w-full" />
        </div>
        {!collapsed && (
          <div className="min-w-0 flex-1 overflow-hidden">
            <p className="truncate font-semibold tracking-[-0.02em]">
              ExtortSignal
            </p>
            <p className="text-xs leading-4 text-zinc-500">
              Public claim intelligence
            </p>
          </div>
        )}
        <button
          type="button"
          onClick={() => onCollapsedChange(!collapsed)}
          className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-zinc-200 bg-white text-zinc-500 transition-colors hover:bg-zinc-100 hover:text-zinc-900"
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          title={collapsed ? "Expand navigation" : "Collapse navigation"}
        >
          {collapsed ? <CaretRight size={17} /> : <CaretLeft size={17} />}
        </button>
      </div>
      <nav
        className={`flex items-center justify-between gap-1 md:block md:space-y-1 ${collapsed ? "md:mt-5" : "md:mt-9"}`}
        aria-label="Main navigation"
      >
        {navItems.map(({ page, label, icon: Icon }) => {
          const active = current === page;
          const hideOnMobile = [
            "profiles",
            "activity",
            "direct",
            "tasks",
            "settings",
          ].includes(page);
          return (
            <button
              key={page}
              type="button"
              aria-label={label}
              onClick={() => onNavigate(page)}
              title={collapsed ? label : undefined}
              className={`${hideOnMobile ? "hidden md:flex" : "flex"} group relative isolate min-h-11 min-w-11 flex-1 items-center justify-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition active:scale-[0.98] md:w-full md:flex-none ${collapsed ? "md:justify-center md:px-0" : "md:justify-start"} ${
                active
                  ? "text-white"
                  : "text-zinc-600 hover:bg-zinc-100 hover:text-zinc-950"
              }`}
              aria-current={active ? "page" : undefined}
            >
              {active && (
                <motion.span
                  layoutId="active-navigation-item"
                  className="absolute inset-0 -z-10 rounded-xl bg-zinc-900"
                  transition={
                    reducedMotion
                      ? { duration: 0 }
                      : { type: "spring", stiffness: 360, damping: 31 }
                  }
                />
              )}
              <motion.span
                animate={reducedMotion ? undefined : { scale: active ? 1.08 : 1 }}
                transition={{ type: "spring", stiffness: 360, damping: 24 }}
                className="grid place-items-center"
              >
                <Icon size={20} weight={active ? "fill" : "regular"} />
              </motion.span>
              {!collapsed && (
                <span className="hidden md:inline">{label}</span>
              )}
              {page === "alerts" && urgent > 0 && (
                <motion.span
                  key={urgent}
                  initial={reducedMotion ? false : { opacity: 0, scale: 0.72 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ type: "spring", stiffness: 420, damping: 22 }}
                  className={`absolute grid min-h-5 min-w-5 place-items-center rounded-full bg-rose-600 px-1 text-[10px] font-bold text-white ${collapsed ? "right-0 top-0" : "right-1 top-0.5 md:static md:ml-auto"}`}
                >
                  {urgent}
                </motion.span>
              )}
            </button>
          );
        })}
      </nav>
      <div
        className={`absolute bottom-5 hidden rounded-2xl border border-zinc-200 bg-zinc-50 md:block ${collapsed ? "left-3 right-3 p-3" : "left-4 right-4 p-3"}`}
        title={
          collapsed
            ? "Monitoring active · Public claims are allegations until independently confirmed."
            : undefined
        }
      >
        <div
          className={`flex items-center text-xs font-semibold text-zinc-700 ${collapsed ? "justify-center" : "gap-2"}`}
        >
          <StatusPulse />
          {!collapsed && "Monitoring active"}
        </div>
        {!collapsed && (
          <p className="mt-1.5 text-xs leading-relaxed text-zinc-500">
            Public claims are allegations until independently confirmed.
          </p>
        )}
      </div>
    </aside>
  );
}

function TopBar({
  page,
  sources,
  onRefresh,
  onOpenGuide,
}: {
  page: Page;
  sources: SourceHealth[];
  onRefresh: () => Promise<void>;
  onOpenGuide: () => void;
}) {
  const reducedMotion = useReducedMotion();
  const [refreshing, setRefreshing] = useState(false);
  const working = sources.filter(
    (source) => source.status === "working",
  ).length;
  const activeSources = sources.filter(
    (source) => source.status !== "needs_configuration",
  ).length;
  const title = navItems.find((item) => item.page === page)?.label ?? "Home";
  const runRefresh = async () => {
    setRefreshing(true);
    await onRefresh();
    setRefreshing(false);
  };
  return (
    <header className="sticky top-0 z-10 border-b border-zinc-200/80 bg-[#f5f7f6] px-4 py-4 sm:px-6 md:px-9">
      <div className="mx-auto flex max-w-[1400px] items-center justify-between gap-4">
        <div>
          <motion.h1
            key={title}
            initial={reducedMotion ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: reducedMotion ? 0 : 0.2 }}
            className="text-xl font-semibold tracking-tight md:text-2xl"
          >
            {title}
          </motion.h1>
          <p className="hidden text-sm text-zinc-500 sm:block">
            Defensive monitoring of public ransomware claims
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onOpenGuide}
            className="button-secondary !min-h-9 !px-3"
            aria-label="Open product guide"
          >
            <Info size={18} />
            <span className="hidden lg:inline">Guide</span>
          </button>
          <div
            className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-zinc-900 p-1.5 shadow-sm ring-1 ring-zinc-700/10"
            title="Chill Ethical People"
          >
            <img
              src="/chill-ethical-capybara-on-dark.svg"
              alt="Chill Ethical People"
              className="h-full w-full"
            />
          </div>
          <button
            type="button"
            onClick={() => void runRefresh()}
            className="button-secondary"
          >
            <SpinnerGap
              className={refreshing ? "animate-spin" : ""}
              size={18}
            />
            <span className="hidden sm:inline">
              {working}/{activeSources} active sources working
            </span>
            <span className="sm:hidden">Refresh</span>
          </button>
        </div>
      </div>
    </header>
  );
}

function Home({
  summary,
  onNavigate,
}: {
  summary: DashboardSummary;
  onNavigate: (page: Page) => void;
}) {
  const reducedMotion = useReducedMotion();
  const enabledSources = summary.sources.filter(
    (source) => source.status !== "needs_configuration",
  );
  const allWorking =
    enabledSources.length > 0 &&
    enabledSources.every((source) => source.status === "working");
  return (
    <div className="space-y-9">
      <section className="grid gap-5 lg:grid-cols-[1.65fr_1fr]">
        <div className="overflow-hidden rounded-[2rem] bg-zinc-900 p-7 text-white shadow-[0_24px_55px_-30px_rgba(24,24,27,0.55)] md:p-9">
          <div className="flex items-center gap-2 text-sm text-zinc-300">
            <StatusPulse tone={summary.urgent_alerts ? "danger" : "healthy"} />
            {summary.urgent_alerts
              ? "Attention needed"
              : "Monitoring is active"}
          </div>
          <div className="mt-12 max-w-2xl">
            <motion.p
              key={summary.urgent_alerts}
              initial={reducedMotion ? false : { opacity: 0, scale: 0.94 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ type: "spring", stiffness: 180, damping: 20 }}
              className="origin-left text-5xl font-semibold tracking-[-0.055em] md:text-7xl"
            >
              <AnimatedNumber value={summary.urgent_alerts} />
            </motion.p>
            <h2 className="mt-3 text-2xl font-medium tracking-tight md:text-3xl">
              urgent client {summary.urgent_alerts === 1 ? "match" : "matches"}
            </h2>
            <p className="mt-3 max-w-[52ch] text-sm leading-relaxed text-zinc-400 md:text-base">
              Every result is a public threat-actor allegation. Review the
              evidence before contacting a client or escalating an incident.
            </p>
          </div>
          <div className="mt-8 flex flex-wrap gap-3">
            <button
              type="button"
              onClick={() => onNavigate("alerts")}
              className="inline-flex items-center gap-2 rounded-xl bg-white px-4 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-zinc-100 active:scale-[0.98]"
            >
              Open analyst workbench <ArrowRight size={18} />
            </button>
            {summary.awaiting_review > 0 && (
              <button
                type="button"
                onClick={() => onNavigate("alerts")}
                className="inline-flex items-center gap-2 rounded-xl bg-amber-400 px-4 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-amber-300 active:scale-[0.98]"
              >
                <ListMagnifyingGlass size={18} />
                {summary.awaiting_review} requiring human review
                <ArrowRight size={18} />
              </button>
            )}
          </div>
        </div>
        <div className="rounded-[2rem] border border-zinc-200 bg-white p-7 shadow-[0_20px_45px_-32px_rgba(24,24,27,0.25)] md:p-8">
          <div className="flex items-start justify-between">
            <div>
              <p className="eyebrow">System condition</p>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight">
                {allWorking
                  ? "Sources are healthy"
                  : "A source needs attention"}
              </h2>
            </div>
            {allWorking ? (
              <CheckCircle
                className="text-teal-700"
                size={30}
                weight="duotone"
              />
            ) : (
              <Warning className="text-amber-600" size={30} weight="duotone" />
            )}
          </div>
          <div className="mt-8 divide-y divide-zinc-100 border-y border-zinc-100">
            {summary.sources.map((source) => (
              <div
                key={source.source}
                data-dashboard-row
                className="grid grid-cols-[auto_minmax(0,1fr)_4.75rem] items-center gap-3 py-4"
              >
                <div className="contents">
                  <StatusPulse
                    tone={
                      source.status === "working"
                        ? "healthy"
                        : source.status === "unavailable"
                          ? "danger"
                          : "warning"
                    }
                  />
                  <div className="min-w-0">
                    <p className="text-sm font-semibold">
                      {sourceLabel(source.source)}
                    </p>
                    <p className="mt-0.5 text-xs leading-5 text-zinc-500">
                      {source.message}
                    </p>
                  </div>
                </div>
                <span className="text-right font-mono text-xs leading-5 text-zinc-500">
                  {source.records_received.toLocaleString()}
                  <span className="block font-sans text-[10px]">records</span>
                </span>
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
          <Metric
            label="Sources online"
            value={
              summary.sources.filter((source) => source.status === "working")
                .length
            }
          />
        </div>
      </section>

      <section className="overflow-hidden rounded-[2rem] border border-teal-200 bg-gradient-to-br from-teal-50/80 via-white to-white shadow-[0_20px_45px_-36px_rgba(15,118,110,0.45)]">
        <div className="flex flex-col gap-4 border-b border-teal-100 px-6 py-5 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <GlobeHemisphereWest size={20} className="text-teal-700" />
              <p className="eyebrow !text-teal-800">Daily regional watch</p>
            </div>
            <h2 className="mt-2 text-2xl font-medium tracking-tight">
              {(summary.daily_focus_count ?? 0).toLocaleString()} new victim
              {(summary.daily_focus_count ?? 0) === 1 ? "" : "s"} in focus regions
            </h2>
            <p className="mt-2 text-sm leading-6 text-zinc-600">
              Deduplicated public claims ingested during the last 24 hours.
              These entries are also prioritized in the scheduled email digest.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate("activity")}
            className="button-secondary shrink-0"
          >
            Open victim list <ArrowRight size={17} />
          </button>
        </div>
        <div className="flex flex-wrap gap-2 px-6 pt-5">
          {(summary.focus_regions ?? []).length ? (
            (summary.focus_regions ?? []).map((region) => (
              <span
                key={region}
                className="rounded-full border border-teal-200 bg-white px-3 py-1 text-xs text-teal-800"
              >
                {region}
              </span>
            ))
          ) : (
            <p className="text-sm text-zinc-500">
              Add focus regions in Settings to activate regional highlighting.
            </p>
          )}
        </div>
        {(summary.daily_focus_victims ?? []).length ? (
          <div className="mt-4 divide-y divide-teal-100 border-t border-teal-100">
            {(summary.daily_focus_victims ?? []).map((claim) => (
              <button
                type="button"
                key={claim.id}
                data-dashboard-row
                onClick={() => onNavigate("activity")}
                className="grid w-full gap-2 px-6 py-4 text-left transition hover:bg-teal-50 md:grid-cols-[minmax(0,1.4fr)_minmax(9rem,.7fr)_minmax(9rem,.7fr)_auto] md:items-center"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-sm font-medium text-zinc-900">
                      {claim.title}
                    </span>
                    <span className="rounded-full bg-teal-700 px-2 py-0.5 text-[10px] uppercase tracking-wide text-white">
                      New
                    </span>
                  </div>
                  <p className="mt-1 truncate text-xs text-zinc-500">
                    {claim.threat_actor || "Unknown threat actor"}
                  </p>
                </div>
                <p className="truncate text-sm text-zinc-600">
                  {claim.country || claim.ai_country || "Unknown geography"}
                </p>
                <p className="truncate text-sm text-zinc-600">
                  {claim.industry || claim.ai_industry || "Unknown industry"}
                </p>
                <p className="whitespace-nowrap font-mono text-xs text-zinc-500">
                  {formatTime(claim.received_at)}
                </p>
              </button>
            ))}
          </div>
        ) : (
          <div className="mx-6 my-5 rounded-xl border border-dashed border-teal-200 bg-white/70 px-4 py-5 text-sm text-zinc-500">
            {(summary.focus_regions ?? []).length
              ? "No new focus-region victims were ingested in the last 24 hours."
              : "Regional victim results will appear here after regions are selected."}
          </div>
        )}
      </section>

      <section className="grid gap-8 xl:grid-cols-[1.35fr_.85fr]">
        <div>
          <SectionHeading
            title="Latest client matches"
            description="The strongest links between public claims and your monitored organizations."
            action="View all alerts"
            onAction={() => onNavigate("alerts")}
          />
          {summary.new_alerts.length ? (
            <div className="mt-5 overflow-hidden rounded-2xl border border-zinc-200 bg-white">
              {summary.new_alerts.map((alert, index) => (
                <AlertRow key={alert.id} alert={alert} divided={index > 0} />
              ))}
            </div>
          ) : (
            <EmptyState
              title="No client matches"
              description="Monitoring is active. New matches will appear here with the evidence that produced them."
              icon={<ShieldCheck size={30} />}
            />
          )}
        </div>
        <div>
          <SectionHeading
            title="Recent activity"
            description="The latest claims received across all sources."
            action="Open activity"
            onAction={() => onNavigate("activity")}
          />
          <div className="mt-5 divide-y divide-zinc-200 border-y border-zinc-200">
            {summary.recent_claims.slice(0, 6).map((claim) => (
              <ClaimRow key={claim.id} claim={claim} />
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}

function AlertsPage({
  alerts,
  onUpdated,
}: {
  alerts: Alert[];
  onUpdated: () => Promise<void>;
}) {
  const [filter, setFilter] = useState<"open" | "review" | "all" | "closed">(
    "open",
  );
  const [industry, setIndustry] = useState("");
  const [geography, setGeography] = useState("");
  const [clientId, setClientId] = useState("");
  const [selected, setSelected] = useState<Alert | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [bulkStatus, setBulkStatus] = useState<AlertStatus>("investigating");
  const [bulkNote, setBulkNote] = useState("");
  const [bulkFalsePositiveCategory, setBulkFalsePositiveCategory] = useState(
    "unrelated_organization",
  );
  const [bulkWorking, setBulkWorking] = useState(false);
  const [bulkError, setBulkError] = useState("");
  const [bulkNotice, setBulkNotice] = useState("");
  const [liveAlerts, setLiveAlerts] = useState(alerts);
  useEffect(() => setLiveAlerts(alerts), [alerts]);
  const closedStatuses: AlertStatus[] = ["resolved", "dismissed"];
  const industries = Array.from(
    new Set(liveAlerts.map((alert) => alert.claim_industry).filter(Boolean)),
  ).sort((a, b) => a.localeCompare(b));
  const geographies = Array.from(
    new Set(liveAlerts.map((alert) => alert.claim_country).filter(Boolean)),
  ).sort((a, b) => a.localeCompare(b));
  const clients = Array.from(
    new Map(
      liveAlerts.map((alert) => [alert.client_id, alert.client_name]),
    ).entries(),
  ).sort((a, b) => a[1].localeCompare(b[1]));
  const filtered = liveAlerts.filter((alert) => {
    const workflowMatch =
      filter === "all" ||
      (filter === "open" && !closedStatuses.includes(alert.status)) ||
      (filter === "closed" && closedStatuses.includes(alert.status)) ||
      (filter === "review" &&
        alert.severity === "review" &&
        alert.status === "new");
    return (
      workflowMatch &&
      (!industry || alert.claim_industry === industry) &&
      (!geography || alert.claim_country === geography) &&
      (!clientId || alert.client_id === clientId)
    );
  });
  const statusCounts = liveAlerts.reduce<Record<string, number>>(
    (counts, alert) => ({
      ...counts,
      [alert.status]: (counts[alert.status] || 0) + 1,
    }),
    {},
  );
  const reviewCount = liveAlerts.filter(
    (alert) => alert.severity === "review" && alert.status === "new",
  ).length;
  const filteredIds = filtered.map((alert) => alert.id);
  const allFilteredSelected =
    filteredIds.length > 0 &&
    filteredIds.every((alertId) => selectedIds.includes(alertId));
  useEffect(() => {
    const available = new Set(liveAlerts.map((alert) => alert.id));
    setSelectedIds((current) => current.filter((alertId) => available.has(alertId)));
  }, [liveAlerts]);
  const toggleSelected = (alertId: string) => {
    setSelectedIds((current) =>
      current.includes(alertId)
        ? current.filter((item) => item !== alertId)
        : [...current, alertId],
    );
  };
  const toggleAllFiltered = () => {
    setSelectedIds((current) => {
      if (allFilteredSelected)
        return current.filter((alertId) => !filteredIds.includes(alertId));
      return Array.from(new Set([...current, ...filteredIds]));
    });
  };
  const applyBulkStatus = async () => {
    if (!selectedIds.length) return;
    setBulkWorking(true);
    setBulkError("");
    setBulkNotice("");
    try {
      const result = await api.bulkUpdateAlerts(
        selectedIds,
        bulkStatus,
        bulkNote,
      );
      setSelectedIds([]);
      setBulkNote("");
      setBulkNotice(
        result.missing
          ? `${result.updated} alerts updated; ${result.missing} no longer existed.`
          : `${result.updated} alerts updated successfully.`,
      );
      const updatedIds = new Set(selectedIds);
      setLiveAlerts((current) =>
        current.map((alert) =>
          updatedIds.has(alert.id)
            ? { ...alert, status: bulkStatus, note: bulkNote }
            : alert,
        ),
      );
      await onUpdated();
    } catch (reason) {
      setBulkError(
        reason instanceof Error
          ? reason.message
          : "Bulk alert status update failed",
      );
    } finally {
      setBulkWorking(false);
    }
  };
  const queueBulkAssessments = async () => {
    if (!selectedIds.length || selectedIds.length > 100) return;
    setBulkWorking(true);
    setBulkError("");
    setBulkNotice("");
    let queuedCount = 0;
    try {
      const chunks: string[][] = [];
      for (let index = 0; index < selectedIds.length; index += 25)
        chunks.push(selectedIds.slice(index, index + 25));
      for (const alertIds of chunks) {
        await api.queueAIJob("bulk_alert_assessment", {
          alert_ids: alertIds,
        });
        queuedCount += alertIds.length;
      }
      setSelectedIds([]);
      setBulkNotice(
        `${queuedCount} AI assessments queued in ${chunks.length} background ${chunks.length === 1 ? "task" : "tasks"}.`,
      );
    } catch (reason) {
      if (queuedCount)
        setSelectedIds((current) => current.slice(queuedCount));
      setBulkError(
        `${queuedCount ? `${queuedCount} assessments were queued before the failure. ` : ""}${reason instanceof Error ? reason.message : "Bulk AI assessment could not be queued"}`,
      );
    } finally {
      setBulkWorking(false);
    }
  };
  const recordBulkFalsePositives = async () => {
    if (!selectedIds.length || selectedIds.length > 100) return;
    setBulkWorking(true);
    setBulkError("");
    setBulkNotice("");
    try {
      const result = await api.bulkMarkFalsePositive(
        selectedIds,
        bulkFalsePositiveCategory,
        bulkNote || "Analyst marked these alerts as false matches",
      );
      setSelectedIds(result.failures.map((failure) => failure.alert_id));
      setBulkNote("");
      setBulkNotice(
        result.failed
          ? `${result.recorded} false matches stored; ${result.failed} failed and remain selected.`
          : `${result.recorded} false matches dismissed and stored for future retrieval.`,
      );
      const recordedIds = new Set(result.recorded_alert_ids);
      setLiveAlerts((current) =>
        current.map((alert) =>
          recordedIds.has(alert.id)
            ? { ...alert, status: "dismissed" as AlertStatus }
            : alert,
        ),
      );
      await onUpdated();
    } catch (reason) {
      setBulkError(
        reason instanceof Error
          ? reason.message
          : "Bulk false-match feedback could not be stored",
      );
    } finally {
      setBulkWorking(false);
    }
  };
  return (
    <div>
      <PageIntro
        eyebrow="Analyst workbench"
        title="Alerts and review"
        description="Triage direct client matches and uncertain review items in one workflow, with client, industry, and geography filtering."
      />
      <div className="mt-7 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        {(
          [
            "new",
            "investigating",
            "client_notified",
            "monitoring",
            "resolved",
            "dismissed",
          ] as AlertStatus[]
        ).map((status) => (
          <motion.div
            layout
            key={status}
            className="flex min-h-20 min-w-0 items-center justify-between gap-3 rounded-2xl border border-zinc-200 bg-white p-4 transition-shadow duration-300"
          >
            <AlertStatusBadge status={status} />
            <motion.p
              key={`${status}-${statusCounts[status] || 0}`}
              initial={{ opacity: 0.45, y: 3 }}
              animate={{ opacity: 1, y: 0 }}
              className="shrink-0 font-mono text-2xl font-medium tabular-nums"
            >
              {statusCounts[status] || 0}
            </motion.p>
          </motion.div>
        ))}
      </div>
      <section className="mt-7 rounded-2xl border border-zinc-200 bg-white p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div
            className="flex flex-wrap gap-2"
            role="group"
            aria-label="Alert workflow filters"
          >
            {(["open", "review", "all", "closed"] as const).map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => setFilter(value)}
                className={`filter-pill ${filter === value ? "filter-pill-active" : ""}`}
              >
                {value === "open"
                  ? "Open workflow"
                  : value === "review"
                    ? `Human review (${reviewCount})`
                    : value === "closed"
                      ? "Closed"
                      : "All alerts"}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="text-xs font-semibold text-teal-800 disabled:text-zinc-300"
            disabled={!industry && !geography && !clientId}
            onClick={() => {
              setIndustry("");
              setGeography("");
              setClientId("");
            }}
          >
            Clear filters
          </button>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <SearchableSelect
            ariaLabel="Filter client"
            value={clientId}
            onChange={setClientId}
            options={[
              { value: "", label: "All clients" },
              ...clients.map(([value, label]) => ({ value, label })),
            ]}
          />
          <SearchableSelect
            ariaLabel="Filter industry"
            value={industry}
            onChange={setIndustry}
            options={[
              { value: "", label: "All industries" },
              ...industries.map((value) => ({ value, label: value })),
            ]}
          />
          <SearchableSelect
            ariaLabel="Filter geography"
            value={geography}
            onChange={setGeography}
            options={[
              { value: "", label: "All geographies" },
              ...geographies.map((value) => ({ value, label: value })),
            ]}
          />
        </div>
      </section>
      {filtered.length > 0 && (
        <section className="mt-5 rounded-2xl border border-zinc-200 bg-white p-4">
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              role="checkbox"
              aria-checked={allFilteredSelected}
              onClick={toggleAllFiltered}
              className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-zinc-200 px-3 text-sm text-zinc-700 transition hover:bg-zinc-50"
            >
              <span
                className={`grid h-5 w-5 place-items-center rounded-md border ${allFilteredSelected ? "border-teal-700 bg-teal-700 text-white" : "border-zinc-300 bg-white"}`}
              >
                {allFilteredSelected && <Check size={14} weight="bold" />}
              </span>
              Select filtered ({filtered.length})
            </button>
            <span className="text-xs text-zinc-500">
              {selectedIds.length
                ? `${selectedIds.length} selected`
                : "Select alerts for status changes or AI-assisted triage"}
            </span>
            {selectedIds.length > 0 && (
              <button
                type="button"
                onClick={() => setSelectedIds([])}
                className="ml-auto text-xs font-medium text-zinc-500 hover:text-zinc-900"
              >
                Clear selection
              </button>
            )}
          </div>
          {selectedIds.length > 0 && (
            <div className="mt-4 grid gap-3 border-t border-zinc-100 pt-4 lg:grid-cols-2 xl:grid-cols-[minmax(12rem,.7fr)_minmax(14rem,1fr)_auto_auto]">
              <CustomSelect
                ariaLabel="Bulk alert status"
                value={bulkStatus}
                onChange={(value) =>
                  setBulkStatus(value as AlertStatus)
                }
                options={[
                  { value: "new", label: "Mark new" },
                  { value: "investigating", label: "Start investigation" },
                  { value: "client_notified", label: "Mark client notified" },
                  { value: "monitoring", label: "Move to monitoring" },
                  { value: "resolved", label: "Mark resolved" },
                  { value: "dismissed", label: "Dismiss" },
                ]}
              />
              <input
                className="input"
                value={bulkNote}
                maxLength={500}
                onChange={(event) => setBulkNote(event.target.value)}
                placeholder="Optional analyst note for every selected alert"
                aria-label="Bulk alert note"
              />
              <button
                type="button"
                disabled={bulkWorking}
                onClick={() => void applyBulkStatus()}
                className="button-secondary justify-center whitespace-nowrap"
              >
                {bulkWorking ? (
                  <SpinnerGap size={17} className="animate-spin" />
                ) : (
                  <CheckCircle size={17} />
                )}
                Apply status
              </button>
              <button
                type="button"
                disabled={bulkWorking || selectedIds.length > 100}
                onClick={() => void queueBulkAssessments()}
                className="button-primary justify-center whitespace-nowrap !bg-violet-700"
                title={
                  selectedIds.length > 100
                    ? "Select no more than 100 alerts for one bulk AI run"
                    : "Queue background AI assessments in batches of 25"
                }
              >
                <Cpu size={17} />
                AI assess selected
              </button>
              {selectedIds.length > 100 && (
                <p className="text-xs text-amber-700 lg:col-span-4">
                  Bulk AI and false-match recording are capped at 100 alerts per
                  action. Status operations can still be applied to the full
                  selection.
                </p>
              )}
              {bulkStatus === "dismissed" && (
                <div className="grid gap-3 rounded-xl border border-amber-200 bg-amber-50/50 p-3 lg:col-span-2 xl:col-span-4 xl:grid-cols-[minmax(12rem,.7fr)_minmax(0,1fr)_auto] xl:items-center">
                  <CustomSelect
                    ariaLabel="Bulk false-positive category"
                    value={bulkFalsePositiveCategory}
                    onChange={setBulkFalsePositiveCategory}
                    options={[
                      { value: "unrelated_organization", label: "Unrelated organization" },
                      { value: "ambiguous_name", label: "Ambiguous company name" },
                      { value: "stale_or_duplicate", label: "Stale or duplicate claim" },
                      { value: "incorrect_context", label: "Incorrect context" },
                      { value: "other", label: "Other" },
                    ]}
                  />
                  <p className="text-xs leading-5 text-zinc-600">
                    Save the dismissal context as retrieval-ready analyst
                    feedback so similar future matches can be flagged for review.
                  </p>
                  <button
                    type="button"
                    disabled={bulkWorking || selectedIds.length > 100}
                    onClick={() => void recordBulkFalsePositives()}
                    className="button-secondary justify-center whitespace-nowrap !border-amber-300 text-amber-900"
                  >
                    <XCircle size={17} />
                    Dismiss + remember
                  </button>
                </div>
              )}
            </div>
          )}
          {bulkError && <InlineNotice tone="danger">{bulkError}</InlineNotice>}
          {bulkNotice && <InlineNotice tone="neutral">{bulkNotice}</InlineNotice>}
        </section>
      )}
      {filtered.length ? (
        <div className="mt-6 overflow-hidden rounded-2xl border border-zinc-200 bg-white">
          <AnimatePresence initial={false}>
            {filtered.map((alert, index) => (
              <motion.div
                layout
                key={alert.id}
                initial={{ opacity: 0, y: 5 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.22 }}
                className={`flex items-stretch transition-colors duration-300 ${index > 0 ? "border-t border-zinc-200" : ""} ${selectedIds.includes(alert.id) ? "bg-teal-50/50" : alert.severity === "review" && alert.status === "new" ? "bg-amber-50/45" : ""}`}
              >
                <div className="flex shrink-0 items-center px-3 sm:px-4">
                  <button
                    type="button"
                    role="checkbox"
                    aria-checked={selectedIds.includes(alert.id)}
                    aria-label={`Select ${alert.claim_title}`}
                    onClick={() => toggleSelected(alert.id)}
                    className={`grid h-6 w-6 place-items-center rounded-md border transition ${selectedIds.includes(alert.id) ? "border-teal-700 bg-teal-700 text-white" : "border-zinc-300 bg-white hover:border-teal-600"}`}
                  >
                    {selectedIds.includes(alert.id) && (
                      <Check size={15} weight="bold" />
                    )}
                  </button>
                </div>
                <button
                  type="button"
                  className="min-w-0 flex-1 text-left"
                  onClick={() => setSelected(alert)}
                >
                  <AlertRow alert={alert} />
                </button>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      ) : (
        <EmptyState
          title="Nothing needs attention"
          description="There are no alerts matching this workflow and filter combination."
          icon={<CheckCircle size={30} />}
        />
      )}
      <AnimatePresence>
        {selected && (
          <AlertDrawer
            alert={selected}
            onClose={() => setSelected(null)}
            onUpdated={async (updated) => {
              if (updated) {
                setSelected(updated);
                setLiveAlerts((current) =>
                  current.map((alert) =>
                    alert.id === updated.id ? updated : alert,
                  ),
                );
              }
              await onUpdated();
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
function AlertDrawer({
  alert,
  onClose,
  onUpdated,
}: {
  alert: Alert;
  onClose: () => void;
  onUpdated: (updated?: Alert) => Promise<void>;
}) {
  const reducedMotion = useReducedMotion();
  const [working, setWorking] = useState(false);
  const [status, setStatus] = useState<AlertStatus>(alert.status);
  const [note, setNote] = useState(alert.note || "");
  const [draft, setDraft] = useState<NotificationDraft | null>(null);
  const [context, setContext] = useState<AlertIntelligenceContext | null>(null);
  const [contextLoading, setContextLoading] = useState(true);
  const [draftMode, setDraftMode] = useState<"ai" | "standard" | "">("");
  const [confirmAIDraft, setConfirmAIDraft] = useState(false);
  const [confirmFalsePositive, setConfirmFalsePositive] = useState(false);
  const [falsePositiveCategory, setFalsePositiveCategory] = useState(
    "unrelated_organization",
  );
  const [captureWorking, setCaptureWorking] = useState(false);
  const [assessmentWorking, setAssessmentWorking] = useState(false);
  const [assessmentQueued, setAssessmentQueued] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    setContextLoading(true);
    void api
      .alertIntelligenceContext(alert.id)
      .then(setContext)
      .catch((reason) =>
        setError(
          reason instanceof Error
            ? reason.message
            : "Alert intelligence context could not be loaded",
        ),
      )
      .finally(() => setContextLoading(false));
  }, [alert.id]);
  const act = async (nextStatus: AlertStatus, nextNote = note) => {
    setWorking(true);
    setError("");
    try {
      const updated = await api.updateAlert(alert.id, nextStatus, nextNote);
      setStatus(updated.status);
      setNote(updated.note || "");
      await onUpdated(updated);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Alert status could not be updated",
      );
    } finally {
      setWorking(false);
    }
  };
  const openDraft = async (mode: "ai" | "standard") => {
    setWorking(true);
    setDraftMode(mode);
    setError("");
    try {
      if (mode === "ai")
        await api.queueAIJob("alert_notification_draft", {
          alert_id: alert.id,
        });
      else {
        const saved = await api.notificationDraft(alert.id);
        setDraft(saved);
        setContext((current) =>
          current
            ? { ...current, saved_drafts: [saved, ...current.saved_drafts] }
            : current,
        );
      }
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Draft could not be created",
      );
    } finally {
      setWorking(false);
      setDraftMode("");
    }
  };
  const queueEvidenceCapture = async () => {
    setCaptureWorking(true);
    setError("");
    try {
      const job = await api.queueAlertCapture(alert.id);
      setContext((current) =>
        current
          ? { ...current, capture_jobs: [job, ...current.capture_jobs] }
          : current,
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Focused evidence capture could not be queued",
      );
    } finally {
      setCaptureWorking(false);
    }
  };
  const queueAssessment = async () => {
    setAssessmentWorking(true);
    setError("");
    try {
      await api.queueAIJob("alert_assessment", { alert_id: alert.id });
      setAssessmentQueued(true);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "AI alert assessment could not be queued",
      );
    } finally {
      setAssessmentWorking(false);
    }
  };
  const markFalsePositive = async () => {
    setWorking(true);
    setError("");
    try {
      const result = await api.markFalsePositive(
        alert.id,
        falsePositiveCategory,
        note || "Analyst marked this as an unrelated match",
      );
      setConfirmFalsePositive(false);
      setStatus(result.alert.status);
      await onUpdated(result.alert);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "False-positive feedback could not be saved",
      );
    } finally {
      setWorking(false);
    }
  };
  const professionalProfile = resolveProfessionalProfile(
    context?.actor_profile,
  );
  const latestAssessment: AlertAIAssessment | undefined =
    context?.ai_assessments?.[0];
  return (
    <>
      <motion.div
        className="fixed inset-0 z-30 bg-zinc-950/30 backdrop-blur-sm"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      >
        <motion.aside
          className="absolute inset-y-0 right-0 w-full max-w-4xl overflow-y-auto bg-[#f8faf9] p-5 shadow-2xl sm:p-8 lg:p-10"
          initial={{ x: reducedMotion ? 0 : "100%" }}
          animate={{ x: 0 }}
          exit={{ x: reducedMotion ? 0 : "100%" }}
          transition={{ type: "spring", stiffness: 160, damping: 24 }}
          onClick={(event) => event.stopPropagation()}
          aria-label="Alert details"
        >
          <div className="flex items-start justify-between gap-5">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={alert.severity} />
                <AlertStatusBadge status={alert.status} />
              </div>
              <h2 className="mt-4 text-3xl font-semibold tracking-tight">
                {alert.claim_title}
              </h2>
              <p className="mt-2 text-zinc-500">
                Public ransomware claim by {alert.threat_actor}
              </p>
            </div>
            <button
              type="button"
              className="icon-button"
              onClick={onClose}
              aria-label="Close alert details"
            >
              <X size={20} />
            </button>
          </div>
          <InlineNotice tone="neutral">
            This is an unverified threat-actor allegation, not confirmation of a
            breach.
          </InlineNotice>
          <div className="mt-7 grid gap-4 sm:grid-cols-2">
            <DetailBlock label="Matched client" value={alert.client_name} />
            <DetailBlock label="Why it matched" value={alert.reason} />
            <DetailBlock
              label="Confidence"
              value={`${alert.score} / 100`}
              mono
            />
            <DetailBlock
              label="Victim named / published"
              value={
                context?.published_at
                  ? formatTime(context.published_at)
                  : alert.published_at
                    ? formatTime(alert.published_at)
                    : "Not supplied by source"
              }
            />
            <DetailBlock
              label="Ingested locally"
              value={formatTime(
                context?.ingested_at || alert.received_at || alert.created_at,
              )}
            />
          </div>
          <section className="mt-8">
            <p className="eyebrow">Evidence from the source</p>
            <blockquote className="mt-3 rounded-2xl border border-zinc-200 bg-white p-5 text-sm leading-7 text-zinc-700">
              {alert.evidence ||
                "The source did not include a separate description."}
            </blockquote>
          </section>
          <section className="mt-8 border-t border-zinc-200 pt-7">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="eyebrow !text-violet-700">
                  AI-assisted alert assessment
                </p>
                <h3 className="mt-2 text-lg font-semibold">
                  Named-victim and alert relevance
                </h3>
                <p className="mt-2 max-w-2xl text-xs leading-5 text-zinc-500">
                  Uses the canonical organization profile, supplied incident
                  evidence, match rationale and sourced actor CTI. Deterministic
                  matching remains authoritative.
                </p>
              </div>
              <button
                type="button"
                disabled={assessmentWorking}
                onClick={() => void queueAssessment()}
                className="button-primary shrink-0 !bg-violet-700"
              >
                {assessmentWorking ? (
                  <SpinnerGap size={17} className="animate-spin" />
                ) : (
                  <Cpu size={17} />
                )}
                {latestAssessment ? "Refresh assessment" : "AI assess alert"}
              </button>
            </div>
            {assessmentQueued && !latestAssessment && (
              <InlineNotice tone="neutral">
                Assessment queued in the background. The AI task centre will
                notify you when the saved result is ready.
              </InlineNotice>
            )}
            {latestAssessment ? (
              <AlertAssessmentView assessment={latestAssessment} />
            ) : !assessmentQueued && !contextLoading ? (
              <div className="mt-5 rounded-2xl border border-dashed border-violet-200 bg-violet-50/30 p-5 text-sm leading-6 text-zinc-500">
                No AI assessment has been saved for this alert. Starting one
                will enrich the named victim first when its organization
                profile has not previously been enriched.
              </div>
            ) : null}
          </section>
          <section className="mt-8 border-t border-zinc-200 pt-7">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="eyebrow">Threat-actor profile</p>
                <h3 className="mt-2 text-lg font-semibold">
                  {alert.threat_actor}
                </h3>
              </div>
              {professionalProfile && (
                <span className="rounded-full bg-zinc-200 px-2.5 py-1 text-[10px] font-bold uppercase text-zinc-600">
                  {professionalProfile.source_confidence} source confidence
                </span>
              )}
            </div>
            {contextLoading ? (
              <LoadingStatusCard
                title="Loading sourced actor profile"
                description="Retrieving the retained CTI context for this alert."
                className="mt-4 max-w-lg"
              />
            ) : context?.actor_profile ? (
              <div className="mt-4 rounded-2xl border border-zinc-200 bg-white p-5">
                <p className="text-sm leading-7 text-zinc-700">
                  {professionalProfile?.summary ||
                    "No externally sourced actor profile is currently available."}
                </p>
                {professionalProfile && (
                  <>
                    <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2 text-[11px] leading-5 text-zinc-500">
                      <span>
                        Sources: {professionalProfile.sources.join(", ") || "Local actor-label registry"}
                      </span>
                      {professionalProfile.generated_at && (
                        <span>
                          Refreshed {formatTime(professionalProfile.generated_at)}
                        </span>
                      )}
                    </div>
                    {(professionalProfile.motivation ||
                      professionalProfile.targeting ||
                      professionalProfile.capabilities ||
                      professionalProfile.campaign_history) && (
                      <dl className="mt-5 grid gap-3 border-t border-zinc-100 pt-5 sm:grid-cols-2">
                        <ProfileText
                          label="Motivation"
                          value={professionalProfile.motivation || "Not established in retained OSINT."}
                          evidenceCount={professionalProfile.field_evidence?.motivation?.length}
                        />
                        <ProfileText
                          label="Targeting"
                          value={professionalProfile.targeting || "Not established in retained OSINT."}
                          evidenceCount={professionalProfile.field_evidence?.targeting?.length}
                        />
                        <ProfileText
                          label="Capabilities"
                          value={professionalProfile.capabilities || "Not established in retained OSINT."}
                          evidenceCount={professionalProfile.field_evidence?.capabilities?.length}
                        />
                        <ProfileText
                          label="Campaign history"
                          value={professionalProfile.campaign_history || "Not established in retained OSINT."}
                          evidenceCount={professionalProfile.field_evidence?.campaign_history?.length}
                        />
                      </dl>
                    )}
                    {professionalProfile.identity.attack_id && (
                      <div className="mt-5 rounded-xl bg-teal-50 p-4 text-xs leading-6 text-zinc-600">
                        <span className="text-teal-900">
                          {professionalProfile.identity.canonical_name} · {professionalProfile.identity.attack_id}
                        </span>
                        {professionalProfile.identity.aliases.length > 0 && (
                          <span> · Aliases: {professionalProfile.identity.aliases.join(", ")}</span>
                        )}
                        <span>
                          {" "}· {professionalProfile.technique_count} techniques · {professionalProfile.software_count} software entries · {professionalProfile.campaign_count} campaigns
                        </span>
                      </div>
                    )}
                  </>
                )}
                <details className="mt-5 border-t border-zinc-100 pt-4">
                  <summary className="cursor-pointer text-xs font-medium text-zinc-600">
                    Local observation layer · {context.actor_profile.claim_count} unverified claims
                  </summary>
                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <ProfileList
                      title="Observed industries"
                      items={context.actor_profile.top_industries}
                    />
                    <ProfileList
                      title="Observed geographies"
                      items={context.actor_profile.top_countries}
                    />
                  </div>
                  <p className="mt-4 text-[11px] leading-5 text-zinc-400">
                    {context.actor_profile.caveat}
                  </p>
                </details>
              </div>
            ) : (
              <p className="mt-4 text-sm text-zinc-500">
                No actor profile is available for this observation period.
              </p>
            )}
          </section>
          {context?.false_positive_precedents.length ? (
            <section className="mt-8 border-t border-zinc-200 pt-7">
              <p className="eyebrow">Analyst-feedback retrieval</p>
              <h3 className="mt-2 text-lg font-semibold">
                Similar prior false positives
              </h3>
              <InlineNotice tone="neutral">
                These are local lexical retrieval hints, not automated dismissal
                decisions. Review the underlying evidence before changing this
                alert.
              </InlineNotice>
              <div className="mt-4 space-y-3">
                {context.false_positive_precedents.map((item) => (
                  <div
                    key={item.feedback_id}
                    className="rounded-2xl border border-amber-200 bg-amber-50/60 p-4"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-xs font-bold uppercase tracking-wide text-amber-800">
                        {item.category.replaceAll("_", " ")}
                      </p>
                      <span className="font-mono text-xs text-amber-900">
                        {Math.round(item.similarity * 100)}% lexical overlap
                      </span>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-zinc-700">
                      {item.analyst_note}
                    </p>
                    <p className="mt-2 text-[10px] text-zinc-500">
                      Recorded {formatTime(item.created_at)} ·{" "}
                      {item.retrieval_basis}
                    </p>
                  </div>
                ))}
              </div>
            </section>
          ) : null}
          <section className="mt-8 border-t border-zinc-200 pt-7">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="eyebrow">Direct-site evidence</p>
                <h3 className="mt-2 text-lg font-semibold">
                  Capture the flagged victim listing
                </h3>
                <p className="mt-2 max-w-2xl text-xs leading-5 text-zinc-500">
                  Queues a read-only, Tor-isolated capture against an already
                  allowlisted site for this actor. The worker searches only
                  visible victim-list content, never forms, authentication,
                  downloads, or cross-origin links.
                </p>
              </div>
              <button
                type="button"
                disabled={captureWorking}
                onClick={() => void queueEvidenceCapture()}
                className="button-secondary whitespace-nowrap"
              >
                {captureWorking ? (
                  <SpinnerGap className="animate-spin" size={18} />
                ) : (
                  <Camera size={18} />
                )}
                Capture DLS evidence
              </button>
            </div>
            {context?.capture_jobs.length ? (
              <div className="mt-4 space-y-2">
                {context.capture_jobs.slice(0, 4).map((job) => (
                  <div
                    key={job.id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-zinc-200 bg-white px-4 py-3 text-xs"
                  >
                    <div>
                      <p className="font-semibold">
                        {job.group_name} · {job.status.replaceAll("_", " ")}
                      </p>
                      <p className="mt-1 text-zinc-500">
                        Requested {formatTime(job.requested_at)}
                        {job.victim_match_found
                          ? " · victim text located"
                          : job.status === "completed"
                            ? " · victim text not located in captured list"
                            : ""}
                      </p>
                    </div>
                    {job.status === "completed" && job.segment_count > 0 && (
                      <a
                        className="font-semibold text-teal-800 underline underline-offset-2"
                        href={api.captureScreenshotUrl(job.id, 1)}
                        target="_blank"
                        rel="noreferrer"
                      >
                        Open evidence
                      </a>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-4 text-xs text-zinc-500">
                No focused evidence capture has been linked to this alert.
              </p>
            )}
          </section>
          <section className="mt-8 border-t border-zinc-200 pt-7">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="eyebrow">Saved communications</p>
                <h3 className="mt-2 text-lg font-semibold">
                  Client email drafts
                </h3>
              </div>
              <span className="rounded-full bg-zinc-200 px-3 py-1 text-xs font-semibold text-zinc-600">
                {context?.saved_drafts.length || 0} saved
              </span>
            </div>
            {context?.saved_drafts.length ? (
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                {context.saved_drafts.map((item) => (
                  <button
                    type="button"
                    key={item.id}
                    onClick={() => setDraft(item)}
                    className="rounded-2xl border border-zinc-200 bg-white p-4 text-left transition hover:border-teal-300"
                  >
                    <p className="line-clamp-2 text-sm font-semibold">
                      {item.subject}
                    </p>
                    <p className="mt-2 text-xs text-zinc-500">
                      {item.generated_by} · updated{" "}
                      {formatTime(item.updated_at)}
                    </p>
                  </button>
                ))}
              </div>
            ) : (
              <p className="mt-4 text-xs text-zinc-500">
                Create a standard or AI-assisted draft below. Every generated
                draft is preserved locally for this client alert.
              </p>
            )}
          </section>
          <section className="mt-8 border-t border-zinc-200 pt-7">
            <h3 className="text-lg font-semibold">Recommended next steps</h3>
            <ol className="mt-4 space-y-3 text-sm text-zinc-600">
              <li className="flex gap-3">
                <StepNumber value="1" />
                Notify the client incident contact through an approved channel.
              </li>
              <li className="flex gap-3">
                <StepNumber value="2" />
                Check for independent confirmation and relevant internal
                telemetry.
              </li>
              <li className="flex gap-3">
                <StepNumber value="3" />
                Record investigation notes without treating the allegation as
                confirmed.
              </li>
            </ol>
          </section>
          <section className="mt-8 border-t border-zinc-200 pt-7">
            <h3 className="text-lg font-semibold">Workflow status</h3>
            <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_auto]">
              <CustomSelect
                ariaLabel="Workflow status"
                value={status}
                onChange={(value) => setStatus(value as AlertStatus)}
                options={(
                  [
                    "new",
                    "investigating",
                    "client_notified",
                    "monitoring",
                    "resolved",
                    "dismissed",
                  ] as AlertStatus[]
                ).map((value) => ({ value, label: alertStatusLabel(value) }))}
              />
              <button
                type="button"
                disabled={working || status === alert.status}
                onClick={() => void act(status)}
                className="button-primary"
              >
                Save status
              </button>
            </div>
            <textarea
              className="input mt-3 min-h-24 resize-y"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              maxLength={500}
              placeholder="Investigation note or client response…"
            />
            {alert.notified_at && (
              <p className="mt-2 text-xs text-zinc-500">
                Client-notified status first recorded{" "}
                {formatTime(alert.notified_at)}.
              </p>
            )}
          </section>
          {error && <InlineNotice tone="danger">{error}</InlineNotice>}
          <div className="mt-8 grid grid-cols-1 gap-3 border-t border-zinc-200 pt-6 sm:grid-cols-2 lg:grid-cols-4">
            <button
              type="button"
              disabled={working}
              onClick={() => setConfirmAIDraft(true)}
              className="button-primary justify-center whitespace-nowrap"
            >
              {draftMode === "ai" ? (
                <SpinnerGap className="animate-spin" size={18} />
              ) : (
                <Cpu size={18} />
              )}
              AI draft email
            </button>
            <button
              type="button"
              disabled={working}
              onClick={() => void openDraft("standard")}
              className="button-secondary justify-center whitespace-nowrap"
            >
              {draftMode === "standard" ? (
                <SpinnerGap className="animate-spin" size={18} />
              ) : (
                <EnvelopeSimple size={18} />
              )}
              Standard draft
            </button>
            <button
              type="button"
              disabled={working}
              onClick={() =>
                void act("investigating", note || "Investigation started")
              }
              className="button-secondary justify-center whitespace-nowrap"
            >
              <Check size={18} />
              Start investigation
            </button>
            <button
              type="button"
              disabled={working}
              onClick={() => setConfirmFalsePositive(true)}
              className="button-secondary justify-center whitespace-nowrap"
            >
              <XCircle size={18} />
              False match
            </button>
          </div>
        </motion.aside>
      </motion.div>
      {confirmAIDraft && (
        <Modal
          title="Share sanitized alert context with the AI provider?"
          description="The platform replaces the monitored client identity before requesting a scenario-specific draft."
          onClose={() => setConfirmAIDraft(false)}
        >
          <InlineNotice tone="neutral">
            The client name, primary domain, aliases, and direct-match
            references are replaced with MONITORED_CLIENT before leaving the
            platform. The real client name is restored locally after the draft
            returns.
          </InlineNotice>
          <p className="mt-5 text-xs leading-5 text-zinc-500">
            The request still includes generalized monitoring regions and
            industries, the public claim, timestamps, match type, and locally
            observed threat-actor statistics. It never includes DLS addresses or
            leaked material. Choose the standard draft if no alert context may
            leave the platform.
          </p>
          <div className="mt-6 flex flex-wrap justify-end gap-3">
            <button
              type="button"
              className="button-secondary"
              onClick={() => setConfirmAIDraft(false)}
            >
              Cancel
            </button>
            <button
              type="button"
              className="button-primary"
              onClick={() => {
                setConfirmAIDraft(false);
                void openDraft("ai");
              }}
            >
              <Cpu size={18} />
              Continue with sanitized draft
            </button>
          </div>
        </Modal>
      )}
      {confirmFalsePositive && (
        <Modal
          title="Record this false positive?"
          description="The alert will be dismissed and its decision context stored as a retrieval-ready analyst-feedback record."
          onClose={() => setConfirmFalsePositive(false)}
        >
          <InlineNotice tone="neutral">
            Future retrieval may warn analysts about similar decisions, but it
            will never dismiss an alert automatically. Client, claim, and match
            snapshots remain local.
          </InlineNotice>
          <div className="mt-5">
            <Field label="False-positive category">
              <CustomSelect
                ariaLabel="False-positive category"
                value={falsePositiveCategory}
                onChange={setFalsePositiveCategory}
                options={[
                  {
                    value: "unrelated_organization",
                    label: "Unrelated organization",
                  },
                  { value: "ambiguous_name", label: "Ambiguous company name" },
                  {
                    value: "stale_or_duplicate",
                    label: "Stale or duplicate claim",
                  },
                  {
                    value: "incorrect_context",
                    label: "Incorrect industry or geography context",
                  },
                  { value: "other", label: "Other" },
                ]}
              />
            </Field>
          </div>
          <label className="mt-5 block">
            <span className="text-sm font-semibold text-zinc-800">
              Analyst rationale
            </span>
            <textarea
              className="input mt-2 min-h-28 resize-y"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Explain why this match is not relevant so future retrieval has useful context."
              maxLength={2000}
            />
          </label>
          <div className="mt-6 flex flex-wrap justify-end gap-3">
            <button
              type="button"
              className="button-secondary"
              onClick={() => setConfirmFalsePositive(false)}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={working}
              className="button-primary"
              onClick={() => void markFalsePositive()}
            >
              {working ? (
                <SpinnerGap className="animate-spin" size={18} />
              ) : (
                <XCircle size={18} />
              )}
              Dismiss and save feedback
            </button>
          </div>
        </Modal>
      )}
      {draft && (
        <NotificationDraftDialog
          draft={draft}
          onClose={() => setDraft(null)}
          onSave={async (subject, body) => {
            const saved = await api.saveNotificationDraft(
              alert.id,
              draft.id,
              subject,
              body,
            );
            setDraft(saved);
            setContext((current) =>
              current
                ? {
                    ...current,
                    saved_drafts: current.saved_drafts.map((item) =>
                      item.id === saved.id ? saved : item,
                    ),
                  }
                : current,
            );
          }}
          onMarkNotified={async () => {
            const updated = await api.updateAlert(
              alert.id,
              "client_notified",
              note || "Analyst confirmed client notification",
            );
            setDraft(null);
            setStatus(updated.status);
            await onUpdated(updated);
          }}
        />
      )}
    </>
  );
}

function NotificationDraftDialog({
  draft,
  onClose,
  onSave,
  onMarkNotified,
}: {
  draft: NotificationDraft;
  onClose: () => void;
  onSave: (subject: string, body: string) => Promise<void>;
  onMarkNotified: () => Promise<void>;
}) {
  const [subject, setSubject] = useState(draft.subject);
  const [body, setBody] = useState(draft.body);
  const [copied, setCopied] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const copy = async () => {
    const content = `Subject: ${subject}\n\n${body}`;
    setError("");
    try {
      if (navigator.clipboard?.writeText)
        await navigator.clipboard.writeText(content);
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
        setError(
          "Your browser blocked clipboard access. Select the message and copy it manually.",
        );
        return;
      }
    }
    setCopied(true);
  };
  const openEmailApp = () =>
    window.location.assign(
      `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`,
    );
  const markNotified = async () => {
    setWorking(true);
    setError("");
    try {
      await onMarkNotified();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Alert status could not be updated",
      );
      setWorking(false);
    }
  };
  const save = async () => {
    setWorking(true);
    setError("");
    try {
      await onSave(subject, body);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Draft could not be saved",
      );
    } finally {
      setWorking(false);
    }
  };
  return (
    <motion.div
      className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-zinc-950/45 p-4 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        className="my-8 w-full max-w-3xl rounded-[2rem] bg-white p-6 shadow-2xl sm:p-8"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="eyebrow">Client communication</p>
            <h2 className="mt-2 text-2xl font-semibold">
              Review notification draft
            </h2>
            <p className="mt-2 text-sm text-zinc-500">{draft.disclaimer}</p>
          </div>
          <button type="button" className="icon-button" onClick={onClose}>
            <X size={19} />
          </button>
        </div>
        <div className="mt-6">
          <Field label="Subject">
            <input
              className="input"
              value={subject}
              onChange={(event) => {
                setSubject(event.target.value);
                setCopied(false);
              }}
            />
          </Field>
        </div>
        <label className="mt-5 block">
          <span className="text-sm font-semibold text-zinc-800">Message</span>
          <textarea
            className="input mt-2 min-h-[25rem] resize-y font-mono text-xs leading-6"
            value={body}
            onChange={(event) => {
              setBody(event.target.value);
              setCopied(false);
            }}
          />
        </label>
        {error && <InlineNotice tone="danger">{error}</InlineNotice>}
        <p className="mt-4 text-xs leading-5 text-zinc-500">
          This draft is stored locally for the client alert. Opening your email
          app does not send anything.
        </p>
        <div className="mt-6 flex flex-wrap justify-end gap-3">
          <button
            type="button"
            className="button-secondary"
            onClick={() => void copy()}
          >
            {copied ? <Check size={18} /> : <EnvelopeSimple size={18} />}
            {copied ? "Copied" : "Copy draft"}
          </button>
          <button
            type="button"
            disabled={working}
            className="button-secondary"
            onClick={() => void save()}
          >
            {working ? (
              <SpinnerGap className="animate-spin" size={18} />
            ) : (
              <Check size={18} />
            )}
            Save draft
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={openEmailApp}
          >
            <EnvelopeSimple size={18} />
            Open in email app
          </button>
          <button
            type="button"
            disabled={working}
            className="button-primary"
            onClick={() => void markNotified()}
          >
            {working ? (
              <SpinnerGap className="animate-spin" size={18} />
            ) : (
              <Check size={18} />
            )}
            Mark as notified
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

function ClientsPage({
  clients,
  onCreated,
}: {
  clients: Client[];
  onCreated: () => Promise<void>;
}) {
  const [editing, setEditing] = useState<Client | null | undefined>(undefined);
  const [deleting, setDeleting] = useState<Client | null>(null);
  return (
    <div>
      <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <PageIntro
          eyebrow="Watchlist"
          title="Clients"
          description="Organizations, markets, industries, subsidiaries, and third parties monitored for public ransomware claims."
        />
        <button
          type="button"
          onClick={() => setEditing(null)}
          className="button-primary"
        >
          <Plus size={18} />
          Add client
        </button>
      </div>
      <div className="mt-8 overflow-hidden rounded-2xl border border-zinc-200 bg-white">
        <div className="hidden grid-cols-[1.35fr_1fr_1fr_.7fr_auto] items-center gap-4 border-b border-zinc-200 bg-zinc-50 px-5 py-3 text-xs font-medium uppercase tracking-wide text-zinc-500 sm:grid">
          <span>Organization</span>
          <span>Markets and sectors</span>
          <span>Relationships</span>
          <span>Priority</span>
          <span className="text-right">Actions</span>
        </div>
        {clients.map((client, index) => (
          <div
            key={client.id}
            className={`grid gap-4 p-5 sm:grid-cols-[1.35fr_1fr_1fr_.7fr_auto] sm:items-center ${index ? "border-t border-zinc-200" : ""}`}
          >
            <div>
              <p className="font-semibold">{client.canonical_name}</p>
              <p className="mt-1 font-mono text-xs text-zinc-500">
                {client.primary_domain}
              </p>
              {client.description && (
                <p className="mt-2 line-clamp-2 text-xs leading-5 text-zinc-500">
                  {client.description}
                </p>
              )}
            </div>
            <div>
              <p className="text-sm text-zinc-700">
                {summarizeValues(
                  [...client.countries, ...client.cities],
                  "Markets not set",
                )}
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                {summarizeValues(client.industries, "Industries not set")}
              </p>
            </div>
            <div>
              <p className="text-sm text-zinc-600">
                {client.related_entities.length
                  ? `${client.related_entities.length} related ${client.related_entities.length === 1 ? "organization" : "organizations"}`
                  : "No related organizations"}
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                {client.keywords.length
                  ? `${client.keywords.length} alert ${client.keywords.length === 1 ? "keyword" : "keywords"}`
                  : "No alert keywords"}
              </p>
            </div>
            <PriorityBadge priority={client.priority} />
            <div className="flex items-center gap-2 sm:justify-end">
              <button
                type="button"
                onClick={() => setEditing(client)}
                className="rounded-lg px-2.5 py-2 text-sm font-medium text-teal-800 hover:bg-teal-50"
              >
                Edit
              </button>
              <button
                type="button"
                onClick={() => setDeleting(client)}
                className="grid h-9 w-9 place-items-center rounded-lg text-zinc-400 hover:bg-rose-50 hover:text-rose-700"
                aria-label={`Delete ${client.canonical_name}`}
                title="Delete client profile"
              >
                <Trash size={17} />
              </button>
            </div>
          </div>
        ))}
      </div>
      <AnimatePresence>
        {editing !== undefined && (
          <ClientModal
            client={editing}
            onClose={() => setEditing(undefined)}
            onCreated={async () => {
              setEditing(undefined);
              await onCreated();
            }}
          />
        )}
      </AnimatePresence>
      <AnimatePresence>
        {deleting && (
          <ClientDeleteModal
            client={deleting}
            onClose={() => setDeleting(null)}
            onDeleted={async () => {
              setDeleting(null);
              await onCreated();
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function ClientDeleteModal({
  client,
  onClose,
  onDeleted,
}: {
  client: Client;
  onClose: () => void;
  onDeleted: () => Promise<void>;
}) {
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const remove = async () => {
    setWorking(true);
    setError("");
    try {
      await api.deleteClient(client.id);
      await onDeleted();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Client could not be deleted",
      );
      setWorking(false);
    }
  };
  return (
    <Modal
      title={`Delete ${client.canonical_name}?`}
      description="This permanently removes the monitored client profile and client-specific alert workflow records. Public claims and retained source evidence are preserved."
      onClose={onClose}
    >
      <InlineNotice tone="danger">
        Saved notification drafts, AI alert assessments, false-positive feedback,
        and alerts linked only to this client will also be deleted. This action
        cannot be undone.
      </InlineNotice>
      {error && <InlineNotice tone="danger">{error}</InlineNotice>}
      <div className="mt-6 flex flex-wrap justify-end gap-3">
        <button
          type="button"
          disabled={working}
          onClick={onClose}
          className="button-secondary"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={working}
          onClick={() => void remove()}
          className="button-primary !bg-rose-700 hover:!bg-rose-800"
        >
          {working ? (
            <SpinnerGap className="animate-spin" size={18} />
          ) : (
            <Trash size={18} />
          )}
          Delete client
        </button>
      </div>
    </Modal>
  );
}

function ClientModal({
  client,
  onClose,
  onCreated,
}: {
  client: Client | null;
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const [form, setForm] = useState<NewClient>(
    client
      ? {
          canonical_name: client.canonical_name,
          primary_domain: client.primary_domain,
          description: client.description,
          countries: [...client.countries],
          cities: [...client.cities],
          industries: [...client.industries],
          related_entities: client.related_entities.map((entity) => ({
            ...entity,
          })),
          priority: client.priority,
          aliases: [...client.aliases],
          keywords: [...client.keywords],
        }
      : {
          ...emptyClient,
          countries: [...emptyClient.countries],
          cities: [],
          industries: [],
          related_entities: [],
          keywords: [],
        },
  );
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      if (client) await api.updateClient(client.id, form);
      else await api.createClient(form);
      await onCreated();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Client could not be saved",
      );
      setSaving(false);
    }
  };
  return (
    <Modal
      title={client ? "Edit monitored client" : "Add a monitored client"}
      description="Define the organization, operating markets, industries, and related companies that should participate in matching."
      onClose={onClose}
    >
      <ClientForm
        form={form}
        setForm={setForm}
        onSubmit={submit}
        saving={saving}
        error={error}
        submitLabel={client ? "Save changes" : "Add client"}
      />
    </Modal>
  );
}

function IntelligencePage({
  onNavigate,
}: {
  onNavigate: (page: Page) => void;
}) {
  const intelligenceRoot = useRef<HTMLDivElement>(null);
  const reducedMotion = useReducedMotion();
  const [days, setDays] = useState(30);
  const [query, setQuery] = useState("");
  const [actor, setActor] = useState("");
  const [country, setCountry] = useState("");
  const [industry, setIndustry] = useState("");
  const [publicationStatus, setPublicationStatus] = useState("");
  const [volumeDateBasis, setVolumeDateBasis] = useState<
    "first_publication" | "attack_date"
  >("first_publication");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<IntelligenceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [analysisScope, setAnalysisScope] =
    useState<IntelligenceAnalysisScope>("overall");
  const [analysisValue, setAnalysisValue] = useState("");
  const [intelligenceAnalysis, setIntelligenceAnalysis] =
    useState<IntelligenceAIAnalysis | null>(null);
  const [analysisHistory, setAnalysisHistory] = useState<
    IntelligenceAIAnalysis[]
  >([]);
  const [historyPreview, setHistoryPreview] =
    useState<IntelligenceAIAnalysis | null>(null);
  const [analyzingIntelligence, setAnalyzingIntelligence] = useState(false);
  const [enrichingClaimId, setEnrichingClaimId] = useState("");
  const [bulkEnriching, setBulkEnriching] = useState(false);
  const [aiError, setAIError] = useState("");
  const [aiNotice, setAINotice] = useState("");
  const [actorProfiles, setActorProfiles] = useState<ThreatActorProfile[]>([]);
  const [selectedProfileActor, setSelectedProfileActor] = useState("");
  const [profileError, setProfileError] = useState("");

  useGSAP(
    () => {
      const root = intelligenceRoot.current;
      if (!root) return;
      const select = gsap.utils.selector(root);
      const intro = select("[data-intelligence-intro]");
      const controls = select("[data-intelligence-controls]");
      const metrics = select("[data-intelligence-metric]");
      const panels = select("[data-intelligence-panel]");

      if (reducedMotion) {
        gsap.set([...intro, ...controls, ...metrics, ...panels], {
          clearProps: "all",
        });
        return;
      }

      const timeline = gsap.timeline({ defaults: { ease: "power2.out" } });
      timeline
        .fromTo(
          intro,
          { autoAlpha: 0, y: 8 },
          {
            autoAlpha: 1,
            y: 0,
            duration: 0.34,
            stagger: 0.055,
            clearProps: "transform,opacity,visibility",
          },
        )
        .fromTo(
          controls,
          { autoAlpha: 0, y: 6 },
          {
            autoAlpha: 1,
            y: 0,
            duration: 0.3,
            clearProps: "transform,opacity,visibility",
          },
          "-=0.18",
        )
        .fromTo(
          metrics,
          { autoAlpha: 0, y: 5 },
          {
            autoAlpha: 1,
            y: 0,
            duration: 0.3,
            stagger: 0.045,
            clearProps: "transform,opacity,visibility",
          },
          "-=0.12",
        )
        .fromTo(
          panels,
          { autoAlpha: 0 },
          {
            autoAlpha: 1,
            duration: 0.36,
            stagger: 0.055,
            clearProps: "opacity,visibility",
          },
          "-=0.12",
        );
    },
    { scope: intelligenceRoot, dependencies: [reducedMotion] },
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLoading(true);
      void api
        .intelligence({
          days,
          query,
          actor,
          country,
          industry,
          publication_status: publicationStatus,
          page,
        })
        .then((result) => {
          setData(result);
          setError("");
        })
        .catch((reason) =>
          setError(
            reason instanceof Error
              ? reason.message
              : "Intelligence could not be loaded",
          ),
        )
        .finally(() => setLoading(false));
    }, 220);
    return () => window.clearTimeout(timer);
  }, [days, query, actor, country, industry, publicationStatus, page]);

  const loadActorProfiles = useCallback(async () => {
    try {
      const profiles = await api.actorProfiles(0);
      setActorProfiles(profiles);
      setSelectedProfileActor((current) =>
        profiles.some((profile) => profile.actor === current)
          ? current
          : (profiles[0]?.actor ?? ""),
      );
      setProfileError("");
    } catch (reason) {
      setProfileError(
        reason instanceof Error
          ? reason.message
          : "Threat-actor profiles could not be loaded",
      );
    }
  }, []);
  useEffect(() => {
    void loadActorProfiles();
  }, [loadActorProfiles]);

  useEffect(() => {
    void api
      .intelligenceAnalysisHistory(20)
      .then(setAnalysisHistory)
      .catch((reason) =>
        setAIError(
          reason instanceof Error
            ? reason.message
            : "Analysis history could not be loaded",
        ),
      );
  }, []);

  const analysisOptions =
    analysisScope === "actor"
      ? (data?.facets.actors ?? [])
      : analysisScope === "region"
        ? (data?.facets.countries ?? [])
        : analysisScope === "industry"
          ? (data?.facets.industries ?? [])
          : [];
  useEffect(() => {
    if (analysisScope === "overall") {
      if (analysisValue) setAnalysisValue("");
    } else if (!analysisOptions.includes(analysisValue)) {
      setAnalysisValue(analysisOptions[0] ?? "");
    }
  }, [analysisScope, analysisValue, analysisOptions]);

  const analyzeIntelligence = async () => {
    if (analysisScope !== "overall" && !analysisValue) return;
    setAnalyzingIntelligence(true);
    setAIError("");
    try {
      await api.queueAIJob("intelligence_analysis", {
        scope: analysisScope,
        value: analysisValue,
        days: days || 365,
      });
      setAINotice(
        "Analysis queued. You can continue browsing; the AI task center will notify you when the persisted assessment is ready.",
      );
    } catch (reason) {
      setAIError(
        reason instanceof Error
          ? reason.message
          : "Intelligence analysis failed",
      );
    } finally {
      setAnalyzingIntelligence(false);
    }
  };
  const enrichVictim = async (claimId: string) => {
    setEnrichingClaimId(claimId);
    setAIError("");
    setAINotice("");
    try {
      await api.queueAIJob("victim_enrichment", { claim_id: claimId });
      setAINotice(
        "Victim research queued. Continue browsing; completed organization context will appear in the AI task center and Activity claim drawer.",
      );
    } catch (reason) {
      setAIError(
        reason instanceof Error ? reason.message : "Victim enrichment failed",
      );
    } finally {
      setEnrichingClaimId("");
    }
  };
  const enrichNewVictims = async () => {
    setBulkEnriching(true);
    setAIError("");
    setAINotice("");
    try {
      await api.queueAIJob("bulk_victim_enrichment", { limit: 25 });
      setAINotice(
        "Bulk victim research queued. The AI task center will report enriched, failed, and remaining counts when it finishes.",
      );
    } catch (reason) {
      setAIError(
        reason instanceof Error
          ? reason.message
          : "Bulk victim enrichment failed",
      );
    } finally {
      setBulkEnriching(false);
    }
  };

  const changeFilter = (setter: (value: string) => void, value: string) => {
    setter(value);
    setPage(1);
  };
  return (
    <div ref={intelligenceRoot}>
      <div
        data-intelligence-intro
        className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end"
      >
        <PageIntro
          eyebrow="Ransomware landscape"
          title="Victim intelligence"
          description="Explore deduplicated public ransomware claims by period, actor, geography, industry, and publication state."
        />
        <div
          className="flex flex-wrap gap-2"
          role="group"
          aria-label="Intelligence period"
        >
          {[
            [30, "30 days"],
            [180, "6 months"],
            [365, "1 year"],
            [0, "All time"],
          ].map(([value, label]) => (
            <button
              type="button"
              key={value}
              onClick={() => {
                setDays(Number(value));
                setPage(1);
              }}
              className={`filter-pill ${days === value ? "filter-pill-active" : ""}`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      <div data-intelligence-intro>
        <InlineNotice tone="neutral">
          Records are threat-actor allegations aggregated from attributed public
          sources. The same normalized threat actor and victim is counted once,
          while every underlying source observation remains retained as evidence.
          {data?.duplicates_collapsed
            ? ` ${data.duplicates_collapsed.toLocaleString()} duplicate source ${data.duplicates_collapsed === 1 ? "record is" : "records are"} consolidated in this view.`
            : ""} Use the volume chart's date-basis switch when comparing a
          provider that groups records by estimated attack date rather than first
          publication. Counts may still differ where proprietary telemetry is not
          available.
        </InlineNotice>
      </div>
      <div
        data-intelligence-controls
        className="mt-7 rounded-2xl border border-zinc-200 bg-white p-3"
      >
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2 px-1">
          <p className="text-xs text-zinc-500">
            Threat actor, geography, industry, and status filters update every
            metric, graph, map, chart, and exported PNG.
          </p>
          {(query || actor || country || industry || publicationStatus) && (
            <button
              type="button"
              className="text-xs font-medium text-teal-800"
              onClick={() => {
                setQuery("");
                setActor("");
                setCountry("");
                setIndustry("");
                setPublicationStatus("");
                setPage(1);
              }}
            >
              Clear all filters
            </button>
          )}
        </div>
        <div className="grid gap-3 lg:grid-cols-[1.4fr_repeat(4,1fr)]">
          <label className="flex min-h-12 items-center gap-3 rounded-xl border border-zinc-200 bg-white px-4">
            <MagnifyingGlass size={18} className="text-zinc-400" />
            <span className="sr-only">Search victims</span>
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(1);
              }}
              className="w-full bg-transparent text-sm outline-none"
              placeholder="Search company, domain, actor…"
            />
          </label>
          <FilterSelect
            label="Threat actor"
            value={actor}
            options={data?.facets.actors ?? []}
            onChange={(value) => changeFilter(setActor, value)}
          />
          <FilterSelect
            label="Country"
            value={country}
            options={data?.facets.countries ?? []}
            onChange={(value) => changeFilter(setCountry, value)}
          />
          <FilterSelect
            label="Industry"
            value={industry}
            options={data?.facets.industries ?? []}
            onChange={(value) => changeFilter(setIndustry, value)}
          />
          <FilterSelect
            label="Status"
            value={publicationStatus}
            options={data?.facets.statuses ?? []}
            onChange={(value) => changeFilter(setPublicationStatus, value)}
          />
        </div>
      </div>
      {error && <InlineNotice tone="danger">{error}</InlineNotice>}
      <div
        className={`mt-7 grid gap-4 sm:grid-cols-2 xl:grid-cols-5 ${loading ? "opacity-60" : ""}`}
      >
        <div data-intelligence-metric>
          <IntelligenceMetric
            label="Victim claims"
            value={data?.total ?? 0}
            helper="Deduplicated records"
          />
        </div>
        <div data-intelligence-metric>
          <GrowthMetric
            growth={data?.overall_growth}
            basisDays={data?.growth_basis_days ?? (days || 30)}
          />
        </div>
        <div data-intelligence-metric>
          <IntelligenceMetric
            label="Daily average"
            value={data?.daily_average ?? 0}
            helper="During selected period"
          />
        </div>
        <div data-intelligence-metric>
          <IntelligenceMetric
            label="Active groups"
            value={data?.active_groups ?? 0}
            helper="Distinct operators"
          />
        </div>
        <div data-intelligence-metric>
          <IntelligenceMetric
            label="Countries affected"
            value={data?.countries_affected ?? 0}
            helper="Known locations only"
          />
        </div>
      </div>
      <div data-intelligence-panel className="mt-7 grid gap-5 xl:grid-cols-[1.25fr_.75fr]">
        <MonthlyLineChart
          items={
            volumeDateBasis === "attack_date"
              ? (data?.monthly_attack_trend ?? [])
              : (data?.monthly_trend ?? [])
          }
          basis={volumeDateBasis}
          attackDateCoverage={data?.attack_date_coverage ?? 0}
          onBasisChange={setVolumeDateBasis}
        />
        <RankingCard
          title="Most active groups"
          items={data?.top_groups ?? []}
        />
      </div>
      <div data-intelligence-panel className="mt-5 grid gap-5 xl:grid-cols-[1.3fr_.7fr]">
        <CountryWorldMap items={data?.top_countries ?? []} />
        <IndustryPieChart items={data?.top_industries ?? []} />
      </div>
      <div data-intelligence-panel className="mt-5 grid gap-5 xl:grid-cols-[1.15fr_.85fr]">
        <GrowthRankingCard
          title="Growth by threat group"
          description={`Latest ${data?.growth_basis_days ?? 30} days versus the preceding period.`}
          items={data?.group_growth ?? []}
        />
        <RegionGrowthCard
          items={data?.monitored_region_growth ?? []}
          basisDays={data?.growth_basis_days ?? 30}
          onEdit={() => onNavigate("settings")}
        />
      </div>
      <ThreatActorProfiles
        profiles={actorProfiles}
        selectedActor={selectedProfileActor}
        error={profileError}
        onSelect={setSelectedProfileActor}
        onProfilesReload={loadActorProfiles}
      />
      <FlexibleAnalysisCard
        scope={analysisScope}
        value={analysisValue}
        options={analysisOptions}
        analysis={intelligenceAnalysis}
        working={analyzingIntelligence}
        onScope={(scope) => {
          setAnalysisScope(scope);
          setIntelligenceAnalysis(null);
        }}
        onValue={(value) => {
          setAnalysisValue(value);
          setIntelligenceAnalysis(null);
        }}
        onAnalyze={() => void analyzeIntelligence()}
      />
      <AnalysisHistory
        records={analysisHistory}
        selectedId={intelligenceAnalysis?.id ?? ""}
        onSelect={(record) => {
          setIntelligenceAnalysis(record);
          setHistoryPreview(record);
        }}
      />
      <AnimatePresence>
        {historyPreview && (
          <AnalysisRecordDialog
            record={historyPreview}
            onClose={() => setHistoryPreview(null)}
          />
        )}
      </AnimatePresence>
      {aiNotice && <InlineNotice tone="neutral">{aiNotice}</InlineNotice>}
      {aiError && <InlineNotice tone="danger">{aiError}</InlineNotice>}
      <VictimClaimsSection
        data={data}
        loading={loading}
        page={page}
        onPage={setPage}
        enrichingClaimId={enrichingClaimId}
        bulkEnriching={bulkEnriching}
        onEnrich={(claimId) => void enrichVictim(claimId)}
        onBulkEnrich={() => void enrichNewVictims()}
      />
    </div>
  );
}

function VictimClaimsSection({
  data,
  loading,
  page,
  onPage,
  enrichingClaimId,
  bulkEnriching,
  onEnrich,
  onBulkEnrich,
}: {
  data: IntelligenceResponse | null;
  loading: boolean;
  page: number;
  onPage: (page: number) => void;
  enrichingClaimId: string;
  bulkEnriching: boolean;
  onEnrich: (claimId: string) => void;
  onBulkEnrich: () => void;
}) {
  return (
    <section className="mt-8">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <h3 className="text-xl font-semibold">Victim claims</h3>
          <p className="mt-1 text-sm text-zinc-500">
            Source evidence plus optional AI context checked against passive
            public background sources.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={bulkEnriching || !!enrichingClaimId}
            onClick={onBulkEnrich}
            className="button-secondary whitespace-nowrap !border-violet-200 text-violet-800"
          >
            {bulkEnriching ? (
              <SpinnerGap className="animate-spin" size={17} />
            ) : (
              <Cpu size={17} />
            )}
            {bulkEnriching ? "Checking backgrounds…" : "Enrich next 25 new"}
          </button>
          {loading && (
            <SpinnerGap className="animate-spin text-teal-800" size={22} />
          )}
        </div>
      </div>
      <div className="mt-5 overflow-x-auto rounded-2xl border border-zinc-200 bg-white">
        <table className="w-full min-w-[1050px] text-left">
          <thead className="border-b border-zinc-200 bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
            <tr>
              <th className="px-5 py-4">Organization</th>
              <th className="px-5 py-4">Country / industry</th>
              <th className="px-5 py-4">Threat actor</th>
              <th className="px-5 py-4">Status</th>
              <th className="px-5 py-4">Source</th>
              <th className="px-5 py-4 text-right">Published</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {loading && !data && (
              <tr>
                <td colSpan={6} className="p-5 sm:p-7">
                  <LoadingStatusCard
                    title="Loading victim claims"
                    description="Retrieving deduplicated claims for the selected intelligence view."
                    className="max-w-xl"
                  />
                </td>
              </tr>
            )}
            {data?.victims.map((claim) => (
              <tr key={claim.id} className="align-top hover:bg-zinc-50">
                <td className="px-5 py-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="font-semibold">{claim.title}</p>
                      <p className="mt-1 max-w-md text-xs leading-5 text-zinc-500">
                        {claim.description ||
                          claim.domains[0] ||
                          "No source description supplied"}
                      </p>
                      {claim.ai_description && (
                        <div className="mt-2 max-w-md rounded-lg bg-violet-50 px-3 py-2 text-xs leading-5 text-violet-900">
                          <span className="mr-2 font-bold uppercase tracking-wide">
                            AI context
                          </span>
                          {claim.ai_description}
                          {claim.ai_rationale && (
                            <p className="mt-1 text-[11px] text-violet-700">
                              Match basis: {claim.ai_rationale}
                            </p>
                          )}
                          {claim.ai_sources.length > 0 && (
                            <div className="mt-1 flex flex-wrap gap-2">
                              {claim.ai_sources.map((url, sourceIndex) => (
                                <a
                                  key={url}
                                  href={url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="font-semibold underline underline-offset-2"
                                >
                                  Background source {sourceIndex + 1}
                                </a>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    <button
                      type="button"
                      disabled={!!enrichingClaimId || bulkEnriching}
                      onClick={() => onEnrich(claim.id)}
                      className="shrink-0 rounded-lg border border-violet-200 bg-white px-2.5 py-1.5 text-[11px] font-semibold text-violet-800 hover:bg-violet-50"
                    >
                      {enrichingClaimId === claim.id ? (
                        <SpinnerGap className="animate-spin" size={14} />
                      ) : claim.ai_enriched_at ? (
                        "Refresh AI"
                      ) : (
                        "AI enrich"
                      )}
                    </button>
                  </div>
                </td>
                <td className="px-5 py-4 text-sm text-zinc-600">
                  <p>
                    {claim.country || claim.ai_country || "Unknown country"}
                    {!claim.country && claim.ai_country && (
                      <span className="ml-1 rounded bg-violet-50 px-1.5 py-0.5 text-[10px] font-semibold text-violet-700">
                        AI
                      </span>
                    )}
                  </p>
                  <p className="mt-1 text-xs text-zinc-500">
                    {claim.industry || claim.ai_industry || "Unknown industry"}
                    {!claim.industry && claim.ai_industry && (
                      <span className="ml-1 rounded bg-violet-50 px-1.5 py-0.5 font-semibold text-violet-700">
                        AI
                      </span>
                    )}
                  </p>
                  {claim.industry &&
                    claim.ai_industry &&
                    claim.industry.toLowerCase() !==
                      claim.ai_industry.toLowerCase() && (
                      <p className="mt-1 text-[11px] text-violet-700">
                        AI industry: {claim.ai_industry}
                      </p>
                    )}
                  {claim.country &&
                    claim.ai_country &&
                    claim.country.toLowerCase() !==
                      claim.ai_country.toLowerCase() && (
                      <p className="mt-1 text-[11px] text-violet-700">
                        AI geography: {claim.ai_country}
                      </p>
                    )}
                  {claim.ai_organization_type && (
                    <p className="mt-1 text-[11px] text-zinc-400">
                      {claim.ai_organization_type} · {claim.ai_confidence ?? 0}%
                      confidence
                    </p>
                  )}
                </td>
                <td className="px-5 py-4 text-sm font-medium">
                  {claim.threat_actor}
                </td>
                <td className="px-5 py-4">
                  <ClaimStatus value={claim.publication_status} />
                </td>
                <td className="px-5 py-4 text-sm text-zinc-600">
                  {sourceLabel(claim.source)}
                </td>
                <td className="px-5 py-4 text-right font-mono text-xs text-zinc-500">
                  {claim.published_at
                    ? formatTime(claim.published_at)
                    : "Not supplied"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && !data?.victims.length && (
          <div className="p-10 text-center text-sm text-zinc-500">
            No claims match these filters.
          </div>
        )}
      </div>
      {data && data.pages > 1 && (
        <div className="mt-5 flex items-center justify-end gap-3">
          <button
            type="button"
            className="button-secondary"
            disabled={page <= 1}
            onClick={() => onPage(page - 1)}
          >
            Previous
          </button>
          <span className="font-mono text-xs text-zinc-500">
            Page {page} of {data.pages}
          </span>
          <button
            type="button"
            className="button-secondary"
            disabled={page >= data.pages}
            onClick={() => onPage(page + 1)}
          >
            Next
          </button>
        </div>
      )}
    </section>
  );
}

type CaptureJobFilter =
  | "all"
  | "attention"
  | "queued"
  | "running"
  | "completed"
  | "failed";

type CaptureJobGrouping = "status" | "actor" | "none";
type CaptureJobSort = "newest" | "oldest" | "actor";
type ClearableCaptureStatus = "queued" | "failed";

function captureJobNeedsAttention(job: CaptureJob) {
  return (
    job.status === "failed" ||
    job.opsec_status === "failed" ||
    job.evidence_readiness === "review" ||
    job.evidence_readiness === "not_ready" ||
    job.capture_truncated ||
    job.more_content_suspected
  );
}

function captureStatusLabel(status: string) {
  return status.charAt(0).toUpperCase() + status.slice(1).replaceAll("_", " ");
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
  const [runtime, setRuntime] = useState<RuntimeSettings | null>(null);
  const [captureInterval, setCaptureInterval] = useState("30");
  const [scheduleSaving, setScheduleSaving] = useState(false);
  const [coverageSaving, setCoverageSaving] = useState(false);
  const [catalogSyncing, setCatalogSyncing] = useState(false);
  const [confirmCapture, setConfirmCapture] = useState<DlsTarget | null>(null);
  const [reviewCapture, setReviewCapture] = useState<{
    job: CaptureJob;
    page: number;
    expanded: boolean;
    zoom: number;
  } | null>(null);
  const [clearJobsOpen, setClearJobsOpen] = useState(false);
  const [clearJobStatuses, setClearJobStatuses] = useState<
    ClearableCaptureStatus[]
  >(["queued", "failed"]);
  const [clearingJobs, setClearingJobs] = useState(false);
  const [clearJobsError, setClearJobsError] = useState("");
  const [jobQuery, setJobQuery] = useState("");
  const [jobFilter, setJobFilter] = useState<CaptureJobFilter>("all");
  const [jobGrouping, setJobGrouping] =
    useState<CaptureJobGrouping>("status");
  const [jobSort, setJobSort] = useState<CaptureJobSort>("newest");
  const refresh = useCallback(async (showLoading = true) => {
    if (showLoading) setLoading(true);
    try {
      const [overview, settings] = await Promise.all([
        api.directSites(query),
        api.runtimeSettings(),
      ]);
      setData(overview);
      setRuntime(settings);
      setCaptureInterval(String(settings.active_interval_minutes));
      setError("");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Direct-site catalog could not be loaded",
      );
    } finally {
      if (showLoading) setLoading(false);
    }
  }, [query]);
  useEffect(() => {
    const timer = window.setTimeout(() => void refresh(), 200);
    return () => window.clearTimeout(timer);
  }, [refresh]);
  useEffect(() => {
    if (
      !data?.jobs.some(
        (job) => job.status === "queued" || job.status === "running",
      )
    )
      return;
    const timer = window.setInterval(() => {
      void api.directSites(query).then(setData);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [data?.jobs, query]);
  const saveCaptureSchedule = async () => {
    if (!runtime) return;
    setScheduleSaving(true);
    setNotice("");
    setError("");
    try {
      const updated = await api.updateRuntimeSettings({
        ...runtime,
        operating_mode: "active",
        scheduling_enabled: true,
        active_interval_minutes: Number(captureInterval),
      });
      setRuntime(updated);
      setNotice(
        `Active capture scheduling enabled ${captureInterval === "60" ? "hourly" : `every ${captureInterval} minutes`}. Allowlisted sites will be queued at that interval.`,
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Capture schedule could not be saved",
      );
    } finally {
      setScheduleSaving(false);
    }
  };
  const saveCoverageControls = async () => {
    if (!runtime) return;
    setCoverageSaving(true);
    setNotice("");
    setError("");
    try {
      const updated = await api.updateRuntimeSettings({ ...runtime });
      setRuntime(updated);
      setNotice(
        "Capture coverage controls saved. New jobs will use these limits.",
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Capture coverage controls could not be saved",
      );
    } finally {
      setCoverageSaving(false);
    }
  };
  const applyCoveragePreset = (preset: "balanced" | "thorough") => {
    if (!runtime) return;
    setRuntime({
      ...runtime,
      capture_max_scrolls: preset === "thorough" ? 120 : 60,
      capture_stable_passes: preset === "thorough" ? 5 : 3,
      capture_scroll_delay_ms: preset === "thorough" ? 1500 : 1000,
      capture_max_page_height: preset === "thorough" ? 100000 : 50000,
      capture_segment_height: 1400,
    });
  };
  const sync = async () => {
    setCatalogSyncing(true);
    setNotice("");
    setError("");
    try {
      const result = await api.syncDirectSites();
      setNotice(
        `Catalog synchronized: ${result.received.toLocaleString()} DLS locations checked and ${result.created.toLocaleString()} added.`,
      );
      await refresh(false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Catalog synchronization failed",
      );
    } finally {
      setCatalogSyncing(false);
    }
  };
  const toggle = async (target: DlsTarget) => {
    const updated = await api.updateDirectSite(
      target.id,
      !target.capture_enabled,
    );
    setData((current) =>
      current
        ? {
            ...current,
            capture_enabled:
              current.capture_enabled + (updated.capture_enabled ? 1 : -1),
            targets: current.targets.map((item) =>
              item.id === updated.id ? updated : item,
            ),
          }
        : current,
    );
  };
  const bulkUpdate = async (captureEnabled: boolean) => {
    if (!selectedIds.size) return;
    setBulkUpdating(true);
    setNotice("");
    setError("");
    try {
      const result = await api.updateDirectSitesBulk(
        Array.from(selectedIds),
        captureEnabled,
      );
      setNotice(
        `${result.updated.toLocaleString()} selected DLS ${captureEnabled ? "allowed" : "disallowed"}. No capture was started.`,
      );
      const updatedIds = new Set(selectedIds);
      setData((current) => {
        if (!current) return current;
        const targets = current.targets.map((target) =>
          updatedIds.has(target.id)
            ? { ...target, capture_enabled: captureEnabled }
            : target,
        );
        return {
          ...current,
          targets,
          capture_enabled: targets.filter((target) => target.capture_enabled)
            .length,
        };
      });
      setSelectedIds(new Set());
      void refresh(false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Bulk allowlist update failed",
      );
    } finally {
      setBulkUpdating(false);
    }
  };
  const visibleTargets = data?.targets.slice(0, 120) ?? [];
  const selectTargets = (targets: DlsTarget[]) =>
    setSelectedIds(new Set(targets.map((target) => target.id)));
  const toggleSelected = (targetId: string) =>
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(targetId)) next.delete(targetId);
      else next.add(targetId);
      return next;
    });
  const queue = async (target: DlsTarget) => {
    setNotice("");
    setError("");
    try {
      await api.queueCapture(target.id);
      setConfirmCapture(null);
      setNotice(`Capture queued for ${target.group_name}.`);
      await refresh(false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Capture could not be queued",
      );
    }
  };
  const clearCaptureJobs = async () => {
    if (!clearJobStatuses.length) return;
    setClearingJobs(true);
    setClearJobsError("");
    try {
      const result = await api.clearCaptureJobs(clearJobStatuses);
      setNotice(
        `${result.deleted.toLocaleString()} queued or failed capture job${result.deleted === 1 ? "" : "s"} cleared. Running work and completed evidence were preserved.`,
      );
      setClearJobsOpen(false);
      setJobFilter("all");
      await refresh(false);
    } catch (reason) {
      setClearJobsError(
        reason instanceof Error
          ? reason.message
          : "Capture jobs could not be cleared",
      );
    } finally {
      setClearingJobs(false);
    }
  };
  const captureJobCounts = useMemo(() => {
    const counts = {
      all: 0,
      attention: 0,
      queued: 0,
      running: 0,
      completed: 0,
      failed: 0,
    };
    for (const job of data?.jobs ?? []) {
      counts.all += 1;
      if (captureJobNeedsAttention(job)) counts.attention += 1;
      if (
        ["queued", "running", "completed", "failed"].includes(job.status)
      ) {
        counts[job.status as "queued" | "running" | "completed" | "failed"] += 1;
      }
    }
    return counts;
  }, [data?.jobs]);
  const filteredCaptureJobs = useMemo(() => {
    const needle = jobQuery.trim().toLocaleLowerCase();
    const jobs = (data?.jobs ?? []).filter((job) => {
      const matchesStatus =
        jobFilter === "all" ||
        (jobFilter === "attention"
          ? captureJobNeedsAttention(job)
          : job.status === jobFilter);
      const searchable = [
        job.group_name,
        job.victim_name,
        job.status,
        job.coverage_status,
        job.continuity_status,
        job.evidence_readiness,
        job.readiness_reason,
        job.error,
        ...job.detected_statuses,
        ...job.victim_candidates.flatMap((candidate) => [
          candidate.name,
          candidate.domain,
        ]),
      ]
        .join(" ")
        .toLocaleLowerCase();
      return matchesStatus && (!needle || searchable.includes(needle));
    });
    return jobs.sort((left, right) => {
      if (jobSort === "actor") {
        return left.group_name.localeCompare(right.group_name, undefined, {
          sensitivity: "base",
        });
      }
      const leftTime = Date.parse(
        left.completed_at || left.started_at || left.requested_at,
      );
      const rightTime = Date.parse(
        right.completed_at || right.started_at || right.requested_at,
      );
      return jobSort === "oldest" ? leftTime - rightTime : rightTime - leftTime;
    });
  }, [data?.jobs, jobFilter, jobQuery, jobSort]);
  const captureJobGroups = useMemo(() => {
    if (jobGrouping === "none") {
      return [{ key: "all", label: "", jobs: filteredCaptureJobs }];
    }
    const grouped = new Map<string, CaptureJob[]>();
    for (const job of filteredCaptureJobs) {
      const key = jobGrouping === "status" ? job.status : job.group_name;
      grouped.set(key, [...(grouped.get(key) ?? []), job]);
    }
    const statusOrder = ["running", "queued", "failed", "completed"];
    return Array.from(grouped, ([key, jobs]) => ({
      key,
      label: jobGrouping === "status" ? captureStatusLabel(key) : key,
      jobs,
    })).sort((left, right) =>
      jobGrouping === "status"
        ? (statusOrder.indexOf(left.key) === -1
            ? statusOrder.length
            : statusOrder.indexOf(left.key)) -
          (statusOrder.indexOf(right.key) === -1
            ? statusOrder.length
            : statusOrder.indexOf(right.key))
        : left.label.localeCompare(right.label, undefined, {
            sensitivity: "base",
          }),
    );
  }, [filteredCaptureJobs, jobGrouping]);
  return (
    <div>
      <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <PageIntro
          eyebrow="Isolated collection"
          title="Threat-actor sites"
          description="Maintain an attributed DLS catalog and select which public pages the Kali evidence worker may capture."
        />
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            className="button-secondary"
            onClick={() => setShowKaliGuide(true)}
          >
            <Info size={18} />
            Kali setup guide
          </button>
          <button
            type="button"
            className="button-primary"
            disabled={catalogSyncing}
            onClick={() => void sync()}
          >
            <SpinnerGap
              className={catalogSyncing ? "animate-spin" : ""}
              size={18}
            />
            {catalogSyncing ? "Synchronizing…" : "Synchronize catalog"}
          </button>
        </div>
      </div>
      {(!data?.worker_configured || !data.worker_online) && (
        <InlineNotice tone="neutral">
          <span>
            <strong>
              {data?.worker_configured
                ? "Separate Kali worker is offline."
                : "Kali worker connection pending."}
            </strong>{" "}
            The browser worker runs as a separate restricted process and must
            register an authenticated local heartbeat before capture is enabled.{" "}
            <button
              type="button"
              className="font-semibold text-teal-800 underline"
              onClick={() => setShowKaliGuide(true)}
            >
              Open the setup guide
            </button>
            .
          </span>
        </InlineNotice>
      )}
      {data?.worker_configured && data.worker_online && (
        <InlineNotice tone="neutral">
          <span>
            <strong>Separate worker online; fail-closed OPSEC gate enabled.</strong>{" "}
            Every DLS visit
            requires a loopback Tor SOCKS5 handshake, uses an ephemeral browser
            context, denies browser permissions and downloads, and blocks
            requests to every origin except the exact allowlisted onion. The
            result is recorded on each capture job.
          </span>
        </InlineNotice>
      )}
      {data?.worker_online && !data.ocr_configured && (
        <InlineNotice tone="neutral">
          <span>
            <strong>OCR is not installed.</strong> Browser text extraction still
            works, but image-only victim cards require local Tesseract. Run{" "}
            <span className="font-mono">sudo apt install tesseract-ocr</span>{" "}
            inside Kali, then restart ExtortSignal.
          </span>
        </InlineNotice>
      )}
      {data && data.catalog_total > data.available && (
        <InlineNotice tone="neutral">
          <span>
            <strong>DLS availability is volatile.</strong> The public catalog
            currently reports {data.available.toLocaleString()} of{" "}
            {data.catalog_total.toLocaleString()} locations available. Scheduled
            capture now skips mirrors not reported available; manual capture
            remains possible for analyst testing because upstream availability
            can be stale.
          </span>
        </InlineNotice>
      )}
      {notice && <InlineNotice tone="neutral">{notice}</InlineNotice>}
      {error && <InlineNotice tone="danger">{error}</InlineNotice>}
      {!!data?.jobs.length && data.jobs[0].opsec_status !== "not_checked" && (
        <InlineNotice
          tone={data.jobs[0].opsec_status === "passed" ? "neutral" : "danger"}
        >
          <span>
            <strong>Latest capture OPSEC: {data.jobs[0].opsec_status}.</strong>{" "}
            Tor preflight{" "}
            {data.jobs[0].tor_preflight_passed ? "passed" : "did not pass"};{" "}
            {data.jobs[0].blocked_request_count.toLocaleString()} off-origin
            request{data.jobs[0].blocked_request_count === 1 ? "" : "s"},{" "}
            {data.jobs[0].blocked_popup_count.toLocaleString()} popup
            {data.jobs[0].blocked_popup_count === 1 ? "" : "s"}, and{" "}
            {data.jobs[0].blocked_download_count.toLocaleString()} download
            {data.jobs[0].blocked_download_count === 1 ? "" : "s"} blocked.
          </span>
        </InlineNotice>
      )}
      <div className="mt-7 grid gap-4 sm:grid-cols-3">
        <IntelligenceMetric
          label="DLS locations"
          value={data?.catalog_total ?? 0}
          helper="Maintained public catalog"
        />
        <IntelligenceMetric
          label="Reported available"
          value={data?.available ?? 0}
          helper="Upstream availability signal"
        />
        <IntelligenceMetric
          label="Capture allowlist"
          value={data?.capture_enabled ?? 0}
          helper="Explicitly approved sites"
        />
      </div>
      <section className="mt-5 rounded-2xl border border-amber-200 bg-amber-50/50 p-5">
        <div className="grid gap-5 lg:grid-cols-[1fr_260px_auto] lg:items-end">
          <div>
            <p className="eyebrow !text-amber-800">Active capture controls</p>
            <h3 className="mt-2 text-lg font-semibold">
              Schedule allowlisted screenshots
            </h3>
            <p className="mt-2 text-xs leading-5 text-zinc-600">
              Scheduled runs queue every allowed DLS. Manual and scheduled
              capture both require Active mode. The worker scrolls lazy-loaded
              victim lists until page height stabilizes, then saves numbered
              review pages without clicking links or download controls.
            </p>
          </div>
          <Field
            label="Capture frequency"
            helper={`Last scheduled run: ${formatTime(runtime?.last_active_run_at)}`}
          >
            <CustomSelect
              ariaLabel="Active capture frequency"
              value={captureInterval}
              onChange={setCaptureInterval}
              options={[
                { value: "5", label: "Every 5 minutes" },
                { value: "15", label: "Every 15 minutes" },
                { value: "30", label: "Every 30 minutes" },
                { value: "60", label: "Hourly" },
                { value: "360", label: "Every 6 hours" },
                { value: "720", label: "Every 12 hours" },
                { value: "1440", label: "Daily" },
              ]}
            />
          </Field>
          <button
            type="button"
            disabled={!runtime || scheduleSaving || !data?.worker_online}
            onClick={() => void saveCaptureSchedule()}
            className="button-primary whitespace-nowrap"
          >
            {scheduleSaving ? (
              <SpinnerGap className="animate-spin" size={17} />
            ) : (
              <ClockCounterClockwise size={17} />
            )}
            Enable schedule
          </button>
        </div>
        {runtime?.operating_mode !== "active" && (
          <div className="mt-4 rounded-xl border border-amber-300 bg-amber-100 px-4 py-3 text-xs font-semibold text-amber-900">
            Capture is locked while monitoring is{" "}
            {runtime?.operating_mode || "not configured"}. Enable Active mode
            before testing or scheduling DLS access.
          </div>
        )}
        <div className="mt-4 rounded-xl border border-amber-200 bg-white px-4 py-3 text-xs leading-5 text-zinc-600">
          <strong className="text-zinc-900">Screenshot storage:</strong>{" "}
          <span className="break-all font-mono">
            {data?.evidence_directory || "data/captures"}
          </span>
          <br />
          Each successful job is stored as review-sized pages:{" "}
          <span className="font-mono">
            threat-actor/YYYY-MM-DD_HH-MM-SS_TZ_pNNN.png
          </span>
          .
        </div>
      </section>
      <section className="mt-5 min-w-0 overflow-hidden rounded-2xl border border-teal-200 bg-white p-5">
        <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-start">
          <div className="min-w-0">
            <p className="eyebrow">Coverage assurance</p>
            <h3 className="mt-2 text-lg font-semibold">
              How thoroughly should each victim list load?
            </h3>
            <p className="mt-2 max-w-3xl text-xs leading-5 text-zinc-600">
              The worker scrolls until page height stabilizes, expands exact
              load-more controls, follows same-origin next-page controls, and
              records visible ARIA tabs as separate evidence states. Every
              action is read-only, bounded, and restricted to the current onion
              host.
            </p>
          </div>
          <div className="grid w-full gap-2 sm:w-auto sm:grid-cols-2">
            <button
              type="button"
              className="button-secondary w-full !min-h-10 whitespace-nowrap px-4 text-xs"
              disabled={!runtime || coverageSaving}
              onClick={() => applyCoveragePreset("balanced")}
            >
              Balanced preset
            </button>
            <button
              type="button"
              className="button-secondary w-full !min-h-10 whitespace-nowrap px-4 text-xs"
              disabled={!runtime || coverageSaving}
              onClick={() => applyCoveragePreset("thorough")}
            >
              Thorough preset
            </button>
          </div>
        </div>
        {runtime && (
          <div className="mt-5 grid min-w-0 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-5">
            <Field
              label="Maximum scroll passes"
              helper="Higher catches longer lazy-loaded lists."
            >
              <CustomSelect
                ariaLabel="Maximum scroll passes"
                value={String(runtime.capture_max_scrolls)}
                onChange={(value) =>
                  setRuntime({ ...runtime, capture_max_scrolls: Number(value) })
                }
                options={[
                  { value: "30", label: "30 passes" },
                  { value: "60", label: "60 passes" },
                  { value: "120", label: "120 passes" },
                  { value: "200", label: "200 passes" },
                ]}
              />
            </Field>
            <Field
              label="Stable confirmations"
              helper="Unchanged page-height checks required."
            >
              <CustomSelect
                ariaLabel="Stable confirmations"
                value={String(runtime.capture_stable_passes)}
                onChange={(value) =>
                  setRuntime({
                    ...runtime,
                    capture_stable_passes: Number(value),
                  })
                }
                options={[
                  { value: "2", label: "2 checks" },
                  { value: "3", label: "3 checks" },
                  { value: "5", label: "5 checks" },
                  { value: "8", label: "8 checks" },
                ]}
              />
            </Field>
            <Field
              label="Wait after each scroll"
              helper="Allows slower cards to render."
            >
              <CustomSelect
                ariaLabel="Wait after each scroll"
                value={String(runtime.capture_scroll_delay_ms)}
                onChange={(value) =>
                  setRuntime({
                    ...runtime,
                    capture_scroll_delay_ms: Number(value),
                  })
                }
                options={[
                  { value: "500", label: "0.5 seconds" },
                  { value: "1000", label: "1 second" },
                  { value: "1500", label: "1.5 seconds" },
                  { value: "2500", label: "2.5 seconds" },
                  { value: "5000", label: "5 seconds" },
                ]}
              />
            </Field>
            <Field
              label="Maximum page height"
              helper="Safety cap for unusually long sites."
            >
              <CustomSelect
                ariaLabel="Maximum page height"
                value={String(runtime.capture_max_page_height)}
                onChange={(value) =>
                  setRuntime({
                    ...runtime,
                    capture_max_page_height: Number(value),
                  })
                }
                options={[
                  { value: "25000", label: "25,000 px" },
                  { value: "50000", label: "50,000 px" },
                  { value: "75000", label: "75,000 px" },
                  { value: "100000", label: "100,000 px" },
                ]}
              />
            </Field>
            <Field
              label="Review page size"
              helper="PNG height shown in evidence review."
            >
              <CustomSelect
                ariaLabel="Review page size"
                value={String(runtime.capture_segment_height)}
                onChange={(value) =>
                  setRuntime({
                    ...runtime,
                    capture_segment_height: Number(value),
                  })
                }
                options={[
                  { value: "1000", label: "1,000 px" },
                  { value: "1400", label: "1,400 px" },
                  { value: "1800", label: "1,800 px" },
                  { value: "2200", label: "2,200 px" },
                ]}
              />
            </Field>
          </div>
        )}
        <div className="mt-5 grid min-w-0 gap-3 rounded-xl bg-teal-50 px-4 py-3 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-center">
          <p className="min-w-0 text-xs leading-5 text-teal-900">
            <strong>Interaction guardrails:</strong> no AI agent, typing, forms,
            authentication, downloads, messages, mutation requests, popups, or
            cross-origin navigation. A non-white entry screen may receive one
            exact Enter/Continue/View site/Proceed click.
          </p>
          <button
            type="button"
            className="button-primary w-full shrink-0 whitespace-nowrap sm:w-auto"
            disabled={!runtime || coverageSaving}
            onClick={() => void saveCoverageControls()}
          >
            {coverageSaving ? (
              <SpinnerGap className="animate-spin" size={17} />
            ) : (
              <Check size={17} />
            )}
            Save coverage controls
          </button>
        </div>
      </section>
      <label className="mt-7 flex max-w-xl items-center gap-3 rounded-xl border border-zinc-200 bg-white px-4 py-3">
        <MagnifyingGlass size={19} className="text-zinc-400" />
        <span className="sr-only">Search threat-actor sites</span>
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          className="w-full bg-transparent text-sm outline-none"
          placeholder="Search group or catalog title"
        />
      </label>
      <div className="mt-4 flex flex-col justify-between gap-3 rounded-2xl border border-zinc-200 bg-white p-4 sm:flex-row sm:items-center">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-zinc-800">
            {selectedIds.size.toLocaleString()} selected
          </span>
          <button
            type="button"
            onClick={() => selectTargets(visibleTargets)}
            disabled={!visibleTargets.length || bulkUpdating}
            className="text-xs font-semibold text-teal-800"
          >
            Select visible
          </button>
          <span className="text-zinc-300">·</span>
          <button
            type="button"
            onClick={() =>
              selectTargets(
                visibleTargets.filter((target) => target.capture_enabled),
              )
            }
            disabled={
              !visibleTargets.some((target) => target.capture_enabled) ||
              bulkUpdating
            }
            className="text-xs font-semibold text-zinc-600"
          >
            Select allowed
          </button>
          <span className="text-zinc-300">·</span>
          <button
            type="button"
            onClick={() =>
              selectTargets(
                visibleTargets.filter((target) => !target.capture_enabled),
              )
            }
            disabled={
              !visibleTargets.some((target) => !target.capture_enabled) ||
              bulkUpdating
            }
            className="text-xs font-semibold text-zinc-600"
          >
            Select disallowed
          </button>
          {selectedIds.size > 0 && (
            <>
              <span className="text-zinc-300">·</span>
              <button
                type="button"
                onClick={() => setSelectedIds(new Set())}
                disabled={bulkUpdating}
                className="text-xs font-semibold text-zinc-500"
              >
                Clear
              </button>
            </>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={!selectedIds.size || bulkUpdating}
            onClick={() => void bulkUpdate(true)}
            className="button-primary !min-h-10 px-4 text-xs"
          >
            {bulkUpdating ? (
              <SpinnerGap className="animate-spin" size={16} />
            ) : (
              <Check size={16} />
            )}
            Allow selected
          </button>
          <button
            type="button"
            disabled={!selectedIds.size || bulkUpdating}
            onClick={() => void bulkUpdate(false)}
            className="button-secondary !min-h-10 px-4 text-xs"
          >
            <XCircle size={16} />
            Disallow selected
          </button>
        </div>
      </div>
      <div className="mt-6 overflow-hidden rounded-2xl border border-zinc-200 bg-white">
        {loading && !data && (
          <div className="p-5 sm:p-7">
            <LoadingStatusCard
              title="Loading direct-site controls"
              description="Retrieving the maintained DLS catalog and recent capture state."
              className="max-w-xl"
            />
          </div>
        )}
        {visibleTargets.map((target, index) => (
          <div
            key={target.id}
            className={`grid gap-4 p-5 xl:grid-cols-[1.25rem_minmax(0,1.2fr)_minmax(0,1fr)_9.5rem_14rem] xl:items-center ${index ? "border-t border-zinc-100" : ""} ${selectedIds.has(target.id) ? "bg-teal-50/50" : ""}`}
          >
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={selectedIds.has(target.id)}
                onChange={() => toggleSelected(target.id)}
                className="h-4 w-4 rounded border-zinc-300 accent-teal-700"
                aria-label={`Select ${target.group_name}`}
              />
            </label>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-semibold">{target.group_name}</p>
                <span
                  className={`rounded-full px-2.5 py-1 text-[10px] font-bold uppercase ${target.available ? "bg-teal-50 text-teal-800" : "bg-zinc-100 text-zinc-500"}`}
                >
                  {target.available ? "reported online" : "not reported online"}
                </span>
              </div>
              <p className="mt-1 line-clamp-2 text-xs leading-5 text-zinc-500">
                {target.description || target.title || "No catalog description"}
              </p>
            </div>
            <div>
              <p className="font-mono text-xs text-zinc-600">
                {target.address_hint}
              </p>
              <p className="mt-1 text-xs text-zinc-400">
                Address stored locally · not clickable
              </p>
            </div>
            <div>
              <p className="text-xs font-semibold text-zinc-700">
                Last capture
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                {target.last_capture_at
                  ? formatTime(target.last_capture_at)
                  : "Never"}
              </p>
            </div>
            <div className="flex flex-wrap gap-2 xl:justify-end">
              <button
                type="button"
                className={
                  target.capture_enabled ? "button-primary" : "button-secondary"
                }
                onClick={() => void toggle(target)}
              >
                {target.capture_enabled ? (
                  <Check size={17} />
                ) : (
                  <Plus size={17} />
                )}
                {target.capture_enabled ? "Allowed" : "Allow"}
              </button>
              <button
                type="button"
                title={
                  runtime?.operating_mode !== "active"
                    ? "Switch monitoring to Active mode first"
                    : "Capture this allowlisted site"
                }
                className="button-secondary"
                disabled={
                  !target.capture_enabled ||
                  !data?.worker_online ||
                  runtime?.operating_mode !== "active"
                }
                onClick={() => setConfirmCapture(target)}
              >
                <Camera size={17} />
                Capture
              </button>
            </div>
          </div>
        ))}
        {!loading && !visibleTargets.length && (
          <div className="p-10 text-center text-sm text-zinc-500">
            No DLS locations match this search.
          </div>
        )}
      </div>
      {(data?.targets.length ?? 0) > 120 && (
        <p className="mt-3 text-xs text-zinc-500">
          Showing the first 120 results. Search by group to narrow the catalog.
        </p>
      )}
      {data && (
        <section className="mt-9">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
            <div>
              <h3 className="text-xl font-semibold">Recent capture jobs</h3>
              <p className="mt-1 text-sm text-zinc-500">
                Filter operational state and group captures for faster analyst
                review.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <p className="text-xs text-zinc-500" aria-live="polite">
                Showing {filteredCaptureJobs.length.toLocaleString()} of{" "}
                {data.jobs.length.toLocaleString()} recent jobs
              </p>
              <button
                type="button"
                className="button-secondary !min-h-10 px-3 text-xs text-rose-700"
                disabled={
                  !((data.job_status_counts?.queued ?? 0) +
                    (data.job_status_counts?.failed ?? 0))
                }
                onClick={() => {
                  setClearJobStatuses(["queued", "failed"]);
                  setClearJobsError("");
                  setClearJobsOpen(true);
                }}
              >
                <Trash size={16} />
                Clear queued / failed
              </button>
            </div>
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
            {(
              [
                { key: "all", label: "All" },
                { key: "attention", label: "Needs attention" },
                { key: "queued", label: "Queued" },
                { key: "running", label: "Running" },
                { key: "completed", label: "Completed" },
                { key: "failed", label: "Failed" },
              ] as Array<{ key: CaptureJobFilter; label: string }>
            ).map((item) => (
              <button
                key={item.key}
                type="button"
                aria-pressed={jobFilter === item.key}
                onClick={() => setJobFilter(item.key)}
                className={`rounded-2xl border px-4 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-600 ${
                  jobFilter === item.key
                    ? "border-teal-700 bg-teal-50 text-teal-900"
                    : "border-zinc-200 bg-white text-zinc-600 hover:border-teal-300"
                }`}
              >
                <span className="block text-xs">{item.label}</span>
                <span className="mt-1 block font-mono text-xl text-zinc-900">
                  {captureJobCounts[item.key].toLocaleString()}
                </span>
              </button>
            ))}
          </div>
          <div className="mt-4 grid gap-3 rounded-2xl border border-zinc-200 bg-white p-4 lg:grid-cols-[minmax(0,1fr)_14rem_14rem_auto] lg:items-end">
            <Field label="Search jobs">
              <div className="relative">
                <MagnifyingGlass
                  size={17}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400"
                />
                <input
                  value={jobQuery}
                  onChange={(event) => setJobQuery(event.target.value)}
                  className="input pl-10"
                  placeholder="Actor, victim, status, or error"
                  aria-label="Search recent capture jobs"
                />
              </div>
            </Field>
            <Field label="Group by">
              <CustomSelect
                ariaLabel="Capture job grouping"
                value={jobGrouping}
                onChange={(value) =>
                  setJobGrouping(value as CaptureJobGrouping)
                }
                options={[
                  { value: "status", label: "Status" },
                  { value: "actor", label: "Threat actor" },
                  { value: "none", label: "No grouping" },
                ]}
              />
            </Field>
            <Field label="Sort jobs">
              <CustomSelect
                ariaLabel="Capture job sorting"
                value={jobSort}
                onChange={(value) => setJobSort(value as CaptureJobSort)}
                options={[
                  { value: "newest", label: "Newest first" },
                  { value: "oldest", label: "Oldest first" },
                  { value: "actor", label: "Threat actor" },
                ]}
              />
            </Field>
            <button
              type="button"
              className="button-secondary"
              disabled={
                !jobQuery &&
                jobFilter === "all" &&
                jobGrouping === "status" &&
                jobSort === "newest"
              }
              onClick={() => {
                setJobQuery("");
                setJobFilter("all");
                setJobGrouping("status");
                setJobSort("newest");
              }}
            >
              <XCircle size={17} />
              Reset
            </button>
          </div>
          {filteredCaptureJobs.length ? (
            <div className="mt-4 space-y-4">
              {captureJobGroups.map((group) => (
                <div
                  key={group.key}
                  className="overflow-hidden rounded-2xl border border-zinc-200 bg-white"
                >
                  {jobGrouping !== "none" && (
                    <div className="flex items-center justify-between gap-3 border-b border-zinc-200 bg-zinc-50 px-5 py-3">
                      <p className="text-sm text-zinc-700">{group.label}</p>
                      <span className="rounded-full bg-white px-2.5 py-1 font-mono text-xs text-zinc-600 ring-1 ring-zinc-200">
                        {group.jobs.length.toLocaleString()}
                      </span>
                    </div>
                  )}
                  <div className="divide-y divide-zinc-100">
                    {group.jobs.map((job) => (
                      <motion.div
                        layout
                        key={job.id}
                        initial={{ opacity: 0.7 }}
                        animate={{ opacity: 1 }}
                        className="flex flex-col justify-between gap-4 p-5 transition-colors duration-300 sm:flex-row sm:items-center"
                      >
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-sm font-semibold">
                              {job.group_name}
                            </p>
                            <motion.span
                              layout
                              key={job.status}
                              initial={{ opacity: 0.55, scale: 0.94 }}
                              animate={{ opacity: 1, scale: 1 }}
                              className={`rounded-full px-2 py-1 text-[10px] font-bold uppercase transition-colors duration-300 ${
                                job.status === "completed"
                                  ? "bg-teal-50 text-teal-800"
                                  : job.status === "failed"
                                    ? "bg-red-50 text-red-800"
                                    : job.status === "running"
                                      ? "bg-sky-100 text-sky-800"
                                      : "bg-amber-100 text-amber-800"
                              }`}
                            >
                              {captureStatusLabel(job.status)}
                            </motion.span>
                    {job.status === "completed" && (
                      <span
                        className={`rounded-full px-2 py-1 text-[10px] font-bold uppercase ${job.coverage_status === "stable" ? "bg-teal-50 text-teal-800" : "bg-amber-100 text-amber-800"}`}
                      >
                        {job.coverage_status === "stable"
                          ? "Stable coverage"
                          : job.coverage_status === "height_limit"
                            ? "Height limit reached"
                            : job.coverage_status === "scroll_limit"
                              ? "Scroll limit reached"
                              : "Coverage not measured"}
                      </span>
                    )}
                    {job.status === "completed" && (
                      <span
                        className={`rounded-full px-2 py-1 text-[10px] font-bold uppercase ${
                          job.evidence_readiness === "ready"
                            ? "bg-teal-50 text-teal-800"
                            : job.evidence_readiness === "not_ready"
                              ? "bg-red-50 text-red-800"
                              : "bg-amber-100 text-amber-800"
                        }`}
                      >
                        {job.evidence_readiness === "ready"
                          ? "Victim evidence ready"
                          : job.evidence_readiness === "not_ready"
                            ? "Evidence not ready"
                            : job.evidence_readiness === "review"
                              ? "Analyst review required"
                              : "Evidence not assessed"}
                      </span>
                    )}
                    {job.continuity_status === "matched" && (
                      <span className="rounded-full bg-teal-50 px-2 py-1 text-[10px] font-bold uppercase text-teal-800">
                        Previous victim anchor found
                      </span>
                    )}
                    {job.more_content_suspected && (
                      <span className="rounded-full bg-red-50 px-2 py-1 text-[10px] font-bold uppercase text-red-800">
                        More content suspected
                      </span>
                    )}
                    {job.pagination_detected && (
                      <span className="rounded-full bg-amber-100 px-2 py-1 text-[10px] font-bold uppercase text-amber-800">
                        Pagination detected
                      </span>
                    )}
                    {job.duplicate_of_job_id && (
                      <span className="rounded-full bg-zinc-100 px-2 py-1 text-[10px] font-bold uppercase text-zinc-600">
                        Duplicate text
                      </span>
                    )}
                    {job.status_changed && (
                      <span className="rounded-full bg-amber-100 px-2 py-1 text-[10px] font-bold uppercase text-amber-800">
                        Status changed
                      </span>
                    )}
                    {job.css_blur_element_count > 0 && (
                      <span className="rounded-full bg-sky-100 px-2 py-1 text-[10px] font-bold uppercase text-sky-800">
                        Source CSS blur detected
                      </span>
                    )}
                  </div>
                  <p className="mt-1 font-mono text-xs text-zinc-400">
                    {job.address_hint}
                  </p>
                  {job.status === "completed" && (
                    <>
                      <p
                        className={`mt-2 text-xs ${job.capture_truncated ? "text-amber-700" : "text-zinc-500"}`}
                      >
                        {job.scroll_count.toLocaleString()} scroll passes ·{" "}
                        {job.page_height.toLocaleString()} px coverage ·{" "}
                        {job.segment_count.toLocaleString()} review page
                        {job.segment_count === 1 ? "" : "s"}
                        {job.capture_truncated
                          ? " · review coverage warning"
                          : " · height stabilized"}
                      </p>
                      <p
                        className={`mt-1 text-xs ${job.more_content_suspected ? "font-semibold text-red-700" : "text-zinc-500"}`}
                      >
                        {job.continuity_status === "matched"
                          ? `OCR continuity matched a previous first-page anchor${job.continuity_page ? ` on review page ${job.continuity_page}` : ""}${job.continuity_anchor ? `: ${job.continuity_anchor}` : ""}.`
                          : job.continuity_status === "missing"
                            ? `Previous OCR anchor was not found${job.pagination_detected ? "; a next/load-more control is visible" : ""}.`
                            : job.continuity_status === "ocr_unavailable"
                              ? "OCR continuity could not be evaluated."
                              : "This capture establishes the first OCR continuity baseline."}
                      </p>
                      <p className="mt-1 text-xs text-zinc-500">
                        Text: {job.extraction_method || "not extracted"}
                        {job.text_path
                          ? ` · +${job.added_line_count.toLocaleString()} / −${job.removed_line_count.toLocaleString()} lines`
                          : ""}
                        {job.detected_statuses.length
                          ? ` · signals: ${job.detected_statuses.join(", ")}`
                          : ""}
                        {job.css_blur_element_count > 0
                          ? ` · ${job.css_blur_element_count} visibly blurred source element${job.css_blur_element_count === 1 ? "" : "s"}`
                          : ""}
                      </p>
                      <p
                        className={`mt-1 text-xs ${job.evidence_readiness === "not_ready" ? "text-red-700" : job.evidence_readiness === "review" ? "text-amber-700" : "text-zinc-500"}`}
                      >
                        {job.readiness_reason ||
                          "Evidence readiness has not been assessed."}
                      </p>
                      {job.victim_candidates.length > 0 && (
                        <div className="mt-3 max-w-3xl rounded-xl border border-teal-100 bg-teal-50/50 px-3 py-3">
                          <p className="text-[10px] uppercase tracking-[0.14em] text-teal-800">
                            Latest observed victim candidates
                          </p>
                          <div className="mt-2 flex flex-wrap gap-2">
                            {job.victim_candidates.slice(0, 10).map((candidate) => (
                              <span
                                key={`${candidate.name}-${candidate.domain}`}
                                title={`${candidate.source.replaceAll("_", " ")} · ${candidate.confidence} confidence${candidate.published_at ? ` · ${formatTime(candidate.published_at)}` : ""}`}
                                className="rounded-lg bg-white px-2.5 py-1.5 text-xs text-zinc-700 ring-1 ring-teal-100"
                              >
                                {candidate.name}
                                {candidate.domain && candidate.domain !== candidate.name
                                  ? ` · ${candidate.domain}`
                                  : ""}
                              </span>
                            ))}
                          </div>
                          {job.victim_candidates.length > 10 && (
                            <p className="mt-2 text-[11px] text-teal-800">
                              +{job.victim_candidates.length - 10} additional candidates
                              retained in this capture record
                            </p>
                          )}
                          <p className="mt-2 text-[11px] leading-4 text-zinc-500">
                            Candidates are locally observed names or domains, not
                            confirmation of compromise. Verify against the screenshot
                            before escalation.
                          </p>
                        </div>
                      )}
                    </>
                  )}
                  {job.error && (
                    <p className="mt-2 max-w-2xl text-xs text-red-700">
                      {job.error}
                    </p>
                  )}
                  {job.content_sha256 && (
                    <p className="mt-2 break-all font-mono text-[10px] text-zinc-400">
                      Capture SHA-256 {job.content_sha256}
                    </p>
                  )}
                  {job.text_sha256 && (
                    <p className="mt-1 break-all font-mono text-[10px] text-zinc-400">
                      Text SHA-256 {job.text_sha256}
                    </p>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-3 sm:justify-end">
                  <div className="text-right">
                    <p
                      className={`text-xs font-semibold uppercase ${job.status === "completed" ? "text-teal-700" : job.status === "failed" ? "text-red-700" : "text-zinc-600"}`}
                    >
                      {job.status}
                    </p>
                    <p className="mt-1 text-xs text-zinc-400">
                      {formatTime(job.completed_at || job.requested_at)}
                    </p>
                  </div>
                  {job.status === "completed" && (
                    <>
                      <button
                        type="button"
                        onClick={() =>
                          setReviewCapture({
                            job,
                            page: 1,
                            expanded: false,
                            zoom: 1,
                          })
                        }
                        className="button-secondary !min-h-10 px-4 text-xs"
                      >
                        <Camera size={16} />
                        Review {job.segment_count || 1} page
                        {job.segment_count === 1 ? "" : "s"}
                      </button>
                      {job.text_path && (
                        <a
                          href={api.captureTextUrl(job.id)}
                          target="_blank"
                          rel="noreferrer"
                          className="button-secondary !min-h-10 px-4 text-xs"
                        >
                          View text
                        </a>
                      )}
                    </>
                  )}
                </div>
              </motion.div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="mt-4 rounded-2xl border border-dashed border-zinc-300 bg-white p-10 text-center">
              <p className="text-sm text-zinc-600">
                {data.jobs.length
                  ? "No capture jobs match the selected filters."
                  : "No capture jobs have been queued yet."}
              </p>
              {(jobQuery || jobFilter !== "all") && (
                <button
                  type="button"
                  className="mt-3 text-sm text-teal-800 underline"
                  onClick={() => {
                    setJobQuery("");
                    setJobFilter("all");
                  }}
                >
                  Clear job filters
                </button>
              )}
            </div>
          )}
        </section>
      )}
      <AnimatePresence>
        {confirmCapture && (
          <Modal
            title={`Capture ${confirmCapture.group_name}?`}
            description="This makes one Tor-routed visit to the allowlisted site, scrolls its public victim list, and retains numbered review PNGs plus local DOM/OCR text."
            onClose={() => setConfirmCapture(null)}
          >
            <InlineNotice tone="neutral">
              No links, forms, authentication, messages, or download controls
              will be used. OCR runs locally in Kali; the capture remains an
              unverified threat-actor allegation and requires analyst review.
            </InlineNotice>
            <div className="mt-6 flex flex-wrap justify-end gap-3">
              <button
                type="button"
                className="button-secondary"
                onClick={() => setConfirmCapture(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="button-primary"
                onClick={() => void queue(confirmCapture)}
              >
                <Camera size={17} />
                Start one capture
              </button>
            </div>
          </Modal>
        )}
        {reviewCapture && (
          <Modal
            wide
            fullScreen={reviewCapture.expanded}
            title={`${reviewCapture.job.group_name} evidence`}
            description={`Review page ${reviewCapture.page} of ${reviewCapture.job.segment_count || 1}. Blurring or masking visible inside the image is preserved as observed on the source page.`}
            onClose={() => setReviewCapture(null)}
          >
            <div className="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-zinc-200 bg-zinc-50 px-3 py-2">
              <p className="text-xs text-zinc-500">
                Use full screen or zoom to inspect victim names and source-page details.
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  className="button-secondary !min-h-9 px-3 text-xs"
                  disabled={reviewCapture.zoom <= 1}
                  onClick={() =>
                    setReviewCapture({
                      ...reviewCapture,
                      zoom: Math.max(1, reviewCapture.zoom - 0.5),
                    })
                  }
                >
                  <MagnifyingGlassMinus size={15} />
                  Zoom out
                </button>
                <button
                  type="button"
                  className="button-secondary !min-h-9 min-w-16 px-3 font-mono text-xs"
                  onClick={() =>
                    setReviewCapture({ ...reviewCapture, zoom: 1 })
                  }
                  title="Reset screenshot zoom"
                >
                  {Math.round(reviewCapture.zoom * 100)}%
                </button>
                <button
                  type="button"
                  className="button-secondary !min-h-9 px-3 text-xs"
                  disabled={reviewCapture.zoom >= 2.5}
                  onClick={() =>
                    setReviewCapture({
                      ...reviewCapture,
                      zoom: Math.min(2.5, reviewCapture.zoom + 0.5),
                    })
                  }
                >
                  <MagnifyingGlassPlus size={15} />
                  Zoom in
                </button>
                <button
                  type="button"
                  className="button-secondary !min-h-9 px-3 text-xs"
                  onClick={() =>
                    setReviewCapture({
                      ...reviewCapture,
                      expanded: !reviewCapture.expanded,
                    })
                  }
                >
                  {reviewCapture.expanded ? (
                    <ArrowsInSimple size={15} />
                  ) : (
                    <ArrowsOutSimple size={15} />
                  )}
                  {reviewCapture.expanded ? "Exit full screen" : "Full screen"}
                </button>
              </div>
            </div>
            <div
              className={`mt-3 overflow-auto rounded-2xl border border-zinc-200 bg-zinc-950 ${reviewCapture.expanded ? "max-h-[calc(100dvh-15rem)]" : "max-h-[65vh]"}`}
            >
              <img
                src={api.captureScreenshotUrl(
                  reviewCapture.job.id,
                  reviewCapture.page,
                )}
                alt={`${reviewCapture.job.group_name} capture page ${reviewCapture.page}`}
                className="mx-auto h-auto max-w-none object-contain transition-[width] duration-200"
                style={{ width: `${reviewCapture.zoom * 100}%` }}
              />
            </div>
            <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
              <a
                href={api.captureScreenshotUrl(
                  reviewCapture.job.id,
                  reviewCapture.page,
                )}
                target="_blank"
                rel="noreferrer"
                className="button-secondary !min-h-10 px-4 text-xs"
              >
                Open original page
              </a>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  className="button-secondary !min-h-10 px-4 text-xs"
                  disabled={reviewCapture.page <= 1}
                  onClick={() =>
                    setReviewCapture({
                      ...reviewCapture,
                      page: reviewCapture.page - 1,
                      zoom: 1,
                    })
                  }
                >
                  <CaretLeft size={16} />
                  Previous
                </button>
                <span className="font-mono text-xs text-zinc-500">
                  {reviewCapture.page} / {reviewCapture.job.segment_count || 1}
                </span>
                <button
                  type="button"
                  className="button-secondary !min-h-10 px-4 text-xs"
                  disabled={
                    reviewCapture.page >= (reviewCapture.job.segment_count || 1)
                  }
                  onClick={() =>
                    setReviewCapture({
                      ...reviewCapture,
                      page: reviewCapture.page + 1,
                      zoom: 1,
                    })
                  }
                >
                  Next
                  <CaretRight size={16} />
                </button>
              </div>
            </div>
          </Modal>
        )}
        {clearJobsOpen && (
          <Modal
            title="Clear capture jobs?"
            description="Choose which non-evidence operational records to remove from the capture queue and job history."
            onClose={() => {
              if (!clearingJobs) setClearJobsOpen(false);
            }}
          >
            <InlineNotice tone="danger">
              Queued jobs will be cancelled and failed job records permanently
              removed. Running jobs, completed evidence, screenshots, OCR text,
              and successful audit records are always preserved.
            </InlineNotice>
            {clearJobsError && (
              <InlineNotice tone="danger">{clearJobsError}</InlineNotice>
            )}
            <div className="mt-5 grid gap-3 sm:grid-cols-2">
              {(
                [
                  {
                    status: "queued",
                    label: "Queued jobs",
                    helper: "Cancel jobs that have not started.",
                  },
                  {
                    status: "failed",
                    label: "Failed jobs",
                    helper: "Remove unsuccessful history records.",
                  },
                ] as Array<{
                  status: ClearableCaptureStatus;
                  label: string;
                  helper: string;
                }>
              ).map((item) => {
                const selected = clearJobStatuses.includes(item.status);
                const count = data?.job_status_counts?.[item.status] ?? 0;
                return (
                  <button
                    key={item.status}
                    type="button"
                    aria-pressed={selected}
                    disabled={clearingJobs || count === 0}
                    onClick={() =>
                      setClearJobStatuses((current) =>
                        current.includes(item.status)
                          ? current.filter((status) => status !== item.status)
                          : [...current, item.status],
                      )
                    }
                    className={`rounded-2xl border p-4 text-left transition-colors ${
                      selected
                        ? "border-rose-400 bg-rose-50 ring-2 ring-rose-100"
                        : "border-zinc-200 bg-white hover:border-zinc-300"
                    } disabled:cursor-not-allowed disabled:opacity-50`}
                  >
                    <span className="flex items-center justify-between gap-3">
                      <span className="text-sm font-medium text-zinc-800">
                        {item.label}
                      </span>
                      <span className="rounded-full bg-white px-2.5 py-1 font-mono text-xs text-zinc-700 ring-1 ring-zinc-200">
                        {count.toLocaleString()}
                      </span>
                    </span>
                    <span className="mt-2 block text-xs leading-5 text-zinc-500">
                      {item.helper}
                    </span>
                  </button>
                );
              })}
            </div>
            <div className="mt-6 flex flex-wrap justify-end gap-3">
              <button
                type="button"
                className="button-secondary"
                disabled={clearingJobs}
                onClick={() => setClearJobsOpen(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="button-primary !bg-rose-700 hover:!bg-rose-800"
                disabled={
                  clearingJobs ||
                  !clearJobStatuses.length ||
                  clearJobStatuses.reduce(
                    (total, status) =>
                      total + (data?.job_status_counts?.[status] ?? 0),
                    0,
                  ) === 0
                }
                onClick={() => void clearCaptureJobs()}
              >
                {clearingJobs ? (
                  <SpinnerGap className="animate-spin" size={18} />
                ) : (
                  <Trash size={18} />
                )}
                Clear{" "}
                {clearJobStatuses
                  .reduce(
                    (total, status) =>
                      total + (data?.job_status_counts?.[status] ?? 0),
                    0,
                  )
                  .toLocaleString()} jobs
              </button>
            </div>
          </Modal>
        )}
        {showKaliGuide && (
          <KaliSetupGuide onClose={() => setShowKaliGuide(false)} />
        )}
      </AnimatePresence>
    </div>
  );
}

function KaliSetupGuide({ onClose }: { onClose: () => void }) {
  return (
    <Modal
      title="Recommended Kali deployment"
      description="Run the complete platform inside a dedicated Kali VM when direct-site capture is required. This keeps Tor, Chromium, evidence, and the GUI isolated from the host."
      onClose={onClose}
    >
      <div className="mt-6 rounded-2xl border border-teal-200 bg-teal-50 p-5">
        <p className="text-sm font-semibold text-teal-900">
          Works with your preferred VM platform
        </p>
        <p className="mt-2 text-xs leading-5 text-teal-800">
          Use NAT networking in VMware, VirtualBox, Parallels, UTM, or another
          trusted hypervisor. Keep the app bound to 127.0.0.1, take a VM
          snapshot, and open the GUI inside Kali. Avoid shared folders and
          clipboard while collecting.
        </p>
      </div>
      <ol className="mt-6 space-y-5">
        <li className="flex gap-3">
          <StepNumber value="1" />
          <div>
            <p className="text-sm font-semibold">Copy the project into Kali</p>
            <p className="mt-1 text-xs leading-5 text-zinc-500">
              Use SCP or a temporary read-only transfer. Place the folder under
              your Kali home directory, then disable the transfer mechanism.
            </p>
          </div>
        </li>
        <li className="flex gap-3">
          <StepNumber value="2" />
          <div className="min-w-0">
            <p className="text-sm font-semibold">
              Run the one-command installer
            </p>
            <pre className="mt-2 overflow-x-auto rounded-xl bg-zinc-900 p-4 font-mono text-xs text-zinc-100">
              chmod +x setup-kali.sh{`\n`}./setup-kali.sh --prepare-capture
            </pre>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <a
                href="/downloads/setup-kali.sh"
                download="setup-kali.sh"
                className="button-secondary !min-h-10 px-4 text-xs"
              >
                <DownloadSimple size={17} />
                Download setup-kali.sh
              </a>
              <span className="text-xs text-zinc-500">
                Save it in the ExtortSignal project folder before running it.
              </span>
            </div>
            <p className="mt-3 text-xs leading-5 text-zinc-500">
              The script requests sudo only for required Kali packages and the
              local system service.
            </p>
          </div>
        </li>
        <li className="flex gap-3">
          <StepNumber value="3" />
          <div>
            <p className="text-sm font-semibold">Open the GUI inside Kali</p>
            <p className="mt-1 font-mono text-xs text-zinc-600">
              http://127.0.0.1:8765
            </p>
          </div>
        </li>
        <li className="flex gap-3">
          <StepNumber value="4" />
          <div>
            <p className="text-sm font-semibold">Allowlist cautiously</p>
            <p className="mt-1 text-xs leading-5 text-zinc-500">
              Enable only attributed sites you need. Do not authenticate, submit
              forms, message actors, or download leaked data.
            </p>
          </div>
        </li>
      </ol>
      <InlineNotice tone="neutral">
        With --prepare-capture, the installer enables the local screenshot
        worker. Captures remain opt-in, Tor-routed, screenshot-only, and stored
        under the private data/captures directory.
      </InlineNotice>
      <div className="mt-6 flex justify-end">
        <button type="button" className="button-primary" onClick={onClose}>
          <Check size={18} />
          Understood
        </button>
      </div>
    </Modal>
  );
}

type DropdownOption = { value: string; label: string };

function StaticCustomSelect({
  ariaLabel,
  value,
  options,
  onChange,
  placeholder = "Choose an option",
  className = "",
}: {
  ariaLabel: string;
  value: string;
  options: DropdownOption[];
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const selected = options.find((option) => option.value === value);
  useEffect(() => {
    const close = (event: MouseEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  return (
    <div ref={root} className={`relative min-w-0 ${className}`}>
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        onKeyDown={(event) => {
          if (event.key === "Escape") setOpen(false);
        }}
        className={`input flex items-center justify-between gap-3 text-left hover:border-zinc-300 hover:bg-zinc-50 ${open ? "border-teal-700 ring-4 ring-teal-700/10" : ""}`}
      >
        <span
          className={`min-w-0 truncate ${selected ? "text-zinc-900" : "text-zinc-500"}`}
        >
          {selected?.label ?? placeholder}
        </span>
        <CaretDown
          size={17}
          className={`shrink-0 text-zinc-400 transition ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && (
        <div
          role="listbox"
          aria-label={ariaLabel}
          className="absolute z-50 mt-2 max-h-64 min-w-full overflow-y-auto rounded-2xl border border-zinc-200 bg-white p-2 shadow-[0_20px_50px_-20px_rgba(24,24,27,.35)]"
        >
          {options.map((option) => (
            <button
              type="button"
              role="option"
              aria-selected={option.value === value}
              key={option.value}
              onClick={() => {
                onChange(option.value);
                setOpen(false);
              }}
              className={`flex w-full items-center justify-between gap-4 rounded-xl px-3 py-2.5 text-left text-sm transition hover:bg-teal-50 hover:text-teal-900 ${option.value === value ? "bg-teal-50 font-semibold text-teal-900" : "text-zinc-700"}`}
            >
              <span className="whitespace-nowrap">{option.label}</span>
              {option.value === value && (
                <Check size={15} className="shrink-0 text-teal-700" />
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function SearchableSelect({
  ariaLabel,
  value,
  options,
  onChange,
  placeholder = "Choose an option",
  searchPlaceholder = "Search options…",
}: {
  ariaLabel: string;
  value: string;
  options: DropdownOption[];
  onChange: (value: string) => void;
  placeholder?: string;
  searchPlaceholder?: string;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const root = useRef<HTMLDivElement>(null);
  const selected = options.find((option) => option.value === value);
  const filtered = options.filter((option) =>
    option.label.toLowerCase().includes(search.trim().toLowerCase()),
  );
  useEffect(() => {
    const close = (event: MouseEvent) => {
      if (!root.current?.contains(event.target as Node)) {
        setOpen(false);
        setSearch("");
      }
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  return (
    <div ref={root} className="relative min-w-0">
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => {
          setOpen((current) => !current);
          setSearch("");
        }}
        className={`input flex items-center justify-between gap-3 text-left hover:border-zinc-300 hover:bg-zinc-50 ${open ? "border-teal-700 ring-4 ring-teal-700/10" : ""}`}
      >
        <span
          className={`min-w-0 truncate ${selected ? "text-zinc-900" : "text-zinc-500"}`}
        >
          {selected?.label ?? placeholder}
        </span>
        <CaretDown
          size={17}
          className={`shrink-0 text-zinc-400 transition ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && (
        <div className="absolute z-50 mt-2 w-full min-w-[260px] rounded-2xl border border-zinc-200 bg-white p-2 shadow-[0_20px_50px_-20px_rgba(24,24,27,.35)]">
          <label className="mb-2 flex min-h-10 items-center gap-2 rounded-xl border border-zinc-200 px-3 focus-within:border-teal-700 focus-within:ring-2 focus-within:ring-teal-700/10">
            <MagnifyingGlass size={15} className="shrink-0 text-zinc-400" />
            <span className="sr-only">{searchPlaceholder}</span>
            <input
              autoFocus
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  setOpen(false);
                  setSearch("");
                }
              }}
              className="w-full bg-transparent text-sm outline-none"
              placeholder={searchPlaceholder}
            />
          </label>
          <div
            role="listbox"
            aria-label={ariaLabel}
            className="max-h-56 overflow-y-auto"
          >
            {filtered.map((option) => (
              <button
                type="button"
                role="option"
                aria-selected={option.value === value}
                key={option.value}
                onClick={() => {
                  onChange(option.value);
                  setOpen(false);
                  setSearch("");
                }}
                className={`flex w-full items-center justify-between gap-4 rounded-xl px-3 py-2.5 text-left text-sm transition hover:bg-teal-50 hover:text-teal-900 ${option.value === value ? "bg-teal-50 font-semibold text-teal-900" : "text-zinc-700"}`}
              >
                <span className="truncate">{option.label}</span>
                {option.value === value && (
                  <Check size={15} className="shrink-0 text-teal-700" />
                )}
              </button>
            ))}
            {!filtered.length && (
              <p className="px-3 py-5 text-center text-xs text-zinc-500">
                No matching options
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function CustomSelect(props: {
  ariaLabel: string;
  value: string;
  options: DropdownOption[];
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}) {
  if (props.options.length > 8) {
    const { className, ...searchableProps } = props;
    return (
      <div className={className}>
        <SearchableSelect
          {...searchableProps}
          searchPlaceholder={`Search ${props.ariaLabel.toLowerCase()}…`}
        />
      </div>
    );
  }
  return <StaticCustomSelect {...props} />;
}

function CustomDatePicker({
  ariaLabel,
  value,
  min,
  max,
  onChange,
  align = "left",
}: {
  ariaLabel: string;
  value: string;
  min?: string;
  max?: string;
  onChange: (value: string) => void;
  align?: "left" | "right";
}) {
  const parse = (date: string) => (date ? new Date(`${date}T00:00:00`) : null);
  const today = new Date();
  const initial = parse(value) ?? today;
  const [open, setOpen] = useState(false);
  const [viewMonth, setViewMonth] = useState(
    () => new Date(initial.getFullYear(), initial.getMonth(), 1),
  );
  const rootRef = useRef<HTMLDivElement>(null);
  const dateKey = (date: Date) =>
    `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
  const todayKey = dateKey(today);
  const selected = parse(value);
  const display = selected
    ? selected.toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      })
    : "Select date";
  const monthLabel = viewMonth.toLocaleDateString(undefined, {
    month: "long",
    year: "numeric",
  });
  const gridStart = new Date(
    viewMonth.getFullYear(),
    viewMonth.getMonth(),
    1 - new Date(viewMonth.getFullYear(), viewMonth.getMonth(), 1).getDay(),
  );
  const days = Array.from(
    { length: 42 },
    (_, index) =>
      new Date(
        gridStart.getFullYear(),
        gridStart.getMonth(),
        gridStart.getDate() + index,
      ),
  );
  const allowed = (key: string) => (!min || key >= min) && (!max || key <= max);
  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);
  const choose = (date: Date) => {
    const key = dateKey(date);
    if (!allowed(key)) return;
    onChange(key);
    setViewMonth(new Date(date.getFullYear(), date.getMonth(), 1));
    setOpen(false);
  };
  const toggle = () => {
    if (!open) {
      const target = parse(value) ?? today;
      setViewMonth(new Date(target.getFullYear(), target.getMonth(), 1));
    }
    setOpen((current) => !current);
  };
  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={toggle}
        className={`input flex w-full cursor-pointer items-center justify-between gap-3 text-left transition-colors duration-200 hover:border-teal-300 focus-visible:border-teal-700 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-teal-700/10 ${value ? "text-zinc-800" : "text-zinc-400"}`}
      >
        <span>{display}</span>
        <CalendarBlank
          size={18}
          className={open ? "text-teal-700" : "text-zinc-400"}
        />
      </button>
      {open && (
        <div
          role="dialog"
          aria-label={`${ariaLabel} calendar`}
          className={`absolute top-[calc(100%+.5rem)] z-[70] w-[21rem] max-w-[calc(100vw-2rem)] rounded-2xl border border-zinc-200 bg-white p-4 shadow-2xl ${align === "right" ? "right-0" : "left-0"}`}
        >
          <div className="flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={() =>
                setViewMonth(
                  new Date(
                    viewMonth.getFullYear(),
                    viewMonth.getMonth() - 1,
                    1,
                  ),
                )
              }
              className="grid h-11 w-11 cursor-pointer place-items-center rounded-xl border border-zinc-200 text-zinc-600 transition-colors hover:bg-zinc-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-600"
              aria-label="Previous month"
            >
              <CaretLeft size={17} />
            </button>
            <p
              className="text-sm font-semibold text-zinc-800"
              aria-live="polite"
            >
              {monthLabel}
            </p>
            <button
              type="button"
              onClick={() =>
                setViewMonth(
                  new Date(
                    viewMonth.getFullYear(),
                    viewMonth.getMonth() + 1,
                    1,
                  ),
                )
              }
              className="grid h-11 w-11 cursor-pointer place-items-center rounded-xl border border-zinc-200 text-zinc-600 transition-colors hover:bg-zinc-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-600"
              aria-label="Next month"
            >
              <CaretRight size={17} />
            </button>
          </div>
          <div className="mt-4 grid grid-cols-7 text-center text-[10px] font-bold uppercase tracking-wide text-zinc-400">
            {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map((day) => (
              <span key={day} className="py-2">
                {day}
              </span>
            ))}
          </div>
          <div className="grid grid-cols-7 gap-0.5">
            {days.map((day) => {
              const key = dateKey(day);
              const inMonth = day.getMonth() === viewMonth.getMonth();
              const isSelected = key === value;
              const isToday = key === todayKey;
              const enabled = allowed(key);
              return (
                <button
                  type="button"
                  key={key}
                  disabled={!enabled}
                  onClick={() => choose(day)}
                  aria-label={day.toLocaleDateString(undefined, {
                    weekday: "long",
                    year: "numeric",
                    month: "long",
                    day: "numeric",
                  })}
                  aria-pressed={isSelected}
                  className={`grid min-h-11 cursor-pointer place-items-center rounded-xl text-xs font-semibold transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-600 disabled:cursor-not-allowed disabled:opacity-25 ${isSelected ? "bg-teal-700 text-white shadow-sm" : isToday ? "bg-teal-50 text-teal-800 ring-1 ring-teal-200" : inMonth ? "text-zinc-700 hover:bg-zinc-100" : "text-zinc-400 hover:bg-zinc-50"}`}
                >
                  {day.getDate()}
                </button>
              );
            })}
          </div>
          <div className="mt-4 flex items-center justify-between border-t border-zinc-100 pt-3">
            <button
              type="button"
              disabled={!value}
              onClick={() => {
                onChange("");
                setOpen(false);
              }}
              className="cursor-pointer text-xs font-semibold text-zinc-500 transition-colors hover:text-zinc-900 disabled:cursor-not-allowed disabled:text-zinc-300"
            >
              Clear
            </button>
            <button
              type="button"
              disabled={!allowed(todayKey)}
              onClick={() => choose(today)}
              className="cursor-pointer rounded-lg bg-teal-50 px-3 py-2 text-xs font-semibold text-teal-800 transition-colors hover:bg-teal-100 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Today
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  const plural =
    (
      {
        Country: "countries",
        Industry: "industries",
        Status: "statuses",
      } as Record<string, string>
    )[label] || `${label.toLowerCase()}s`;
  return (
    <SearchableSelect
      ariaLabel={label}
      value={value}
      onChange={onChange}
      searchPlaceholder={`Search ${label.toLowerCase()}…`}
      options={[
        { value: "", label: `All ${plural}` },
        ...options.map((option) => ({
          value: option,
          label: option.replaceAll("_", " "),
        })),
      ]}
    />
  );
}
function IntelligenceMetric({
  label,
  value,
  helper,
}: {
  label: string;
  value: number;
  helper: string;
}) {
  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-5">
      <p className="text-xs font-semibold uppercase tracking-wide text-zinc-400">
        {label}
      </p>
      <p className="mt-3 font-mono text-3xl font-semibold tracking-tight">
        <AnimatedNumber value={value} />
      </p>
      <p className="mt-1 text-xs text-zinc-500">{helper}</p>
    </div>
  );
}
function GrowthMetric({
  growth,
  basisDays,
}: {
  growth?: IntelligenceResponse["overall_growth"];
  basisDays: number;
}) {
  const positive = (growth?.change ?? 0) > 0;
  const negative = (growth?.change ?? 0) < 0;
  const label =
    growth?.growth_percent == null
      ? growth?.current_count
        ? "New activity"
        : "No baseline"
      : `${growth.growth_percent > 0 ? "+" : ""}${growth.growth_percent}%`;
  return (
    <div
      className={`rounded-2xl border p-5 ${positive ? "border-amber-200 bg-amber-50" : negative ? "border-teal-200 bg-teal-50" : "border-zinc-200 bg-white"}`}
    >
      <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
        Claim growth
      </p>
      <p
        className={`mt-3 font-mono text-3xl font-semibold tracking-tight ${positive ? "text-amber-800" : negative ? "text-teal-800" : ""}`}
      >
        {label}
      </p>
      <p className="mt-1 text-xs text-zinc-500">
        {growth?.current_count ?? 0} vs {growth?.previous_count ?? 0} ·{" "}
        {basisDays} days
      </p>
    </div>
  );
}
function ChartExportButton({
  svgRef,
  name,
  background,
}: {
  svgRef: RefObject<SVGSVGElement | null>;
  name: string;
  background?: string;
}) {
  const [working, setWorking] = useState(false);
  const exportChart = async () => {
    setWorking(true);
    try {
      await exportSvgAsPng(svgRef.current, name, background);
    } finally {
      setWorking(false);
    }
  };
  return (
    <button
      type="button"
      disabled={working}
      onClick={() => void exportChart()}
      className="button-secondary !min-h-10 px-3 py-2 text-xs"
      aria-label={`Export ${name} as PNG`}
    >
      {working ? (
        <SpinnerGap className="animate-spin" size={16} />
      ) : (
        <DownloadSimple size={16} />
      )}
      PNG
    </button>
  );
}
function MonthlyLineChart({
  items,
  basis,
  attackDateCoverage,
  onBasisChange,
}: {
  items: { month: string; count: number }[];
  basis: "first_publication" | "attack_date";
  attackDateCoverage: number;
  onBasisChange: (basis: "first_publication" | "attack_date") => void;
}) {
  const reducedMotion = useReducedMotion();
  const svgRef = useRef<SVGSVGElement>(null);
  const [activePointIndex, setActivePointIndex] = useState<number | null>(null);
  const width = 760;
  const height = 240;
  const left = 48;
  const right = 20;
  const top = 22;
  const bottom = 48;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const max = Math.max(1, ...items.map((item) => item.count));
  const points = items.map((item, index) => ({
    ...item,
    x:
      left +
      (items.length === 1
        ? plotWidth / 2
        : (index / (items.length - 1)) * plotWidth),
    y: top + plotHeight - (item.count / max) * plotHeight,
  }));
  const line = points
    .map(
      (point, index) =>
        `${index ? "L" : "M"} ${point.x.toFixed(1)} ${point.y.toFixed(1)}`,
    )
    .join(" ");
  const area = points.length
    ? `${line} L ${points.at(-1)?.x} ${top + plotHeight} L ${points[0].x} ${top + plotHeight} Z`
    : "";
  const activePoint =
    activePointIndex == null ? null : points[activePointIndex] ?? null;
  const tooltipWidth = 188;
  const tooltipX = activePoint
    ? Math.max(
        left + 2,
        Math.min(
          width - right - tooltipWidth - 2,
          activePoint.x - tooltipWidth / 2,
        ),
      )
    : 0;
  const tooltipY = activePoint
    ? activePoint.y < top + 50
      ? activePoint.y + 14
      : activePoint.y - 49
    : 0;
  return (
    <section className="min-w-0 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="eyebrow">Attack volume</p>
          <div className="mt-2 flex items-center gap-2">
            <h3 className="text-xl font-semibold">Past 12 months</h3>
            <IntelligenceVolumeTooltip />
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2">
          <div className="flex rounded-xl border border-zinc-200 bg-zinc-50 p-1 text-[11px]">
            <button
              type="button"
              onClick={() => onBasisChange("first_publication")}
              className={`rounded-lg px-2.5 py-1.5 ${basis === "first_publication" ? "bg-white text-teal-800 shadow-sm" : "text-zinc-500"}`}
            >
              First published
            </button>
            <button
              type="button"
              onClick={() => onBasisChange("attack_date")}
              className={`rounded-lg px-2.5 py-1.5 ${basis === "attack_date" ? "bg-white text-teal-800 shadow-sm" : "text-zinc-500"}`}
            >
              Est. attack date
            </button>
          </div>
          <span
            className="rounded-full bg-teal-50 px-3 py-1 text-xs font-semibold text-teal-800"
            title={`Total deduplicated actor–victim claims shown by ${basis === "attack_date" ? "source-reported estimated attack date" : "earliest retained publication date"}`}
          >
            {items.reduce((sum, item) => sum + item.count, 0).toLocaleString()}{" "}
            deduplicated claims
          </span>
          <ChartExportButton svgRef={svgRef} name="attack-volume-12-months" />
        </div>
      </div>
      {items.length ? (
        <div className="mt-6 overflow-x-auto">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${width} ${height}`}
            className="h-auto min-w-[620px] w-full"
            role="img"
            aria-label="Line chart of monthly deduplicated public ransomware victim claims over the past 12 months"
          >
            <rect width={width} height={height} fill="#ffffff" />
            <defs>
              <linearGradient
                id="monthly-volume-fill"
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop offset="0%" stopColor="#0f766e" stopOpacity=".24" />
                <stop offset="100%" stopColor="#0f766e" stopOpacity="0" />
              </linearGradient>
            </defs>
            {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
              const y = top + plotHeight * ratio;
              const value = Math.round(max * (1 - ratio));
              return (
                <g key={ratio}>
                  <line
                    x1={left}
                    x2={width - right}
                    y1={y}
                    y2={y}
                    stroke="#e4e4e7"
                    strokeDasharray="4 5"
                  />
                  <text
                    x={left - 10}
                    y={y + 4}
                    textAnchor="end"
                    fontSize="10"
                    fill="#a1a1aa"
                  >
                    {value}
                  </text>
                </g>
              );
            })}
            {area && (
              <motion.path
                d={area}
                fill="url(#monthly-volume-fill)"
                initial={reducedMotion ? false : { opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: reducedMotion ? 0 : 0.45 }}
              />
            )}
            {line && (
              <motion.path
                d={line}
                fill="none"
                stroke="#0f766e"
                strokeWidth="3"
                strokeLinecap="round"
                strokeLinejoin="round"
                initial={
                  reducedMotion ? false : { pathLength: 0, opacity: 0.4 }
                }
                animate={{ pathLength: 1, opacity: 1 }}
                transition={{
                  duration: reducedMotion ? 0 : 0.8,
                  ease: "easeOut",
                }}
              />
            )}
            {points.map((point, index) => (
              <motion.g
                key={point.month}
                role="graphics-symbol"
                tabIndex={0}
                aria-label={`${point.month}: ${point.count} deduplicated victim claims by ${basis === "attack_date" ? "estimated attack date" : "first publication date"}`}
                onMouseEnter={() => setActivePointIndex(index)}
                onMouseLeave={() => setActivePointIndex(null)}
                onFocus={() => setActivePointIndex(index)}
                onBlur={() => setActivePointIndex(null)}
                initial={reducedMotion ? false : { opacity: 0, scale: 0.7 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{
                  type: "spring",
                  stiffness: 260,
                  damping: 20,
                  delay: reducedMotion ? 0 : 0.2 + index * 0.035,
                }}
                style={{ transformOrigin: `${point.x}px ${point.y}px` }}
              >
                <circle
                  cx={point.x}
                  cy={point.y}
                  r="13"
                  fill="transparent"
                  pointerEvents="all"
                />
                <motion.circle
                  cx={point.x}
                  cy={point.y}
                  animate={{ r: activePointIndex === index ? 7 : 5 }}
                  transition={{ duration: reducedMotion ? 0 : 0.14 }}
                  fill="#fff"
                  stroke="#0f766e"
                  strokeWidth="3"
                />
                <text
                  x={point.x}
                  y={height - 18}
                  textAnchor="middle"
                  fontSize="10"
                  fill="#71717a"
                >
                  {new Date(`${point.month}-01T00:00:00`).toLocaleDateString(
                    undefined,
                    { month: "short" },
                  )}
                </text>
              </motion.g>
            ))}
            <AnimatePresence>
              {activePoint && (
                <motion.g
                  aria-hidden="true"
                  initial={reducedMotion ? false : { opacity: 0, y: 3 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 2 }}
                  transition={{ duration: reducedMotion ? 0 : 0.14 }}
                >
                  <rect
                    x={tooltipX}
                    y={tooltipY}
                    width={tooltipWidth}
                    height="42"
                    rx="9"
                    fill="#18181b"
                    opacity=".96"
                  />
                  <text
                    x={tooltipX + 12}
                    y={tooltipY + 16}
                    fontSize="9"
                    fill="#a1a1aa"
                  >
                    {activePoint.month}
                  </text>
                  <text
                    x={tooltipX + 12}
                    y={tooltipY + 31}
                    fontSize="11"
                    fontWeight="600"
                    fill="#ffffff"
                  >
                    {activePoint.count.toLocaleString()} deduplicated claims
                  </text>
                </motion.g>
              )}
            </AnimatePresence>
          </svg>
        </div>
      ) : (
        <p className="mt-12 text-sm text-zinc-500">
          No monthly data is available.
        </p>
      )}
      <p className="mt-3 text-[11px] leading-5 text-zinc-400">
        Twelve calendar months using the active intelligence filters. Each
        actor–victim pair is counted once. {basis === "attack_date"
          ? `Only source records with an estimated attack date are included (${attackDateCoverage}% coverage across the filtered 12-month trend set).`
          : "The month is assigned from the earliest retained publication or discovery date."}{" "}
        Zero-count months remain visible.
      </p>
    </section>
  );
}

function IntelligenceVolumeTooltip() {
  const anchor = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  const rect = open ? anchor.current?.getBoundingClientRect() : null;
  return (
    <>
      <button
        ref={anchor}
        type="button"
        aria-label="Explain how attack volume is deduplicated"
        aria-describedby={open ? "intelligence-volume-method" : undefined}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={() => setOpen((current) => !current)}
        className="grid h-7 w-7 place-items-center rounded-full border border-zinc-200 bg-white text-zinc-500 transition hover:border-teal-300 hover:text-teal-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-600/30"
      >
        <Info size={15} />
      </button>
      {open &&
        rect &&
        createPortal(
          <div
            id="intelligence-volume-method"
            role="tooltip"
            className="pointer-events-none fixed z-[100] w-[min(24rem,calc(100vw-2rem))] rounded-2xl border border-zinc-200 bg-zinc-950 p-4 text-left text-xs leading-5 text-zinc-200 shadow-2xl"
            style={{
              left: Math.max(
                16,
                Math.min(rect.left, window.innerWidth - Math.min(384, window.innerWidth - 32) - 16),
              ),
              top: Math.max(
                16,
                Math.min(rect.bottom + 8, window.innerHeight - 210),
              ),
            }}
          >
            <p className="font-medium text-white">How volume is counted</p>
            <p className="mt-2">
              One normalized threat actor naming one normalized victim counts as
              one canonical claim, even when several public sources report it or
              use different publication dates.
            </p>
            <p className="mt-2 text-zinc-400">
              Every source record remains retained as evidence. The same victim
              named by different threat actors is counted separately. The chart
              can group canonical claims by earliest public discovery or by a
              source-reported estimated attack date; the latter excludes claims
              without that field and shows its coverage below the graph.
            </p>
          </div>,
          document.body,
        )}
    </>
  );
}

const COUNTRY_MAP_POINTS: Record<string, [number, number]> = {
  argentina: [-64, -34],
  australia: [134, -25],
  bangladesh: [90, 24],
  belgium: [4, 51],
  brazil: [-52, -10],
  canada: [-106, 57],
  china: [104, 35],
  egypt: [30, 27],
  finland: [26, 64],
  france: [2, 47],
  germany: [10, 51],
  "hong kong": [114, 22],
  india: [79, 22],
  indonesia: [118, -2],
  iran: [53, 32],
  israel: [35, 31],
  italy: [12, 42],
  japan: [138, 37],
  kenya: [38, 1],
  malaysia: [102, 4],
  mexico: [-102, 23],
  netherlands: [5, 52],
  "new zealand": [174, -41],
  nigeria: [8, 9],
  norway: [9, 61],
  pakistan: [69, 30],
  philippines: [122, 13],
  poland: [20, 52],
  russia: [90, 61],
  "saudi arabia": [45, 24],
  singapore: [104, 1],
  "south africa": [24, -30],
  "south korea": [128, 36],
  spain: [-4, 40],
  sweden: [16, 62],
  switzerland: [8, 47],
  taiwan: [121, 24],
  thailand: [101, 15],
  turkey: [35, 39],
  ukraine: [32, 49],
  "united arab emirates": [54, 24],
  "united kingdom": [-2, 54],
  "united states": [-100, 39],
  vietnam: [108, 16],
};

function countryPoint(name: string): [number, number] | null {
  const aliases: Record<string, string> = {
    usa: "united states",
    us: "united states",
    "u.s.": "united states",
    uk: "united kingdom",
    uae: "united arab emirates",
    korea: "south korea",
    "russian federation": "russia",
  };
  const key = name.trim().toLowerCase();
  return COUNTRY_MAP_POINTS[aliases[key] || key] ?? null;
}

function CountryWorldMap({
  items,
}: {
  items: { name: string; count: number; is_monitored?: boolean }[];
}) {
  return <ThreatWorldMap items={items} resolveCountry={countryPoint} />;
}
const PIE_COLORS = [
  "#0f766e",
  "#14b8a6",
  "#0ea5e9",
  "#6366f1",
  "#8b5cf6",
  "#f59e0b",
  "#a1a1aa",
];

function IndustryPieChart({
  items,
}: {
  items: { name: string; count: number }[];
}) {
  const reducedMotion = useReducedMotion();
  const svgRef = useRef<SVGSVGElement>(null);
  const chartRef = useRef<HTMLDivElement>(null);
  const [hoveredSlice, setHoveredSlice] = useState("");
  const [tooltipPosition, setTooltipPosition] = useState({ x: 110, y: 110 });
  const visible = items.slice(0, 6);
  const other = items.slice(6).reduce((sum, item) => sum + item.count, 0);
  const slices = other
    ? [...visible, { name: "Other", count: other }]
    : visible;
  const total = slices.reduce((sum, item) => sum + item.count, 0);
  let angle = -90;
  const polar = (degrees: number) => {
    const radians = (degrees * Math.PI) / 180;
    return { x: 110 + 92 * Math.cos(radians), y: 110 + 92 * Math.sin(radians) };
  };
  const paths = slices.map((item, index) => {
    const sweep = total ? (item.count / total) * 360 : 0;
    const middleAngle = angle + sweep / 2;
    const start = polar(angle);
    const end = polar(angle + Math.min(sweep, 359.999));
    const path = `M 110 110 L ${start.x} ${start.y} A 92 92 0 ${sweep > 180 ? 1 : 0} 1 ${end.x} ${end.y} Z`;
    angle += sweep;
    return {
      ...item,
      path,
      color: PIE_COLORS[index % PIE_COLORS.length],
      percent: total ? (item.count / total) * 100 : 0,
      offsetX: Math.cos((middleAngle * Math.PI) / 180) * 7,
      offsetY: Math.sin((middleAngle * Math.PI) / 180) * 7,
    };
  });
  const activeSlice = paths.find((item) => item.name === hoveredSlice);
  const showSlice = (name: string, clientX: number, clientY: number) => {
    const bounds = chartRef.current?.getBoundingClientRect();
    if (bounds) {
      setTooltipPosition({
        x: Math.max(68, Math.min(bounds.width - 68, clientX - bounds.left)),
        y: Math.max(34, Math.min(bounds.height - 34, clientY - bounds.top)),
      });
    }
    setHoveredSlice(name);
  };
  return (
    <section className="min-w-0 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
      <div className="flex items-end justify-between gap-3">
        <div>
          <p className="eyebrow">Victim profile</p>
          <h3 className="mt-2 text-xl font-semibold">
            Most affected industries
          </h3>
        </div>
        <ChartExportButton svgRef={svgRef} name="most-affected-industries" />
      </div>
      {total ? (
        <div className="mt-6 grid items-center gap-6 sm:grid-cols-[220px_minmax(0,1fr)] xl:grid-cols-1 2xl:grid-cols-[220px_minmax(0,1fr)]">
          <div ref={chartRef} className="relative mx-auto h-52 w-52">
            <svg
              ref={svgRef}
              viewBox="0 0 220 220"
              className="h-52 w-52 overflow-visible"
              role="img"
              aria-label="Interactive pie chart of retained victim claims by industry"
              onMouseLeave={() => setHoveredSlice("")}
            >
              <rect width="220" height="220" fill="#ffffff" />
              {paths.map((item, index) => {
                const active = hoveredSlice === item.name;
                const muted = Boolean(hoveredSlice && !active);
                return (
                  <motion.path
                    key={item.name}
                    d={item.path}
                    fill={item.color}
                    stroke="#fff"
                    strokeWidth={active ? 3 : 2}
                    tabIndex={0}
                    role="graphics-symbol"
                    aria-label={`${item.name}: ${item.count} deduplicated victim claims, ${item.percent.toFixed(1)} percent`}
                    initial={reducedMotion ? false : { opacity: 0 }}
                    animate={{
                      opacity: muted ? 0.55 : 1,
                      x: active && !reducedMotion ? item.offsetX : 0,
                      y: active && !reducedMotion ? item.offsetY : 0,
                    }}
                    transition={{
                      duration: reducedMotion ? 0 : active ? 0.16 : 0.28,
                      delay: hoveredSlice || reducedMotion ? 0 : index * 0.045,
                      ease: "easeOut",
                    }}
                    className="cursor-default outline-none focus-visible:stroke-zinc-950"
                    onMouseEnter={(event) =>
                      showSlice(item.name, event.clientX, event.clientY)
                    }
                    onMouseMove={(event) =>
                      showSlice(item.name, event.clientX, event.clientY)
                    }
                    onFocus={(event) => {
                      const bounds = event.currentTarget.getBoundingClientRect();
                      showSlice(
                        item.name,
                        bounds.left + bounds.width / 2,
                        bounds.top + bounds.height / 2,
                      );
                    }}
                    onBlur={() => setHoveredSlice("")}
                  />
                );
              })}
            </svg>
            <AnimatePresence>
              {activeSlice && (
                <motion.div
                  role="tooltip"
                  initial={reducedMotion ? false : { opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 2 }}
                  transition={{ duration: reducedMotion ? 0 : 0.14 }}
                  className="pointer-events-none absolute z-20 min-w-32 -translate-x-1/2 -translate-y-[calc(100%+12px)] rounded-xl bg-zinc-950 px-3 py-2 text-left text-white shadow-xl"
                  style={{ left: tooltipPosition.x, top: tooltipPosition.y }}
                >
                  <p className="max-w-40 truncate text-[11px] font-medium">
                    {activeSlice.name}
                  </p>
                  <p className="mt-1 font-mono text-sm">
                    {activeSlice.count.toLocaleString()} claims
                  </p>
                  <p className="mt-0.5 text-[10px] text-zinc-300">
                    {activeSlice.percent.toFixed(1)}% of displayed industries
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
          <div className="space-y-2">
            {paths.map((item) => (
              <button
                type="button"
                key={item.name}
                onMouseEnter={() => setHoveredSlice(item.name)}
                onMouseLeave={() => setHoveredSlice("")}
                onFocus={() => setHoveredSlice(item.name)}
                onBlur={() => setHoveredSlice("")}
                className={`grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 rounded-lg px-2 py-1.5 text-left text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-600/30 ${hoveredSlice === item.name ? "bg-zinc-100" : "hover:bg-zinc-50"}`}
              >
                <span
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ backgroundColor: item.color }}
                />
                <span className="truncate text-zinc-600">{item.name}</span>
                <span className="font-mono font-semibold text-zinc-700">
                  {item.percent.toFixed(1)}%
                </span>
              </button>
            ))}
          </div>
        </div>
      ) : (
        <p className="mt-12 text-sm text-zinc-500">
          No enriched industry data in this period.
        </p>
      )}
      <p className="mt-5 text-[11px] leading-5 text-zinc-400">
        Shares use source-supplied or reviewed AI-enriched industry values in
        the selected period.
      </p>
    </section>
  );
}

function RankingCard({
  title,
  items,
}: {
  title: string;
  items: { name: string; count: number; is_monitored?: boolean }[];
}) {
  const reducedMotion = useReducedMotion();
  const max = Math.max(1, ...items.map((item) => item.count));
  return (
    <section className="rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
      <h3 className="text-xl font-semibold">{title}</h3>
      <div className="mt-6 space-y-4">
        {items.length ? (
          items.map((item, index) => (
            <div
              key={item.name}
              className={
                item.is_monitored
                  ? "rounded-xl bg-sky-50 p-3 ring-1 ring-sky-200"
                  : ""
              }
            >
              <div className="flex items-center justify-between gap-4 text-sm">
                <span className="truncate">
                  <span className="mr-2 font-mono text-xs text-zinc-400">
                    {index + 1}
                  </span>
                  {item.name}
                  {item.is_monitored && (
                    <span className="ml-2 rounded-full bg-sky-100 px-2 py-0.5 text-[10px] font-bold uppercase text-sky-800">
                      Your region
                    </span>
                  )}
                </span>
                <span className="font-mono text-xs font-semibold">
                  {item.count.toLocaleString()}
                </span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-zinc-100">
                <motion.div
                  className={`h-full w-full origin-left rounded-full ${item.is_monitored ? "bg-sky-600" : "bg-teal-700"}`}
                  initial={reducedMotion ? false : { scaleX: 0 }}
                  animate={{ scaleX: Math.max(0.04, item.count / max) }}
                  transition={{
                    type: "spring",
                    stiffness: 105,
                    damping: 20,
                    delay: reducedMotion ? 0 : index * 0.045,
                  }}
                />
              </div>
            </div>
          ))
        ) : (
          <p className="text-sm text-zinc-500">
            No enriched data in this period.
          </p>
        )}
      </div>
    </section>
  );
}
function GrowthRankingCard({
  title,
  description,
  items,
}: {
  title: string;
  description: string;
  items: IntelligenceResponse["group_growth"];
}) {
  return (
    <section className="rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
      <h3 className="text-xl font-semibold">{title}</h3>
      <p className="mt-1 text-xs text-zinc-500">{description}</p>
      <div className="mt-6 divide-y divide-zinc-100">
        {items.length ? (
          items.slice(0, 10).map((item) => (
            <div
              key={item.name}
              className="grid grid-cols-[1fr_auto_auto] items-center gap-4 py-3"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold">{item.name}</p>
                <p className="mt-1 text-xs text-zinc-400">
                  {item.current_count} current · {item.previous_count} previous
                </p>
              </div>
              <span
                className={`font-mono text-xs font-bold ${item.change > 0 ? "text-amber-700" : item.change < 0 ? "text-teal-700" : "text-zinc-400"}`}
              >
                {item.change > 0 ? "+" : ""}
                {item.change}
              </span>
              <GrowthBadge
                percent={item.growth_percent}
                current={item.current_count}
              />
            </div>
          ))
        ) : (
          <p className="py-8 text-sm text-zinc-500">
            No group activity in either comparison period.
          </p>
        )}
      </div>
    </section>
  );
}
function RegionGrowthCard({
  items,
  basisDays,
  onEdit,
}: {
  items: IntelligenceResponse["monitored_region_growth"];
  basisDays: number;
  onEdit: () => void;
}) {
  return (
    <section className="rounded-[2rem] border border-sky-200 bg-sky-50/50 p-6 md:p-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="eyebrow !text-sky-700">Your footprint</p>
          <h3 className="mt-2 text-xl font-semibold">
            Monitored regions and cities
          </h3>
        </div>
        <button
          type="button"
          onClick={onEdit}
          className="text-sm font-semibold text-sky-800"
        >
          Edit regions
        </button>
      </div>
      <p className="mt-2 text-xs leading-5 text-zinc-500">
        Highlighted from global focus regions plus client-profile markets and
        cities. Comparing {basisDays}-day periods.
      </p>
      <div className="mt-5 space-y-3">
        {items.length ? (
          items.map((item) => (
            <div
              key={item.name}
              className="flex items-center justify-between gap-4 rounded-xl border border-sky-100 bg-white p-4"
            >
              <div>
                <p className="text-sm font-semibold">{item.name}</p>
                <p className="mt-1 text-xs text-zinc-400">
                  {item.current_count} current · {item.previous_count} previous
                  · {item.count} selected
                </p>
              </div>
              <GrowthBadge
                percent={item.growth_percent}
                current={item.current_count}
              />
            </div>
          ))
        ) : (
          <p className="rounded-xl bg-white p-5 text-sm text-zinc-500">
            Choose global focus regions in Settings or add markets and cities to
            a client profile.
          </p>
        )}
      </div>
    </section>
  );
}
function GrowthBadge({
  percent,
  current,
}: {
  percent: number | null;
  current: number;
}) {
  const text =
    percent == null
      ? current
        ? "New"
        : "—"
      : `${percent > 0 ? "+" : ""}${percent}%`;
  return (
    <span
      className={`min-w-14 rounded-full px-2.5 py-1 text-center font-mono text-xs font-bold ${percent == null && current ? "bg-amber-100 text-amber-800" : (percent ?? 0) > 0 ? "bg-amber-100 text-amber-800" : (percent ?? 0) < 0 ? "bg-teal-100 text-teal-800" : "bg-zinc-100 text-zinc-500"}`}
    >
      {text}
    </span>
  );
}
function ClaimStatus({ value }: { value: string }) {
  const leaked = value === "data_leaked";
  return (
    <span
      className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold capitalize ${leaked ? "bg-rose-50 text-rose-800" : "bg-amber-50 text-amber-800"}`}
    >
      {value.replaceAll("_", " ")}
    </span>
  );
}

function ThreatActorProfiles({
  profiles,
  profileOptions,
  selectedActor,
  error,
  onSelect,
  onProfilesReload,
}: {
  profiles: ThreatActorProfile[];
  profileOptions?: ThreatActorProfileIndexItem[];
  selectedActor: string;
  error: string;
  onSelect: (actor: string) => void;
  onProfilesReload: () => Promise<void>;
}) {
  const [syncing, setSyncing] = useState(false);
  const [syncNotice, setSyncNotice] = useState("");
  const [refreshingProfile, setRefreshingProfile] = useState(false);
  const profile =
    profiles.find((item) => item.actor === selectedActor) ?? profiles[0];
  const options =
    profileOptions ??
    profiles.map((item) => ({
      actor: item.actor,
      claim_count: item.claim_count,
      first_observed_at: item.first_observed_at,
      last_observed_at: item.last_observed_at,
    }));
  const cti = profile?.cti_profile;
  const professional = resolveProfessionalProfile(profile);
  const sync = async () => {
    setSyncing(true);
    setSyncNotice("");
    try {
      const result = await api.syncActorProfiles();
      await onProfilesReload();
      setSyncNotice(
        `${result.profiles} official ATT&CK group profiles synchronized. Profiles updated without leaving this page.`,
      );
    } catch (reason) {
      setSyncNotice(
        reason instanceof Error
          ? reason.message
          : "ATT&CK synchronization failed",
      );
    } finally {
      setSyncing(false);
    }
  };
  const refreshProfile = async () => {
    if (!profile) return;
    setRefreshingProfile(true);
    setSyncNotice("");
    try {
      await api.queueAIJob("actor_profile_refresh", { actor: profile.actor });
      setSyncNotice(
        `AI refresh queued for ${profile.actor}. The task centre will notify you when the sourced profile is ready.`,
      );
    } catch (reason) {
      setSyncNotice(
        reason instanceof Error
          ? reason.message
          : "Profile refresh could not be queued",
      );
    } finally {
      setRefreshingProfile(false);
    }
  };
  return (
    <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
      <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div>
          <p className="eyebrow">Threat intelligence profiles</p>
          <h3 className="mt-2 text-xl font-semibold">
            Actor identity, behavior and observed activity
          </h3>
          <p className="mt-2 max-w-3xl text-xs leading-5 text-zinc-500">
            {options.length.toLocaleString()} retained actor labels have an
            offline local baseline. Established operations use bundled analyst
            dossiers and attributable sources; emerging labels use conservative
            low-confidence profiles. AI updates are optional, citation-gated
            overlays, and local claims remain a separate observation layer.
          </p>
        </div>
        <div className="flex w-full flex-col gap-2 lg:max-w-md">
          <SearchableSelect
            ariaLabel="Select threat actor profile"
            value={profile?.actor ?? ""}
            onChange={onSelect}
            searchPlaceholder="Search actor labels…"
            options={options.map((item) => ({
              value: item.actor,
              label: `${item.actor} · ${item.claim_count}`,
            }))}
          />
          <button
            type="button"
            onClick={() => void sync()}
            disabled={syncing}
            className="button-secondary justify-center"
          >
            {syncing ? (
              <SpinnerGap className="animate-spin" size={17} />
            ) : (
              <DownloadSimple size={17} />
            )}
            Sync official ATT&amp;CK profiles
          </button>
        </div>
      </div>
      {error && <InlineNotice tone="danger">{error}</InlineNotice>}
      {syncNotice && <InlineNotice tone="neutral">{syncNotice}</InlineNotice>}
      {profile ? (
        <div className="mt-6 space-y-5">
          <section className="rounded-2xl border border-violet-200 bg-violet-50/40 p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium uppercase tracking-wide text-violet-700">
                  Professional actor profile
                </p>
                <h4 className="mt-2 text-lg font-semibold">{profile.actor}</h4>
                <p className="mt-3 whitespace-pre-wrap text-sm leading-7 text-zinc-700">
                  {professional?.summary || profile.summary}
                </p>
                <p className="mt-3 text-[11px] leading-5 text-zinc-500">
                  {professional ? actorProfileProvenance(professional) : "Profile baseline"}
                  {professional?.reviewed_at
                    ? ` · reviewed ${professional.reviewed_at}`
                    : ""}
                  {professional?.generated_at
                    ? ` · AI refreshed ${formatTime(professional.generated_at)}`
                    : ""}
                  {` · ${professional?.source_confidence || "low"} source confidence`}
                  {professional?.analytic_confidence != null
                    ? ` · ${professional.analytic_confidence}% analytic confidence`
                    : ""}
                  {professional?.independent_source_count
                    ? ` · ${professional.independent_source_count} independent source${professional.independent_source_count === 1 ? "" : "s"}`
                    : ""}
                  {professional
                    ? ` · ${professional.actor_class.replaceAll("_", " ")} · ${professional.distribution}`
                    : ""}
                </p>
                {professional?.source_references?.length ? (
                  <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                    {professional.source_references.map((source) =>
                      source.url ? (
                        <a
                          key={`${source.name}-${source.url}`}
                          href={source.url}
                          target="_blank"
                          rel="noreferrer"
                          className="rounded-full border border-violet-200 bg-white px-3 py-1.5 text-violet-800 transition hover:border-violet-400"
                        >
                          {source.name}
                        </a>
                      ) : (
                        <span
                          key={source.name}
                          className="rounded-full border border-zinc-200 bg-white px-3 py-1.5 text-zinc-600"
                        >
                          {source.name}
                        </span>
                      ),
                    )}
                  </div>
                ) : null}
              </div>
              <button
                type="button"
                disabled={refreshingProfile}
                onClick={() => void refreshProfile()}
                className="button-primary shrink-0 !bg-violet-700"
              >
                {refreshingProfile ? (
                  <SpinnerGap className="animate-spin" size={17} />
                ) : (
                  <Cpu size={17} />
                )}
                AI research &amp; update
              </button>
            </div>
            {profile.ai_profile_refresh &&
              professional?.ai_overlay_status === "insufficient_evidence" && (
                <InlineNotice tone="danger">
                  The latest AI research attempt found no adequately cited
                  actor-specific evidence, so the bundled local dossier remains
                  active. The attempt is preserved in AI task history.
                </InlineNotice>
              )}
            {professional &&
              (professional.motivation ||
                professional.targeting ||
                professional.capabilities ||
                professional.campaign_history) && (
              <dl className="mt-5 grid gap-3 border-t border-violet-100 pt-5 md:grid-cols-2">
                <ProfileText
                  label="Motivation"
                  value={professional.motivation || "Not established in retained OSINT."}
                  evidenceCount={professional.field_evidence?.motivation?.length}
                />
                <ProfileText
                  label="Targeting"
                  value={professional.targeting || "Not established in retained OSINT."}
                  evidenceCount={professional.field_evidence?.targeting?.length}
                />
                <ProfileText
                  label="Capabilities"
                  value={professional.capabilities || "Not established in retained OSINT."}
                  evidenceCount={professional.field_evidence?.capabilities?.length}
                />
                <ProfileText
                  label="Campaign history"
                  value={professional.campaign_history || "Not established in retained OSINT."}
                  evidenceCount={professional.field_evidence?.campaign_history?.length}
                />
              </dl>
            )}
            {professional && (
              <details className="group mt-5 rounded-xl border border-violet-100 bg-white/80 p-4">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-4 text-xs text-zinc-700">
                  <span>
                    Analyst brief and detection posture · {professional.profile_status.replaceAll("_", " ")}
                  </span>
                  <CaretDown
                    className="shrink-0 transition group-open:rotate-180"
                    size={17}
                  />
                </summary>
                <div className="mt-4 grid gap-5 border-t border-violet-100 pt-4 lg:grid-cols-2">
                  <div>
                    <p className="text-[11px] uppercase tracking-wide text-zinc-500">
                      Key judgments
                    </p>
                    <ul className="mt-2 space-y-2 text-xs leading-5 text-zinc-700">
                      {professional.key_judgments.map((item) => (
                        <li key={item}>• {item}</li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <p className="text-[11px] uppercase tracking-wide text-zinc-500">
                      Priority actions
                    </p>
                    <ol className="mt-2 space-y-2 text-xs leading-5 text-zinc-700">
                      {professional.priority_actions.map((item, index) => (
                        <li key={item}>{index + 1}. {item}</li>
                      ))}
                    </ol>
                  </div>
                  <div>
                    <p className="text-[11px] uppercase tracking-wide text-zinc-500">
                      Hunt hypotheses
                    </p>
                    <ul className="mt-2 space-y-2 text-xs leading-5 text-zinc-700">
                      {professional.hunt_hypotheses.map((item) => (
                        <li key={item}>• {item}</li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <p className="text-[11px] uppercase tracking-wide text-zinc-500">
                      Detection coverage
                    </p>
                    <p className="mt-2 text-xs leading-5 text-zinc-700">
                      {professional.detection_coverage.message}
                    </p>
                    <p className="mt-2 text-[11px] text-zinc-500">
                      {professional.detection_coverage.documented_technique_count} documented technique relationships · coverage {professional.detection_coverage.status.replaceAll("_", " ")}
                    </p>
                  </div>
                </div>
                {professional.identity.related_but_distinct.length > 0 && (
                  <div className="mt-4 border-t border-violet-100 pt-4 text-xs leading-5 text-zinc-600">
                    <span className="text-zinc-800">Related but not deduplicated:</span>{" "}
                    {professional.identity.related_but_distinct
                      .map((item) => `${item.name} — ${item.relationship}`)
                      .join("; ")}
                  </div>
                )}
                <p className="mt-4 border-t border-violet-100 pt-4 text-[11px] leading-5 text-zinc-500">
                  Identity resolution: {professional.identity.resolution_basis}. Profile schema: {professional.profile_schema}.
                </p>
              </details>
            )}
          </section>
          {profile.osint_evidence?.length ? (
            <details className="group rounded-2xl border border-sky-200 bg-sky-50/30 p-5">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-4">
                <span>
                  <span className="block text-xs font-medium uppercase tracking-wide text-sky-800">
                    Retained OSINT evidence base
                  </span>
                  <span className="mt-1 block text-sm text-zinc-600">
                    {profile.osint_evidence.length} attributable records
                    {professional?.independent_source_count
                      ? ` from ${professional.independent_source_count} sources`
                      : ""}
                  </span>
                </span>
                <CaretDown
                  className="shrink-0 transition group-open:rotate-180"
                  size={18}
                />
              </summary>
              <div className="mt-4 grid gap-3 border-t border-sky-100 pt-4 lg:grid-cols-2">
                {profile.osint_evidence.slice(0, 20).map((item) => (
                  <a
                    key={item.id}
                    href={item.source_url}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded-xl border border-sky-100 bg-white p-4 transition hover:border-sky-300"
                  >
                    <span className="flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-wide text-zinc-400">
                      <span>{item.source_name}</span>
                      <span>·</span>
                      <span>{item.source_tier.replaceAll("-", " ")}</span>
                      {item.published_at ? (
                        <>
                          <span>·</span>
                          <span>{formatTime(item.published_at)}</span>
                        </>
                      ) : null}
                    </span>
                    <span className="mt-2 block text-sm leading-6 text-zinc-700">
                      {item.title}
                    </span>
                    <span className="mt-2 block font-mono text-[10px] text-zinc-400">
                      {item.id}
                    </span>
                  </a>
                ))}
              </div>
              <p className="mt-4 text-[11px] leading-5 text-zinc-500">
                Search results are retained only after actor-name validation.
                Source excerpts are untrusted inputs; the model cannot cite an
                ID absent from this evidence set.
              </p>
            </details>
          ) : (
            <InlineNotice tone="neutral">
              No actor-specific OSINT research has been retained yet. Use
              “Research OSINT &amp; refresh” to collect attributable public-sector
              and security-research evidence before synthesis.
            </InlineNotice>
          )}
          {cti ? (
            <section className="rounded-2xl border border-teal-200 bg-teal-50/40 p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="text-xs font-medium uppercase tracking-wide text-teal-800">
                    Verified external CTI · MITRE ATT&amp;CK
                  </p>
                  <h4 className="mt-2 text-lg font-semibold">
                    {cti.canonical_name}{" "}
                    <span className="font-mono text-sm font-normal text-zinc-500">
                      {cti.attack_id}
                    </span>
                  </h4>
                  <p className="mt-1 text-xs text-zinc-500">
                    Exact{" "}
                    {cti.match_basis === "canonical_name"
                      ? "canonical-name"
                      : "documented associated-name"}{" "}
                    match · updated{" "}
                    {formatTime(cti.modified || cti.refreshed_at)}
                  </p>
                </div>
                {cti.attack_url && (
                  <a
                    href={cti.attack_url}
                    target="_blank"
                    rel="noreferrer"
                    className="button-secondary"
                  >
                    Open ATT&amp;CK profile
                  </a>
                )}
              </div>
              <p className="mt-4 whitespace-pre-wrap text-sm leading-7 text-zinc-700">
                {cti.description ||
                  "ATT&CK does not supply a narrative for this group."}
              </p>
              {cti.aliases.length > 0 && (
                <p className="mt-4 text-xs text-zinc-600">
                  <span className="font-medium">Documented aliases:</span>{" "}
                  {cti.aliases.join(", ")}
                </p>
              )}
              <div className="mt-5 grid gap-5 lg:grid-cols-2">
                <div>
                  <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                    Documented ATT&amp;CK techniques
                  </p>
                  <div className="mt-2 max-h-72 overflow-auto rounded-xl border border-teal-100 bg-white">
                    <table className="w-full text-left text-xs">
                      <thead className="sticky top-0 bg-zinc-50 text-zinc-500">
                        <tr>
                          <th className="px-3 py-2">ID</th>
                          <th className="px-3 py-2">Technique</th>
                          <th className="px-3 py-2">Tactics</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-100">
                        {cti.techniques.map((technique) => (
                          <tr key={technique.id}>
                            <td className="px-3 py-2 font-mono">
                              <a
                                href={technique.url}
                                target="_blank"
                                rel="noreferrer"
                                className="text-teal-800 underline"
                              >
                                {technique.id}
                              </a>
                            </td>
                            <td className="px-3 py-2">{technique.name}</td>
                            <td className="px-3 py-2 text-zinc-500">
                              {technique.tactics.join(", ") || "Not mapped"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
                <div>
                  <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                    Capabilities and campaign associations
                  </p>
                  <div className="mt-2 rounded-xl border border-teal-100 bg-white p-4 text-xs leading-6 text-zinc-600">
                    <p>
                      <span className="font-medium text-zinc-800">
                        Software:
                      </span>{" "}
                      {cti.software.length
                        ? cti.software
                            .slice(0, 20)
                            .map((item) => item.name)
                            .join(", ")
                        : "No software relationship documented in ATT&CK."}
                    </p>
                    <p className="mt-3">
                      <span className="font-medium text-zinc-800">
                        Campaigns:
                      </span>{" "}
                      {cti.campaigns.length
                        ? cti.campaigns.map((item) => item.name).join(", ")
                        : "No campaign relationship documented in ATT&CK."}
                    </p>
                    <p className="mt-3">
                      <span className="font-medium text-zinc-800">
                        Detection review:
                      </span>{" "}
                      compare the documented technique set against your
                      ATT&amp;CK Navigator detection matrix. This console does
                      not claim organizational coverage without an imported
                      coverage layer.
                    </p>
                  </div>
                </div>
              </div>
              <p className="mt-4 text-[11px] leading-5 text-zinc-500">
                {cti.source_note}
              </p>
            </section>
          ) : (
            <InlineNotice tone="neutral">
              No exact MITRE ATT&amp;CK group-name or alias match is cached for
              “{profile.actor}”. The console will not infer a match from shared
              tooling or similar names. Synchronize ATT&amp;CK above to refresh
              the external catalog.
            </InlineNotice>
          )}
          <section className="grid gap-5 xl:grid-cols-[1.3fr_.7fr]">
            <div className="rounded-2xl bg-zinc-50 p-5">
              <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                Locally observed ransomware claims
              </p>
              <h4 className="mt-2 text-lg font-semibold">{profile.actor}</h4>
              <p className="mt-4 text-sm leading-7 text-zinc-700">
                {profile.summary}
              </p>
              <div className="mt-5 grid gap-4 sm:grid-cols-2">
                <ProfileList
                  title="Observed victim industries"
                  items={profile.top_industries}
                />
                <ProfileList
                  title="Observed geographies"
                  items={profile.top_countries}
                />
              </div>
              <p className="mt-5 border-t border-zinc-200 pt-4 text-[11px] leading-5 text-zinc-500">
                {profile.caveat}
              </p>
            </div>
            <div className="rounded-2xl border border-zinc-200 p-5">
              <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                Activity basis
              </p>
              <dl className="mt-4 space-y-3 text-sm">
                <div className="flex justify-between">
                  <dt>Claims in period</dt>
                  <dd className="font-mono">{profile.claim_count}</dd>
                </div>
                <div className="flex justify-between">
                  <dt>First observed</dt>
                  <dd className="font-mono text-xs">
                    {formatTime(profile.first_observed_at)}
                  </dd>
                </div>
                <div className="flex justify-between">
                  <dt>Latest observed</dt>
                  <dd className="font-mono text-xs">
                    {formatTime(profile.last_observed_at)}
                  </dd>
                </div>
              </dl>
              <p className="mt-5 text-[11px] leading-5 text-zinc-500">
                Attribution confidence is not derived from claim volume.
                External identity context appears only after an exact ATT&amp;CK
                match.
              </p>
            </div>
          </section>
        </div>
      ) : (
        <div className="mt-6 rounded-2xl border border-dashed border-zinc-200 p-6 text-sm text-zinc-500">
          No actor profiles are available for this period.
        </div>
      )}
    </section>
  );
}

function ActorProfilesPage() {
  const [profileIndex, setProfileIndex] = useState<
    ThreatActorProfileIndexItem[]
  >([]);
  const [selectedProfile, setSelectedProfile] =
    useState<ThreatActorProfile | null>(null);
  const [selectedActor, setSelectedActor] = useState(() => {
    try {
      return window.localStorage.getItem("extortsignal.actor-profile.selected") || "";
    } catch {
      return "";
    }
  });
  const [loadingIndex, setLoadingIndex] = useState(true);
  const [loadingProfile, setLoadingProfile] = useState(false);
  const [error, setError] = useState("");

  const loadIndex = useCallback(async (showLoading = true) => {
    if (showLoading) setLoadingIndex(true);
    setError("");
    try {
      const result = await api.actorProfileIndex(0);
      setProfileIndex(result);
      if (result.length) setLoadingProfile(true);
      setSelectedActor((current) =>
        result.some((item) => item.actor === current)
          ? current
          : result[0]?.actor || "",
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Threat-actor profile index could not be loaded",
      );
    } finally {
      if (showLoading) setLoadingIndex(false);
    }
  }, []);

  useEffect(() => {
    void loadIndex();
  }, [loadIndex]);

  const loadSelectedProfile = useCallback(async (actor: string) => {
    if (!actor) return;
    setLoadingProfile(true);
    setError("");
    try {
      setSelectedProfile(await api.actorProfile(actor));
    } catch (reason) {
      setSelectedProfile(null);
      setError(
        reason instanceof Error
          ? reason.message
          : "The selected threat-actor profile could not be loaded",
      );
    } finally {
      setLoadingProfile(false);
    }
  }, []);

  useEffect(() => {
    if (
      !selectedActor ||
      !profileIndex.some((item) => item.actor === selectedActor)
    )
      return;
    setSelectedProfile(null);
    void loadSelectedProfile(selectedActor);
  }, [loadSelectedProfile, profileIndex, selectedActor]);

  useEffect(() => {
    if (!selectedActor) return;
    try {
      window.localStorage.setItem(
        "extortsignal.actor-profile.selected",
        selectedActor,
      );
    } catch {
      /* Local storage may be unavailable in hardened browser profiles. */
    }
  }, [selectedActor]);

  const reloadProfiles = useCallback(async () => {
    await Promise.all([
      loadIndex(false),
      selectedActor ? loadSelectedProfile(selectedActor) : Promise.resolve(),
    ]);
  }, [loadIndex, loadSelectedProfile, selectedActor]);

  const loading = loadingIndex || loadingProfile;

  return (
    <div>
      <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <PageIntro
          eyebrow="Actor knowledge base"
          title="Threat-actor profiles"
          description="Review retained professional dossiers, update sourced analysis, and pivot directly into every deduplicated victim claim associated with the selected actor."
        />
        <div className="grid grid-cols-2 gap-5 border-y border-zinc-200 py-3 lg:min-w-72">
          <div>
            <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
              Actor labels
            </p>
            <p className="mt-1 font-mono text-lg text-zinc-800">
              {profileIndex.length.toLocaleString()}
            </p>
          </div>
          <div>
            <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
              Selected claims
            </p>
            <p className="mt-1 font-mono text-lg text-zinc-800">
              {selectedProfile?.claim_count.toLocaleString() ?? "—"}
            </p>
          </div>
        </div>
      </div>

      <InlineNotice tone="neutral">
        Profiles combine attributable external CTI with a separately labelled
        local observation layer. Victim listings remain unverified allegations
        and do not independently establish compromise or attribution.
      </InlineNotice>

      {loading && !selectedProfile ? (
        <ActorProfilesPageSkeleton />
      ) : error && !selectedProfile ? (
        <div>
          <InlineNotice tone="danger">{error}</InlineNotice>
          <button
            type="button"
            onClick={() => {
              void loadIndex();
              if (selectedActor) void loadSelectedProfile(selectedActor);
            }}
            className="button-secondary mt-4"
          >
            Try again
          </button>
        </div>
      ) : selectedProfile ? (
        <>
          <ThreatActorProfiles
            profiles={[selectedProfile]}
            profileOptions={profileIndex}
            selectedActor={selectedProfile.actor}
            error={error}
            onSelect={(actor) => {
              setSelectedProfile(null);
              setLoadingProfile(true);
              setSelectedActor(actor);
            }}
            onProfilesReload={reloadProfiles}
          />
          <ActorVictimPivot
            actor={selectedProfile.actor}
            profile={selectedProfile}
          />
        </>
      ) : (
        <EmptyState
          title="No actor profiles retained"
          description="Synchronize public sources to create conservative local profiles for observed actor labels."
          icon={<FingerprintSimple size={25} />}
        />
      )}
    </div>
  );
}

function ActorProfilesPageSkeleton() {
  return (
    <div
      className="mt-6 space-y-5"
      aria-label="Loading actor profiles"
      aria-busy="true"
    >
      <LoadingStatusCard
        title="Loading actor dossier"
        description="Retrieving the selected profile and victim pivot."
        className="max-w-xl"
      />
      <div className="animate-pulse space-y-5">
      <div className="h-72 rounded-[2rem] border border-zinc-200 bg-zinc-100" />
      <div className="rounded-[2rem] border border-zinc-200 bg-white p-6">
        <div className="h-5 w-48 rounded bg-zinc-200" />
        <div className="mt-5 space-y-3">
          {[0, 1, 2].map((item) => (
            <div key={item} className="h-20 rounded-xl bg-zinc-100" />
          ))}
        </div>
      </div>
      </div>
    </div>
  );
}

function ActorVictimPivot({
  actor,
  profile,
}: {
  actor: string;
  profile?: ThreatActorProfile;
}) {
  const [data, setData] = useState<ActivityResponse | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [selected, setSelected] = useState<Claim | null>(null);
  const [enriching, setEnriching] = useState(false);
  const [drafting, setDrafting] = useState(false);

  useEffect(() => {
    setPage(1);
    setQuery("");
    setSelected(null);
    setData(null);
  }, [actor]);

  const loadVictims = useCallback(async () => {
    if (!actor) return;
    setLoading(true);
    setError("");
    try {
      const result = await api.activity({
        page,
        page_size: 25,
        query,
        actor,
        date_basis: "published",
        sort: "published",
        direction: "desc",
      });
      setData(result);
      setSelected((current) =>
        current
          ? result.items.find((item) => item.id === current.id) ?? current
          : null,
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Victim claims could not be loaded",
      );
    } finally {
      setLoading(false);
    }
  }, [actor, page, query]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadVictims(), 180);
    return () => window.clearTimeout(timer);
  }, [loadVictims]);

  const queueVictimTask = async (
    jobType: "victim_enrichment" | "claim_awareness_draft",
  ) => {
    if (!selected) return;
    const enrichment = jobType === "victim_enrichment";
    enrichment ? setEnriching(true) : setDrafting(true);
    setError("");
    try {
      await api.queueAIJob(jobType, { claim_id: selected.id });
      setNotice(
        enrichment
          ? `Background victim research queued for ${selected.title}.`
          : `Awareness-email draft queued for ${selected.title}.`,
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "The background task could not be queued",
      );
    } finally {
      enrichment ? setEnriching(false) : setDrafting(false);
    }
  };

  const rows = data?.items ?? [];
  return (
    <section className="mt-5 overflow-hidden rounded-[2rem] border border-zinc-200 bg-white">
      <div className="grid gap-5 border-b border-zinc-200 p-5 sm:p-6 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,.7fr)] lg:items-end">
        <div>
          <p className="eyebrow">Victim pivot</p>
          <h3 className="mt-2 text-xl font-medium tracking-[-0.02em] text-zinc-900">
            Claims associated with {actor}
          </h3>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-500">
            One normalized actor naming one normalized victim appears once.
            Underlying source observations remain preserved in the complete
            claim record.
          </p>
        </div>
        <label className="flex min-h-12 items-center gap-3 rounded-xl border border-zinc-200 bg-white px-4 transition-colors focus-within:border-teal-600 focus-within:ring-2 focus-within:ring-teal-100">
          <MagnifyingGlass size={17} className="text-zinc-400" />
          <span className="sr-only">Search victims for {actor}</span>
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
              setSelected(null);
            }}
            className="w-full bg-transparent text-sm outline-none"
            placeholder="Search victim, domain, or context"
          />
        </label>
      </div>

      <div className="grid gap-4 border-b border-zinc-100 bg-zinc-50/70 px-5 py-4 sm:grid-cols-3 sm:px-6">
        <ActorPivotMetric
          label="Deduplicated claims"
          value={(data?.total ?? profile?.claim_count ?? 0).toLocaleString()}
        />
        <ActorPivotMetric
          label="First retained"
          value={profile ? formatTime(profile.first_observed_at) : "—"}
          compact
        />
        <ActorPivotMetric
          label="Latest retained"
          value={profile ? formatTime(profile.last_observed_at) : "—"}
          compact
        />
      </div>

      {notice && (
        <div className="px-5 sm:px-6">
          <InlineNotice tone="neutral" autoDismissMs={6500}>
            {notice}
          </InlineNotice>
        </div>
      )}
      {error && (
        <div className="px-5 sm:px-6">
          <InlineNotice tone="danger">{error}</InlineNotice>
        </div>
      )}

      <div aria-live="polite" aria-busy={loading}>
        {loading && !rows.length ? (
          <div className="px-5 pb-5 sm:px-6">
            <LoadingStatusCard
              title="Loading victim pivot"
              description={`Retrieving deduplicated claims associated with ${actor}.`}
              className="my-5 max-w-xl"
            />
            <div className="animate-pulse divide-y divide-zinc-100">
              {[0, 1, 2, 3].map((item) => (
                <div key={item} className="grid gap-4 py-5 lg:grid-cols-[1.2fr_.8fr_.65fr_auto]">
                  <div className="h-11 rounded-lg bg-zinc-100" />
                  <div className="h-11 rounded-lg bg-zinc-100" />
                  <div className="h-11 rounded-lg bg-zinc-100" />
                  <div className="h-11 w-11 rounded-lg bg-zinc-100" />
                </div>
              ))}
            </div>
          </div>
        ) : rows.length ? (
          <div className="divide-y divide-zinc-100">
            {rows.map((claim) => (
              <button
                key={claim.id}
                type="button"
                onClick={() => setSelected(claim)}
                className="group grid w-full gap-4 px-5 py-4 text-left transition-colors duration-200 hover:bg-teal-50/40 active:scale-[0.995] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-teal-700 sm:px-6 lg:grid-cols-[1.2fr_.8fr_.65fr_auto] lg:items-center"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-zinc-900">
                    {claim.title}
                  </p>
                  <p className="mt-1 truncate text-xs text-zinc-500">
                    {sourceLabel(claim.source)} · {claim.domains[0] || "No domain supplied"}
                  </p>
                </div>
                <div className="min-w-0">
                  <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
                    Organization context
                  </p>
                  <p className="mt-1 truncate text-xs text-zinc-600">
                    {claim.industry || claim.ai_industry || "Unknown industry"}
                    {` · ${claim.country || claim.ai_country || "Unknown geography"}`}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
                    Published
                  </p>
                  <p className="mt-1 whitespace-nowrap font-mono text-[11px] text-zinc-600">
                    {claim.published_at
                      ? formatTime(claim.published_at)
                      : "Not supplied"}
                  </p>
                </div>
                <span className="grid h-10 w-10 place-items-center rounded-xl border border-zinc-200 text-zinc-500 transition duration-200 group-hover:border-teal-300 group-hover:bg-white group-hover:text-teal-800">
                  <ArrowRight size={17} />
                </span>
              </button>
            ))}
          </div>
        ) : (
          <div className="px-5 py-12 text-center sm:px-6">
            <FingerprintSimple size={26} className="mx-auto text-zinc-400" />
            <p className="mt-4 text-sm font-medium text-zinc-700">
              No matching victim claims
            </p>
            <p className="mx-auto mt-2 max-w-md text-xs leading-5 text-zinc-500">
              {query
                ? "Clear the search to return to every retained claim for this actor."
                : "This actor profile currently has no retained victim observations."}
            </p>
          </div>
        )}
      </div>

      <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-zinc-200 px-5 py-4 sm:px-6">
        <p className="text-xs text-zinc-500">
          Page {data?.page ?? page} of {data?.pages ?? 1} · showing {rows.length} of {data?.total ?? 0}
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            className="button-secondary"
            disabled={page <= 1 || loading}
            onClick={() => setPage((current) => current - 1)}
          >
            Previous
          </button>
          <button
            type="button"
            className="button-secondary"
            disabled={page >= (data?.pages ?? 1) || loading}
            onClick={() => setPage((current) => current + 1)}
          >
            Next
          </button>
        </div>
      </footer>

      <AnimatePresence>
        {selected && (
          <CompleteClaimDetailModal
            claim={selected}
            enriching={enriching}
            drafting={drafting}
            error={error}
            onEnrich={() => void queueVictimTask("victim_enrichment")}
            onDraft={() => void queueVictimTask("claim_awareness_draft")}
            onClose={() => setSelected(null)}
          />
        )}
      </AnimatePresence>
    </section>
  );
}

function ActorPivotMetric({
  label,
  value,
  compact = false,
}: {
  label: string;
  value: string;
  compact?: boolean;
}) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
        {label}
      </p>
      <p
        className={`mt-1.5 truncate font-mono text-zinc-700 ${compact ? "text-[11px]" : "text-base"}`}
        title={value}
      >
        {value}
      </p>
    </div>
  );
}

function ProfileText({
  label,
  value,
  evidenceCount,
}: {
  label: string;
  value: string;
  evidenceCount?: number;
}) {
  return (
    <div className="rounded-xl bg-white p-4">
      <dt className="text-[10px] font-medium uppercase tracking-wide text-zinc-500">
        {label}
      </dt>
      <dd className="mt-2 text-xs leading-6 text-zinc-700">{value}</dd>
      {evidenceCount ? (
        <dd className="mt-2 text-[10px] text-sky-700">
          {evidenceCount} retained evidence reference
          {evidenceCount === 1 ? "" : "s"}
        </dd>
      ) : null}
    </div>
  );
}

function ProfileList({
  title,
  items,
}: {
  title: string;
  items: { name: string; count: number }[];
}) {
  return (
    <div>
      <p className="text-xs font-bold uppercase tracking-wide text-zinc-400">
        {title}
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {items.length ? (
          items.map((item) => (
            <span
              key={item.name}
              className="rounded-full bg-white px-2.5 py-1 text-xs text-zinc-700"
            >
              {item.name} · {item.count}
            </span>
          ))
        ) : (
          <span className="text-xs text-zinc-400">Not supplied</span>
        )}
      </div>
    </div>
  );
}

function FlexibleAnalysisCard({
  scope,
  value,
  options,
  analysis,
  working,
  onScope,
  onValue,
  onAnalyze,
}: {
  scope: IntelligenceAnalysisScope;
  value: string;
  options: string[];
  analysis: IntelligenceAIAnalysis | null;
  working: boolean;
  onScope: (scope: IntelligenceAnalysisScope) => void;
  onValue: (value: string) => void;
  onAnalyze: () => void;
}) {
  const scopeOptions: DropdownOption[] = [
    { value: "overall", label: "Overall ransomware trend" },
    { value: "actor", label: "By threat actor" },
    { value: "region", label: "By region" },
    { value: "industry", label: "By victim industry" },
  ];
  const targetLabels = {
    actor: "Choose a threat actor",
    region: "Choose a region",
    industry: "Choose a victim industry",
    overall: "Overall dataset",
  };
  const canAnalyze = scope === "overall" || Boolean(value);
  return (
    <section className="mt-5 rounded-[2rem] border border-violet-200 bg-white p-6 md:p-8">
      <div className="flex min-w-0 flex-col justify-between gap-5">
        <div>
          <p className="eyebrow !text-violet-700">
            Flexible AI-assisted analysis
          </p>
          <h3 className="mt-2 text-xl font-semibold">
            Landscape and victim-pattern assessment
          </h3>
          <p className="mt-2 max-w-3xl text-xs leading-5 text-zinc-500">
            Choose the whole landscape or narrow the evidence by actor, region,
            or victim industry. The model compares volume, growth, victim mix,
            geography, and concentration. Sourced actor profiles are blended
            with fresh, bounded clear-web research and kept distinct from the
            unverified local claim layer. Search evidence is retained with its
            publisher and URL; it does not confirm a victim allegation.
          </p>
        </div>
        <div className="grid min-w-0 gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <CustomSelect
            ariaLabel="Analysis scope"
            value={scope}
            onChange={(next) => onScope(next as IntelligenceAnalysisScope)}
            options={scopeOptions}
          />
          {scope === "overall" ? (
            <div className="input flex items-center text-zinc-500">
              All locally stored claims
            </div>
          ) : (
            <CustomSelect
              ariaLabel={targetLabels[scope]}
              value={value}
              onChange={onValue}
              placeholder={targetLabels[scope]}
              options={options.map((option) => ({
                value: option,
                label: option,
              }))}
            />
          )}
          <button
            type="button"
            disabled={!canAnalyze || working}
            onClick={onAnalyze}
            className="button-primary shrink-0 whitespace-nowrap !bg-violet-700 hover:!bg-violet-800"
          >
            {working ? (
              <SpinnerGap className="animate-spin" size={18} />
            ) : (
              <Cpu size={18} />
            )}
            {analysis ? "Refresh analysis" : "Analyze selection"}
          </button>
        </div>
      </div>
      {analysis ? (
        <div className="mt-6 grid gap-5 lg:grid-cols-[1.25fr_.75fr]">
          <div className="rounded-2xl bg-violet-50 p-5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-white px-3 py-1 text-xs font-semibold text-violet-800">
                {analysis.label}
              </span>
              <span className="text-xs text-violet-700">
                {analysis.claim_count} claims · {analysis.confidence}% AI
                confidence
              </span>
            </div>
            <p className="mt-4 text-sm leading-7 text-zinc-700">
              {analysis.summary || "The model did not provide a narrative."}
            </p>
            {analysis.patterns.length > 0 && (
              <AnalysisList
                title="Observed patterns"
                items={analysis.patterns}
              />
            )}
            {analysis.risk_observations.length > 0 && (
              <AnalysisList
                title="Defensive observations"
                items={analysis.risk_observations}
              />
            )}
            {analysis.caveats.length > 0 && (
              <AnalysisList
                title="Limitations"
                items={analysis.caveats}
                muted
              />
            )}
          </div>
          <div className="rounded-2xl border border-zinc-200 p-5">
            <p className="text-xs font-bold uppercase tracking-wide text-zinc-400">
              Observed locally
            </p>
            <dl className="mt-4 space-y-3 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-zinc-500">Current period</dt>
                <dd className="font-mono font-semibold">
                  {analysis.growth.current_count}
                </dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-zinc-500">Previous period</dt>
                <dd className="font-mono font-semibold">
                  {analysis.growth.previous_count}
                </dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-zinc-500">Change</dt>
                <dd className="font-mono font-semibold">
                  {analysis.growth.change > 0 ? "+" : ""}
                  {analysis.growth.change}
                </dd>
              </div>
            </dl>
            {analysis.threat_actor_context?.length ? (
              <div className="mt-5 border-t border-zinc-100 pt-4">
                <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
                  Actor context used
                </p>
                <div className="mt-2 space-y-2">
                  {analysis.threat_actor_context.map((item) => (
                    <div key={item.actor} className="rounded-xl bg-zinc-50 px-3 py-2">
                      <p className="text-xs text-zinc-700">{item.actor}</p>
                      <p className="mt-1 text-[10px] leading-4 text-zinc-400">
                        {item.professional_profile.sources.join(", ") || "Actor-label registry"} · {item.professional_profile.source_confidence} source confidence
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            {analysis.fresh_osint_safety_net?.length ? (
              <div className="mt-5 border-t border-zinc-100 pt-4">
                <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
                  Fresh OSINT safety net
                </p>
                <div className="mt-2 space-y-2">
                  {analysis.fresh_osint_safety_net.map((item) => (
                    <div key={item.actor} className="rounded-xl bg-zinc-50 px-3 py-2">
                      <p className="text-xs text-zinc-700">{item.actor}</p>
                      <p className="mt-1 text-[10px] leading-4 text-zinc-400">
                        {item.evidence.length} retained records · {item.independent_source_count} independent publishers · checked {formatTime(item.researched_at)}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            <p className="mt-5 text-[11px] leading-5 text-zinc-400">
              Generated {formatTime(analysis.generated_at)} with{" "}
              {analysis.provider} · {analysis.model}
            </p>
          </div>
        </div>
      ) : (
        <div className="mt-6 rounded-2xl border border-dashed border-violet-200 bg-violet-50/40 p-6 text-sm text-zinc-500">
          Select an analysis lens to generate a bounded assessment of the
          current local dataset.
        </div>
      )}
    </section>
  );
}

function AnalysisList({
  title,
  items,
  muted = false,
}: {
  title: string;
  items: string[];
  muted?: boolean;
}) {
  return (
    <div className="mt-4">
      <p
        className={`text-[11px] font-bold uppercase tracking-wide ${muted ? "text-zinc-400" : "text-violet-700"}`}
      >
        {title}
      </p>
      <ul
        className={`mt-2 space-y-2 text-sm ${muted ? "text-zinc-500" : "text-zinc-600"}`}
      >
        {items.map((item) => (
          <li key={item} className="flex gap-2">
            <span className="text-violet-500">•</span>
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

function AnalysisHistory({
  records,
  selectedId,
  onSelect,
}: {
  records: IntelligenceAIAnalysis[];
  selectedId: string;
  onSelect: (record: IntelligenceAIAnalysis) => void;
}) {
  return (
    <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
      <div className="flex items-start gap-3">
        <ClockCounterClockwise className="mt-0.5 text-violet-700" size={22} />
        <div>
          <p className="eyebrow !text-violet-700">Persisted analyst record</p>
          <h3 className="mt-2 text-xl font-semibold">Assessment history</h3>
          <p className="mt-2 text-xs leading-5 text-zinc-500">
            Every generated landscape assessment is retained with its evidence
            window, provider, model, and generation time.
          </p>
        </div>
      </div>
      <div className="mt-5 grid gap-3 lg:grid-cols-2">
        {records.length ? (
          records.map((record) => (
            <button
              key={record.id}
              type="button"
              onClick={() => onSelect(record)}
              aria-haspopup="dialog"
              className={`group rounded-2xl border p-4 text-left transition hover:border-violet-300 hover:bg-violet-50 ${selectedId === record.id ? "border-violet-300 bg-violet-50 ring-2 ring-violet-100" : "border-zinc-200"}`}
            >
              <div className="flex items-center justify-between gap-3">
                <span className="text-sm font-semibold">{record.label}</span>
                <span className="flex items-center gap-2">
                  <span className="rounded-full bg-white px-2 py-1 font-mono text-[10px] text-zinc-500">
                    {record.period_days}d
                  </span>
                  <ArrowRight
                    size={16}
                    className="text-zinc-400 transition-transform group-hover:translate-x-0.5 group-hover:text-violet-700"
                  />
                </span>
              </div>
              <p className="mt-2 line-clamp-2 text-xs leading-5 text-zinc-500">
                {record.summary || "No narrative returned"}
              </p>
              <p className="mt-3 font-mono text-[10px] text-zinc-400">
                {formatTime(record.generated_at)} · {record.provider} ·{" "}
                {record.model}
              </p>
            </button>
          ))
        ) : (
          <p className="rounded-2xl border border-dashed border-zinc-200 p-5 text-sm text-zinc-500">
            No historical assessments yet. Generate one above to create the
            first analyst record.
          </p>
        )}
      </div>
    </section>
  );
}

function AnalysisRecordDialog({
  record,
  onClose,
}: {
  record: IntelligenceAIAnalysis;
  onClose: () => void;
}) {
  return (
    <Modal
      wide
      title={record.label}
      description={`Persisted ${record.period_days}-day assessment generated ${formatTime(record.generated_at)} with ${record.provider} · ${record.model}.`}
      onClose={onClose}
    >
      <div className="mt-6 grid gap-5 lg:grid-cols-[1.25fr_.75fr]">
        <section className="rounded-2xl bg-violet-50 p-5 sm:p-6">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full bg-white px-3 py-1 text-xs text-violet-800">
              {record.scope === "overall"
                ? "Overall landscape"
                : record.scope.replaceAll("_", " ")}
            </span>
            <span className="text-xs text-violet-700">
              {record.claim_count.toLocaleString()} deduplicated claims · {record.confidence}% AI confidence
            </span>
          </div>
          <p className="mt-4 text-sm leading-7 text-zinc-700">
            {record.summary || "The model did not provide a narrative."}
          </p>
          {record.patterns.length > 0 && (
            <AnalysisList title="Observed patterns" items={record.patterns} />
          )}
          {record.risk_observations.length > 0 && (
            <AnalysisList
              title="Defensive observations"
              items={record.risk_observations}
            />
          )}
          {record.caveats.length > 0 && (
            <AnalysisList title="Limitations" items={record.caveats} muted />
          )}
        </section>

        <aside className="rounded-2xl border border-zinc-200 p-5 sm:p-6">
          <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
            Evidence window
          </p>
          <dl className="mt-4 divide-y divide-zinc-100 text-sm">
            <AnalysisRecordStat
              label="Current period"
              value={record.growth.current_count.toLocaleString()}
            />
            <AnalysisRecordStat
              label="Previous period"
              value={record.growth.previous_count.toLocaleString()}
            />
            <AnalysisRecordStat
              label="Change"
              value={`${record.growth.change > 0 ? "+" : ""}${record.growth.change.toLocaleString()}`}
            />
            <AnalysisRecordStat
              label="Country coverage"
              value={`${record.country_coverage}%`}
            />
            <AnalysisRecordStat
              label="Industry coverage"
              value={`${record.industry_coverage}%`}
            />
          </dl>
          <p className="mt-5 text-[11px] leading-5 text-zinc-400">
            This is a historical analyst artifact. It is displayed exactly from
            the locally persisted record and is not regenerated when opened.
          </p>
        </aside>
      </div>
    </Modal>
  );
}

function AnalysisRecordStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 py-3">
      <dt className="text-zinc-500">{label}</dt>
      <dd className="font-mono text-zinc-800">{value}</dd>
    </div>
  );
}

type ActivitySortKey =
  | "claim"
  | "actor"
  | "country"
  | "leak_size"
  | "published"
  | "ingested";
type ActivityDateFilter = "all" | "24h" | "7d" | "30d" | "missing";

function ActivityPage({ claims }: { claims: Claim[] }) {
  const [claimFilter, setClaimFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [countryFilter, setCountryFilter] = useState("");
  const [publishedFilter, setPublishedFilter] =
    useState<ActivityDateFilter>("all");
  const [ingestedFilter, setIngestedFilter] =
    useState<ActivityDateFilter>("all");
  const [sortKey, setSortKey] = useState<ActivitySortKey>("ingested");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");
  const actors = useMemo(
    () =>
      Array.from(
        new Set(claims.map((claim) => claim.threat_actor).filter(Boolean)),
      ).sort((a, b) => a.localeCompare(b)),
    [claims],
  );
  const countries = useMemo(
    () =>
      Array.from(
        new Set(claims.map((claim) => claim.country || "Unknown country")),
      ).sort((a, b) => a.localeCompare(b)),
    [claims],
  );
  const dateOptions: DropdownOption[] = [
    { value: "all", label: "Any date" },
    { value: "24h", label: "Last 24 hours" },
    { value: "7d", label: "Last 7 days" },
    { value: "30d", label: "Last 30 days" },
  ];
  const publishedOptions = [
    ...dateOptions,
    { value: "missing", label: "Date not supplied" },
  ];

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
      const claimText =
        `${claim.title} ${claim.source} ${claim.domains.join(" ")}`.toLowerCase();
      return (
        (!needle || claimText.includes(needle)) &&
        (!actorFilter || claim.threat_actor === actorFilter) &&
        (!countryFilter ||
          (claim.country || "Unknown country") === countryFilter) &&
        withinDate(claim.published_at, publishedFilter) &&
        withinDate(claim.received_at, ingestedFilter)
      );
    });
    const values = (claim: Claim) => ({
      claim: claim.title.toLowerCase(),
      actor: claim.threat_actor.toLowerCase(),
      country: (claim.country || "Unknown country").toLowerCase(),
      leak_size: claim.leak_size_bytes ?? -1,
      published: claim.published_at
        ? new Date(claim.published_at).getTime()
        : 0,
      ingested: new Date(claim.received_at).getTime(),
    });
    return filtered.sort((left, right) => {
      const a = values(left)[sortKey];
      const b = values(right)[sortKey];
      const order =
        typeof a === "number" && typeof b === "number"
          ? a - b
          : String(a).localeCompare(String(b));
      return sortDirection === "asc" ? order : -order;
    });
  }, [
    claims,
    claimFilter,
    actorFilter,
    countryFilter,
    publishedFilter,
    ingestedFilter,
    sortKey,
    sortDirection,
  ]);

  const sort = (key: ActivitySortKey) => {
    if (sortKey === key)
      setSortDirection((current) => (current === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDirection(
        key === "published" || key === "ingested" || key === "leak_size"
          ? "desc"
          : "asc",
      );
    }
  };
  const clearFilters = () => {
    setClaimFilter("");
    setActorFilter("");
    setCountryFilter("");
    setPublishedFilter("all");
    setIngestedFilter("all");
  };
  const filtered = Boolean(
    claimFilter ||
      actorFilter ||
      countryFilter ||
      publishedFilter !== "all" ||
      ingestedFilter !== "all",
  );

  return (
    <div>
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <PageIntro
          eyebrow="All observations"
          title="Activity"
          description="Filter and sort every displayed claim field, with separate source publication and local ingestion timestamps."
        />
        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-zinc-500">
            {rows.length.toLocaleString()} of {claims.length.toLocaleString()}
          </span>
          <button
            type="button"
            onClick={clearFilters}
            disabled={!filtered}
            className="button-secondary !min-h-10 px-3 text-xs"
          >
            Clear filters
          </button>
        </div>
      </div>
      <section className="mt-7 rounded-2xl border border-zinc-200 bg-white p-4">
        <p className="mb-3 text-xs font-bold uppercase tracking-wide text-zinc-400">
          Column filters
        </p>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[1.35fr_.75fr_.65fr_.7fr_.7fr]">
          <label className="flex min-h-12 items-center gap-3 rounded-xl border border-zinc-200 bg-white px-4 focus-within:border-teal-700 focus-within:ring-4 focus-within:ring-teal-700/10">
            <MagnifyingGlass size={17} className="text-zinc-400" />
            <span className="sr-only">Filter claim column</span>
            <input
              value={claimFilter}
              onChange={(event) => setClaimFilter(event.target.value)}
              className="w-full bg-transparent text-sm outline-none"
              placeholder="Company, source, or domain"
            />
          </label>
          <CustomSelect
            ariaLabel="Filter threat actor column"
            value={actorFilter}
            onChange={setActorFilter}
            options={[
              { value: "", label: "All threat actors" },
              ...actors.map((actor) => ({ value: actor, label: actor })),
            ]}
          />
          <CustomSelect
            ariaLabel="Filter country column"
            value={countryFilter}
            onChange={setCountryFilter}
            options={[
              { value: "", label: "All countries" },
              ...countries.map((country) => ({
                value: country,
                label: country,
              })),
            ]}
          />
          <CustomSelect
            ariaLabel="Filter published column"
            value={publishedFilter}
            onChange={(value) =>
              setPublishedFilter(value as ActivityDateFilter)
            }
            options={publishedOptions}
          />
          <CustomSelect
            ariaLabel="Filter ingested column"
            value={ingestedFilter}
            onChange={(value) => setIngestedFilter(value as ActivityDateFilter)}
            options={dateOptions}
          />
        </div>
      </section>
      <div className="mt-5 overflow-x-auto rounded-2xl border border-zinc-200 bg-white">
        <div className="hidden min-w-[900px] grid-cols-[1.35fr_.75fr_.65fr_.7fr_.7fr] gap-4 border-b border-zinc-200 bg-zinc-50 px-5 py-2 md:grid">
          <ActivitySortHeader
            label="Claim"
            column="claim"
            active={sortKey}
            direction={sortDirection}
            onSort={sort}
          />
          <ActivitySortHeader
            label="Threat actor"
            column="actor"
            active={sortKey}
            direction={sortDirection}
            onSort={sort}
          />
          <ActivitySortHeader
            label="Country"
            column="country"
            active={sortKey}
            direction={sortDirection}
            onSort={sort}
          />
          <ActivitySortHeader
            label="Published"
            column="published"
            active={sortKey}
            direction={sortDirection}
            onSort={sort}
          />
          <ActivitySortHeader
            label="Ingested"
            column="ingested"
            active={sortKey}
            direction={sortDirection}
            onSort={sort}
          />
        </div>
        {rows.map((claim, index) => (
          <div
            key={claim.id}
            className={`grid min-w-[900px] gap-4 p-5 md:grid-cols-[1.35fr_.75fr_.65fr_.7fr_.7fr] md:items-center ${index ? "border-t border-zinc-200" : ""}`}
          >
            <div>
              <p className="font-semibold">{claim.title}</p>
              <p className="mt-1 text-xs text-zinc-500">
                {sourceLabel(claim.source)} ·{" "}
                {claim.domains[0] || "public allegation"}
              </p>
            </div>
            <p className="text-sm text-zinc-600">{claim.threat_actor}</p>
            <p className="text-sm text-zinc-600">
              {claim.country || "Unknown country"}
            </p>
            <div>
              <p className="text-[10px] font-semibold uppercase text-zinc-400 md:hidden">
                Published
              </p>
              <p className="font-mono text-xs text-zinc-500">
                {claim.published_at
                  ? formatTime(claim.published_at)
                  : "Not supplied"}
              </p>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase text-zinc-400 md:hidden">
                Ingested
              </p>
              <p className="font-mono text-xs text-zinc-500">
                {formatTime(claim.received_at)}
              </p>
            </div>
          </div>
        ))}
        {!rows.length && (
          <div className="p-10 text-center text-sm text-zinc-500">
            No activity matches all column filters.
          </div>
        )}
      </div>
    </div>
  );
}

function ActivitySortHeader({
  label,
  column,
  active,
  direction,
  onSort,
}: {
  label: string;
  column: ActivitySortKey;
  active: ActivitySortKey;
  direction: "asc" | "desc";
  onSort: (column: ActivitySortKey) => void;
}) {
  const selected = active === column;
  return (
    <button
      type="button"
      onClick={() => onSort(column)}
      aria-label={`Sort ${label} ${selected && direction === "asc" ? "descending" : "ascending"}`}
      className={`flex items-center justify-between gap-2 rounded-lg px-2 py-2 text-left text-xs font-semibold uppercase tracking-wide transition hover:bg-zinc-100 ${selected ? "text-teal-800" : "text-zinc-500"}`}
    >
      <span>{label}</span>
      <CaretDown
        size={14}
        className={`transition ${selected ? "opacity-100" : "opacity-30"} ${selected && direction === "asc" ? "rotate-180" : ""}`}
      />
    </button>
  );
}

function ActivityDetailPage() {
  const [data, setData] = useState<ActivityResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [actor, setActor] = useState("");
  const [country, setCountry] = useState("");
  const [dateBasis, setDateBasis] = useState<"published" | "ingested">(
    "published",
  );
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [sortKey, setSortKey] = useState<ActivitySortKey>("ingested");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);
  const [focusOnly, setFocusOnly] = useState(false);
  const [newOnly, setNewOnly] = useState(false);
  const [selected, setSelected] = useState<Claim | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [enriching, setEnriching] = useState(false);
  const [drafting, setDrafting] = useState(false);
  const [bulkEnriching, setBulkEnriching] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.activity({
        page,
        page_size: pageSize,
        query,
        actor,
        country,
        date_basis: dateBasis,
        date_from: dateFrom,
        date_to: dateTo,
        sort: sortKey,
        direction: sortDirection,
        focus_only: focusOnly,
        new_only: newOnly,
      });
      setData(response);
      setSelected((current) =>
        current
          ? (response.items.find((item) => item.id === current.id) ?? current)
          : null,
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Activity could not be loaded",
      );
    } finally {
      setLoading(false);
    }
  }, [
    page,
    pageSize,
    query,
    actor,
    country,
    dateBasis,
    dateFrom,
    dateTo,
    sortKey,
    sortDirection,
    focusOnly,
    newOnly,
  ]);
  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 220);
    return () => window.clearTimeout(timer);
  }, [load]);
  useEffect(() => {
    setPage(1);
  }, [
    query,
    actor,
    country,
    dateBasis,
    dateFrom,
    dateTo,
    pageSize,
    focusOnly,
    newOnly,
  ]);
  const sort = (key: ActivitySortKey) => {
    if (sortKey === key)
      setSortDirection((value) => (value === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDirection(
        key === "published" || key === "ingested" || key === "leak_size"
          ? "desc"
          : "asc",
      );
    }
    setPage(1);
  };
  const rows = data?.items ?? [];
  const allPageSelected =
    rows.length > 0 && rows.every((claim) => selectedIds.has(claim.id));
  const togglePage = () =>
    setSelectedIds((current) => {
      const next = new Set(current);
      rows.forEach((claim) =>
        allPageSelected ? next.delete(claim.id) : next.add(claim.id),
      );
      return next;
    });
  const queueBulk = async () => {
    const ids = Array.from(selectedIds);
    if (!ids.length) return;
    setBulkEnriching(true);
    try {
      for (let index = 0; index < ids.length; index += 25) {
        const batch = ids.slice(index, index + 25);
        await api.queueAIJob("bulk_victim_enrichment", {
          claim_ids: batch,
          limit: batch.length,
        });
      }
      setNotice(
        `${ids.length} victim profiles queued for background enrichment.`,
      );
      setSelectedIds(new Set());
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Enrichment could not be queued",
      );
    } finally {
      setBulkEnriching(false);
    }
  };
  const enrich = async () => {
    if (!selected) return;
    setEnriching(true);
    try {
      await api.queueAIJob("victim_enrichment", { claim_id: selected.id });
      setNotice(`Background research queued for ${selected.title}.`);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Research could not be queued",
      );
    } finally {
      setEnriching(false);
    }
  };
  const draft = async () => {
    if (!selected) return;
    setDrafting(true);
    try {
      await api.queueAIJob("claim_awareness_draft", { claim_id: selected.id });
      setNotice(`Awareness-email draft queued for ${selected.title}.`);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Draft could not be queued",
      );
    } finally {
      setDrafting(false);
    }
  };
  return (
    <div>
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <PageIntro
          eyebrow="All observations"
          title="Activity"
          description="Search and traverse every retained claim. Open a row for the complete archived source record and enrichment context."
        />
        <span className="font-mono text-xs text-zinc-500">
          {data?.total.toLocaleString() ?? "—"} retained records
        </span>
      </div>
      <section className="mt-7 rounded-2xl border border-zinc-200 bg-white p-4">
        <div className="grid gap-3 lg:grid-cols-[1.4fr_1fr_1fr]">
          <label className="flex min-h-12 items-center gap-3 rounded-xl border border-zinc-200 px-4">
            <MagnifyingGlass size={17} className="text-zinc-400" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="w-full bg-transparent text-sm outline-none"
              placeholder="Company, domain, source, or context"
            />
          </label>
          <SearchableSelect
            ariaLabel="Filter threat actor"
            value={actor}
            onChange={setActor}
            searchPlaceholder="Search threat actors…"
            options={[
              { value: "", label: "All threat actors" },
              ...(data?.actors ?? []).map((value) => ({ value, label: value })),
            ]}
          />
          <SearchableSelect
            ariaLabel="Filter geography"
            value={country}
            onChange={setCountry}
            searchPlaceholder="Search regions or countries…"
            options={[
              { value: "", label: "All geographies" },
              ...(data?.countries ?? []).map((value) => ({
                value,
                label: value,
              })),
            ]}
          />
        </div>
        <div className="mt-3 grid gap-3 border-t border-zinc-100 pt-3 md:grid-cols-2 xl:grid-cols-4">
          <CustomSelect
            ariaLabel="Choose date field"
            value={dateBasis}
            onChange={(value) =>
              setDateBasis(value as "published" | "ingested")
            }
            options={[
              { value: "published", label: "Published date" },
              { value: "ingested", label: "Ingested date" },
            ]}
          />
          <CustomDatePicker
            ariaLabel="Choose start date"
            value={dateFrom}
            max={dateTo || undefined}
            onChange={setDateFrom}
          />
          <CustomDatePicker
            ariaLabel="Choose end date"
            value={dateTo}
            min={dateFrom || undefined}
            onChange={setDateTo}
            align="right"
          />
          <CustomSelect
            ariaLabel="Rows per page"
            value={String(pageSize)}
            onChange={(value) => setPageSize(Number(value))}
            options={[50, 100, 250].map((value) => ({
              value: String(value),
              label: `${value} rows per page`,
            }))}
          />
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-zinc-100 pt-3">
          <button
            type="button"
            disabled={!data?.focus_regions?.length}
            aria-pressed={focusOnly}
            onClick={() => setFocusOnly((value) => !value)}
            className={`rounded-full border px-3 py-2 text-xs transition disabled:cursor-not-allowed disabled:opacity-45 ${
              focusOnly
                ? "border-teal-700 bg-teal-700 text-white"
                : "border-zinc-200 bg-white text-zinc-600 hover:border-teal-300"
            }`}
          >
            Focus regions only
          </button>
          <button
            type="button"
            aria-pressed={newOnly}
            onClick={() => setNewOnly((value) => !value)}
            className={`rounded-full border px-3 py-2 text-xs transition ${
              newOnly
                ? "border-teal-700 bg-teal-700 text-white"
                : "border-zinc-200 bg-white text-zinc-600 hover:border-teal-300"
            }`}
          >
            New in last 24 hours
          </button>
          <span className="ml-auto text-xs text-zinc-500">
            {data?.daily_focus_count ?? 0} new in selected regions
          </span>
        </div>
      </section>
      {notice && <InlineNotice tone="neutral">{notice}</InlineNotice>}
      {error && <InlineNotice tone="danger">{error}</InlineNotice>}
      <section className="mt-5 flex flex-col justify-between gap-3 rounded-2xl border border-violet-200 bg-violet-50/50 p-4 xl:flex-row xl:items-center">
        <label className="flex items-center gap-3 text-sm font-medium">
          <input
            type="checkbox"
            checked={allPageSelected}
            onChange={togglePage}
            className="h-4 w-4 accent-violet-700"
          />
          Select all {rows.length} on this page
        </label>
        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-violet-800">
            {selectedIds.size} selected
          </span>
          <button
            type="button"
            disabled={!selectedIds.size || bulkEnriching}
            onClick={() => void queueBulk()}
            className="button-primary !bg-violet-700"
          >
            {bulkEnriching ? (
              <SpinnerGap className="animate-spin" size={18} />
            ) : (
              <Cpu size={18} />
            )}
            Bulk AI enrich
          </button>
        </div>
      </section>
      <div className="mt-5 overflow-hidden rounded-2xl border border-zinc-200 bg-white xl:overflow-x-auto">
        <div className="hidden min-w-[900px] grid-cols-[1.2fr_1.45fr_.72fr_.68fr_.72fr_1.1fr] gap-2 border-b border-zinc-200 bg-zinc-50 px-4 py-3 xl:grid">
          <ActivitySortHeader
            label="Claim"
            column="claim"
            active={sortKey}
            direction={sortDirection}
            onSort={sort}
          />
          <div className="px-2 py-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">
            Victim description
          </div>
          <ActivitySortHeader
            label="Threat actor"
            column="actor"
            active={sortKey}
            direction={sortDirection}
            onSort={sort}
          />
          <ActivitySortHeader
            label="Geography"
            column="country"
            active={sortKey}
            direction={sortDirection}
            onSort={sort}
          />
          <ActivitySortHeader
            label="Data exfiltrated"
            column="leak_size"
            active={sortKey}
            direction={sortDirection}
            onSort={sort}
          />
          <div className="grid gap-0.5 border-l border-zinc-200 pl-2">
            <ActivitySortHeader
              label="Published"
              column="published"
              active={sortKey}
              direction={sortDirection}
              onSort={sort}
            />
            <ActivitySortHeader
              label="Ingested"
              column="ingested"
              active={sortKey}
              direction={sortDirection}
              onSort={sort}
            />
          </div>
        </div>
        {loading && !rows.length ? (
          <div className="p-5 sm:p-7">
            <LoadingStatusCard
              title="Loading activity records"
              description="Applying the selected filters and retrieving retained claims."
              className="mx-auto max-w-xl"
            />
          </div>
        ) : (
          rows.map((claim, index) => (
            <div
              role="button"
              tabIndex={0}
              key={claim.id}
              onClick={() => setSelected(claim)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  setSelected(claim);
                }
              }}
              aria-label={`Open complete record for ${claim.title}`}
              className={`group grid cursor-pointer gap-4 p-4 transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-teal-700 xl:min-w-[900px] xl:grid-cols-[1.2fr_1.45fr_.72fr_.68fr_.72fr_1.1fr] xl:items-center xl:gap-2 ${
                claim.is_focus_region && claim.is_new_today
                  ? "bg-teal-50/80 hover:bg-teal-100/70"
                  : claim.is_focus_region
                    ? "bg-teal-50/35 hover:bg-teal-50/70"
                    : "hover:bg-teal-50/40"
              } ${index ? "border-t border-zinc-200" : ""}`}
            >
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={selectedIds.has(claim.id)}
                  aria-label={`Select ${claim.title}`}
                  onClick={(event) => event.stopPropagation()}
                  onChange={(event) =>
                    setSelectedIds((current) => {
                      const next = new Set(current);
                      event.target.checked
                        ? next.add(claim.id)
                        : next.delete(claim.id);
                      return next;
                    })
                  }
                  className="mt-1 h-4 w-4 accent-violet-700"
                />
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-medium">{claim.title}</p>
                    {claim.is_focus_region && (
                      <span className="rounded-full bg-teal-700 px-2 py-0.5 text-[9px] uppercase tracking-wide text-white">
                        {claim.is_new_today ? "New focus victim" : "Focus region"}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-zinc-500">
                    {sourceLabel(claim.source)} ·{" "}
                    {claim.domains[0] || "public allegation"}
                  </p>
                  {!!claim.matched_focus_regions?.length && (
                    <p className="mt-1 text-[10px] text-teal-700">
                      Matches {claim.matched_focus_regions.join(", ")}
                    </p>
                  )}
                </div>
              </div>
              <VictimDescriptionPreview claim={claim} />
              <ActivityMobileField label="Threat actor">
                {claim.threat_actor}
              </ActivityMobileField>
              <ActivityMobileField label="Geography">
                {claim.country || claim.ai_country || "Unknown country"}
              </ActivityMobileField>
              <div
                className="text-sm text-zinc-600"
                title={
                  claim.leak_size
                    ? `Source-reported, unverified value · ${claim.leak_size_source || "source metadata"}`
                    : "No explicit leaked-data volume was supplied by retained sources"
                }
              >
                <p className="mb-1 text-[10px] font-medium uppercase tracking-wide text-zinc-400 xl:hidden">
                  Data exfiltrated
                </p>
                <p>{claim.leak_size || "Not reported"}</p>
                {claim.leak_size && (
                  <p className="mt-1 text-[10px] text-zinc-400">
                    Source-reported
                  </p>
                )}
              </div>
              <div className="flex items-center justify-between gap-2 border-zinc-100 xl:border-l xl:pl-3">
                <div className="grid min-w-0 gap-2">
                  <div>
                    <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400 xl:sr-only">
                      Published
                    </p>
                    <p className="whitespace-nowrap font-mono text-xs text-zinc-500">
                      {claim.published_at
                        ? formatTime(claim.published_at)
                        : "Not supplied"}
                    </p>
                  </div>
                  <div>
                    <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400 xl:sr-only">
                      Ingested
                    </p>
                    <p className="whitespace-nowrap font-mono text-xs text-zinc-500">
                      {formatTime(claim.received_at)}
                    </p>
                  </div>
                </div>
                <ArrowRight size={17} />
              </div>
            </div>
          ))
        )}
      </div>
      <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-zinc-500">
          Page {data?.page ?? page} of {data?.pages ?? 1} · showing{" "}
          {rows.length} of {data?.total ?? 0}
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            className="button-secondary"
            disabled={page <= 1 || loading}
            onClick={() => setPage((value) => value - 1)}
          >
            Previous
          </button>
          <button
            type="button"
            className="button-secondary"
            disabled={page >= (data?.pages ?? 1) || loading}
            onClick={() => setPage((value) => value + 1)}
          >
            Next
          </button>
        </div>
      </div>
      <AnimatePresence>
        {selected && (
          <CompleteClaimDetailModal
            claim={selected}
            enriching={enriching}
            drafting={drafting}
            error={error}
            onEnrich={() => void enrich()}
            onDraft={() => void draft()}
            onClose={() => setSelected(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function VictimDescriptionPreview({ claim }: { claim: Claim }) {
  const description = claim.ai_description || claim.description;
  if (!description) {
    return (
      <div className="min-w-0 rounded-xl border border-dashed border-zinc-200 bg-zinc-50/70 px-3 py-2.5">
        <p className="text-xs leading-5 text-zinc-500">
          No organization background supplied
        </p>
        <p className="mt-0.5 text-[10px] text-zinc-400">
          Open the record to request enrichment
        </p>
      </div>
    );
  }
  const preview = claim.ai_description
    ? description.replace(/^\[AI generated\]\s*/i, "")
    : description;
  return (
    <div className="min-w-0 rounded-xl border border-transparent px-2 py-2 transition-colors duration-200 group-hover:border-zinc-200 group-hover:bg-white">
      <div className="flex min-w-0 items-start gap-2.5">
        <span
          className={`mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-lg ${claim.ai_description ? "bg-violet-50 text-violet-700" : "bg-zinc-100 text-zinc-500"}`}
          aria-hidden="true"
        >
          <Info size={14} weight="bold" />
        </span>
        <div className="min-w-0">
          <p
            className={`text-[10px] font-medium uppercase tracking-wide ${claim.ai_description ? "text-violet-700" : "text-zinc-500"}`}
          >
            {claim.ai_description ? "AI-enriched profile" : "Source supplied"}
          </p>
          <p className="mt-1 line-clamp-2 break-words text-xs leading-5 text-zinc-600">
            {preview}
          </p>
          <p className="mt-1 text-[10px] text-zinc-400 opacity-0 transition-opacity duration-200 group-hover:opacity-100 group-focus-visible:opacity-100">
            Open record for the complete description
          </p>
        </div>
      </div>
    </div>
  );
}

function ActivityMobileField({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <p className="mb-1 text-[10px] font-medium uppercase tracking-wide text-zinc-400 xl:hidden">
        {label}
      </p>
      <p className="truncate text-sm text-zinc-600">{children}</p>
    </div>
  );
}

function CompleteClaimDetailModal({
  claim,
  enriching,
  drafting,
  error,
  onEnrich,
  onDraft,
  onClose,
}: {
  claim: Claim;
  enriching: boolean;
  drafting: boolean;
  error: string;
  onEnrich: () => void;
  onDraft: () => void;
  onClose: () => void;
}) {
  const [evidence, setEvidence] = useState<ClaimSourceEvidence | null>(null);
  const [evidenceError, setEvidenceError] = useState("");
  const [evidenceExpanded, setEvidenceExpanded] = useState(false);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [actorProfileOpen, setActorProfileOpen] = useState(false);
  const [actorProfile, setActorProfile] = useState<ThreatActorProfile | null>(
    null,
  );
  const [actorProfileLoading, setActorProfileLoading] = useState(false);
  const [actorProfileError, setActorProfileError] = useState("");
  const openActorProfile = async () => {
    setActorProfileOpen(true);
    if (actorProfile?.actor === claim.threat_actor) return;
    setActorProfileLoading(true);
    setActorProfileError("");
    try {
      setActorProfile(await api.actorProfile(claim.threat_actor));
    } catch (reason) {
      setActorProfileError(
        reason instanceof Error
          ? reason.message
          : "Threat-actor profile could not be loaded",
      );
    } finally {
      setActorProfileLoading(false);
    }
  };
  const toggleEvidence = async () => {
    if (evidenceExpanded) {
      setEvidenceExpanded(false);
      return;
    }
    setEvidenceExpanded(true);
    if (evidence) return;
    setEvidenceLoading(true);
    setEvidenceError("");
    try {
      setEvidence(await api.claimSourceEvidence(claim.id));
    } catch (reason) {
      setEvidenceError(
        reason instanceof Error
          ? reason.message
          : "Archived source evidence could not be loaded",
      );
    } finally {
      setEvidenceLoading(false);
    }
  };
  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !actorProfileOpen) onClose();
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [actorProfileOpen, onClose]);
  useEffect(() => {
    setActorProfile(null);
    setActorProfileError("");
    setActorProfileOpen(false);
  }, [claim.threat_actor]);
  return (
    <>
      <motion.div
        className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-zinc-950/40 p-4 backdrop-blur-sm"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      >
      <motion.section
        role="dialog"
        aria-modal="true"
        className="my-6 max-h-[calc(100dvh-3rem)] w-full max-w-5xl overflow-y-auto rounded-[2rem] bg-white shadow-2xl"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: 12 }}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-zinc-200 bg-white/95 px-6 py-4 backdrop-blur">
          <div>
            <p className="eyebrow">Complete claim record</p>
            <h2 className="mt-1 text-xl font-semibold">{claim.title}</h2>
          </div>
          <button
            type="button"
            aria-label="Close details"
            onClick={onClose}
            className="grid h-10 w-10 place-items-center rounded-xl border border-zinc-200"
          >
            <X size={18} />
          </button>
        </header>
        <div className="space-y-6 p-6">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <ActorProfileMetric
              actor={claim.threat_actor}
              onOpen={() => void openActorProfile()}
            />
            <DetailMetric
              label="Published"
              value={
                claim.published_at
                  ? formatTime(claim.published_at)
                  : "Not supplied"
              }
            />
            <DetailMetric
              label="Est. attack date"
              value={
                claim.attack_date
                  ? formatTime(claim.attack_date)
                  : "Not supplied"
              }
            />
            <DetailMetric
              label="Ingested"
              value={formatTime(claim.received_at)}
            />
            <DetailMetric label="Source" value={sourceLabel(claim.source)} />
            <DetailMetric
              label="Data exfiltrated"
              value={
                claim.leak_size
                  ? `${claim.leak_size} · source-reported`
                  : "Not reported"
              }
            />
          </div>
          {claim.source_tags.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {claim.source_tags.map((tag) => (
                <span
                  key={tag}
                  className="rounded-full bg-amber-50 px-3 py-1 text-xs text-amber-800"
                >
                  {tag}
                </span>
              ))}
            </div>
          )}
          <section className="rounded-2xl border border-zinc-200 p-5">
            <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
              Source-supplied description
            </p>
            <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-7 text-zinc-700">
              {claim.description || "No source description supplied."}
            </p>
            <p className="mt-3 text-[11px] leading-5 text-zinc-500">
              This is the complete description received from the upstream API.
              It may itself be incomplete or combine organization background
              with actor-authored wording.
            </p>
            {claim.source_url && (
              <a
                href={claim.source_url}
                target="_blank"
                rel="noreferrer"
                className="mt-4 inline-flex text-xs font-medium text-teal-800 underline underline-offset-2"
              >
                Open source reference
              </a>
            )}
            {claim.source_screenshot_url && (
              <a
                href={claim.source_screenshot_url}
                target="_blank"
                rel="noreferrer"
                className="ml-4 mt-4 inline-flex text-xs font-medium text-teal-800 underline underline-offset-2"
              >
                Open source screenshot
              </a>
            )}
          </section>
          {claim.ai_description && (
            <section className="rounded-2xl border border-violet-200 bg-violet-50/40 p-5">
              <p className="text-xs font-medium uppercase tracking-wide text-violet-700">
                AI-enriched organization background
              </p>
              <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-7 text-zinc-700">
                {claim.ai_description}
              </p>
            </section>
          )}
          <section className="rounded-2xl border border-zinc-200 p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                  Complete archived source record
                </p>
                <p className="mt-1 text-xs text-zinc-500">
                  The original normalized collector payload retained at
                  ingestion.
                </p>
              </div>
              <button
                type="button"
                onClick={() => void toggleEvidence()}
                className="button-secondary !min-h-9 px-3 py-2 text-xs"
              >
                {evidenceLoading ? (
                  <SpinnerGap className="animate-spin" size={15} />
                ) : (
                  <CaretDown
                    size={15}
                    className={`transition ${evidenceExpanded ? "rotate-180" : ""}`}
                  />
                )}
                {evidenceExpanded ? "Collapse" : "Show record"}
              </button>
            </div>
            {evidenceExpanded && evidenceError && (
              <InlineNotice tone="danger">{evidenceError}</InlineNotice>
            )}
            {evidenceExpanded && evidence ? (
              <>
                <div className="mt-4 rounded-xl border border-zinc-200 bg-white p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-xs font-medium text-zinc-700">
                      Retained source observations
                    </p>
                    <span className="rounded-full bg-zinc-100 px-2.5 py-1 font-mono text-[10px] text-zinc-600">
                      {evidence.observations.length} retained
                    </span>
                  </div>
                  <div className="mt-3 max-h-48 space-y-2 overflow-y-auto">
                    {evidence.observations.map((observation) => (
                      <div
                        key={observation.id}
                        className="grid gap-1 rounded-lg bg-zinc-50 px-3 py-2 text-[11px] text-zinc-600 sm:grid-cols-[minmax(0,1fr)_auto]"
                      >
                        <span className="min-w-0 truncate">
                          {sourceLabel(observation.source)} ·{" "}
                          {observation.source_record_id || "No source record ID"}
                        </span>
                        <span className="font-mono text-zinc-500">
                          {formatTime(observation.received_at)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
                <p className="mt-4 font-mono text-[10px] text-zinc-500">
                  Primary source record ID: {evidence.source_record_id}
                </p>
                <pre className="mt-4 max-h-[38rem] overflow-auto whitespace-pre-wrap break-words rounded-xl bg-zinc-950 p-4 font-mono text-[11px] leading-5 text-zinc-100">
                  {JSON.stringify(evidence.archived_record, null, 2)}
                </pre>
              </>
            ) : (
              evidenceExpanded &&
              !evidenceError &&
              evidenceLoading && (
                <LoadingStatusCard
                  title="Loading archived evidence"
                  description="Retrieving the complete retained source record."
                  className="mt-4 max-w-lg"
                />
              )
            )}
          </section>
          <section className="rounded-2xl border border-violet-200 bg-violet-50/40 p-5">
            <p className="text-xs font-medium uppercase tracking-wide text-violet-700">
              Analyst assistance
            </p>
            <div className="mt-4 flex flex-wrap gap-3">
              <button
                type="button"
                disabled={enriching || drafting}
                onClick={onEnrich}
                className="button-primary !bg-violet-700"
              >
                {enriching ? (
                  <SpinnerGap className="animate-spin" size={18} />
                ) : (
                  <Cpu size={18} />
                )}
                AI enrich victim
              </button>
              <button
                type="button"
                disabled={enriching || drafting}
                onClick={onDraft}
                className="button-secondary"
              >
                {drafting ? (
                  <SpinnerGap className="animate-spin" size={18} />
                ) : (
                  <EnvelopeSimple size={18} />
                )}
                Draft awareness email
              </button>
            </div>
            {error && <InlineNotice tone="danger">{error}</InlineNotice>}
          </section>
          <InlineNotice tone="neutral">
            This is an unverified public allegation. Preserve the source record
            as evidence, but validate victim identity and internal telemetry
            before escalation.
          </InlineNotice>
        </div>
        </motion.section>
      </motion.div>
      <AnimatePresence>
        {actorProfileOpen && (
          <ThreatActorProfilePreviewDialog
            actor={claim.threat_actor}
            profile={actorProfile}
            loading={actorProfileLoading}
            error={actorProfileError}
            onClose={() => setActorProfileOpen(false)}
          />
        )}
      </AnimatePresence>
    </>
  );
}

function ThreatActorProfilePreviewDialog({
  actor,
  profile,
  loading,
  error,
  onClose,
}: {
  actor: string;
  profile: ThreatActorProfile | null;
  loading: boolean;
  error: string;
  onClose: () => void;
}) {
  const professional = resolveProfessionalProfile(profile);
  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [onClose]);
  return (
    <motion.div
      className="fixed inset-0 z-[60] grid place-items-center overflow-y-auto bg-zinc-950/55 p-4 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.section
        role="dialog"
        aria-modal="true"
        aria-labelledby="actor-profile-preview-title"
        className="my-6 max-h-[calc(100dvh-3rem)] w-full max-w-4xl overflow-y-auto rounded-[2rem] bg-[#f8faf9] shadow-2xl"
        initial={{ opacity: 0, y: 18, scale: 0.985 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 12, scale: 0.99 }}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="sticky top-0 z-10 flex items-start justify-between gap-5 border-b border-zinc-200 bg-[#f8faf9]/95 px-5 py-4 backdrop-blur sm:px-7">
          <div className="min-w-0">
            <p className="eyebrow !text-violet-700">
              Professional threat-actor profile
            </p>
            <h2
              id="actor-profile-preview-title"
              className="mt-1 truncate text-xl font-medium text-zinc-900"
            >
              {profile?.actor || actor}
            </h2>
          </div>
          <button
            type="button"
            autoFocus
            aria-label="Close threat-actor profile"
            onClick={onClose}
            className="icon-button shrink-0"
          >
            <X size={19} />
          </button>
        </header>
        <div className="space-y-5 p-5 sm:p-7">
          {loading ? (
            <div className="grid min-h-72 place-items-center rounded-2xl border border-violet-200 bg-white">
              <LoadingStatusCard
                title="Loading retained CTI profile"
                description="Preparing sourced actor context and local observation data."
                className="w-full max-w-md px-4"
              />
            </div>
          ) : error ? (
            <InlineNotice tone="danger">{error}</InlineNotice>
          ) : profile && professional ? (
            <>
              <section className="rounded-2xl border border-violet-200 bg-white p-5 sm:p-6">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full bg-violet-50 px-2.5 py-1 text-[10px] font-medium uppercase tracking-wide text-violet-800">
                    {professional.profile_status.replaceAll("_", " ")}
                  </span>
                  <span className="rounded-full bg-zinc-100 px-2.5 py-1 text-[10px] font-medium uppercase tracking-wide text-zinc-600">
                    {professional.source_confidence} source confidence
                  </span>
                  <span className="rounded-full bg-teal-50 px-2.5 py-1 text-[10px] font-medium uppercase tracking-wide text-teal-800">
                    {professional.distribution}
                  </span>
                </div>
                <p className="mt-4 text-sm leading-7 text-zinc-700">
                  {professional.summary}
                </p>
                <p className="mt-3 text-[11px] leading-5 text-zinc-500">
                  {actorProfileProvenance(professional)}
                  {professional.reviewed_at
                    ? ` · reviewed ${professional.reviewed_at}`
                    : ""}
                  {professional.generated_at
                    ? ` · AI refreshed ${formatTime(professional.generated_at)}`
                    : ""}
                </p>
              </section>

              <dl className="grid gap-3 sm:grid-cols-2">
                <ProfileText
                  label="Motivation"
                  value={
                    professional.motivation ||
                    "Not established in retained OSINT."
                  }
                  evidenceCount={professional.field_evidence?.motivation?.length}
                />
                <ProfileText
                  label="Targeting"
                  value={
                    professional.targeting ||
                    "Not established in retained OSINT."
                  }
                  evidenceCount={professional.field_evidence?.targeting?.length}
                />
                <ProfileText
                  label="Capabilities"
                  value={
                    professional.capabilities ||
                    "Not established in retained OSINT."
                  }
                  evidenceCount={professional.field_evidence?.capabilities?.length}
                />
                <ProfileText
                  label="Campaign history"
                  value={
                    professional.campaign_history ||
                    "Not established in retained OSINT."
                  }
                  evidenceCount={
                    professional.field_evidence?.campaign_history?.length
                  }
                />
              </dl>

              <section className="grid gap-4 rounded-2xl border border-zinc-200 bg-white p-5 lg:grid-cols-[1.15fr_.85fr]">
                <div>
                  <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-500">
                    Identity and provenance
                  </p>
                  <p className="mt-2 text-sm text-zinc-800">
                    {professional.identity.canonical_name}
                    {professional.identity.attack_id
                      ? ` · ${professional.identity.attack_id}`
                      : ""}
                  </p>
                  <p className="mt-2 text-xs leading-5 text-zinc-500">
                    {professional.identity.resolution_basis}
                  </p>
                  {professional.identity.aliases.length > 0 && (
                    <p className="mt-3 text-xs leading-5 text-zinc-600">
                      Aliases: {professional.identity.aliases.join(", ")}
                    </p>
                  )}
                  <div className="mt-4 flex flex-wrap gap-2">
                    {professional.source_references.map((source) =>
                      source.url ? (
                        <a
                          key={`${source.name}-${source.url}`}
                          href={source.url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1.5 rounded-full border border-zinc-200 px-3 py-1.5 text-[11px] text-teal-800 transition-colors duration-200 hover:border-teal-300 hover:bg-teal-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-700"
                        >
                          {source.name}
                          <ArrowRight size={12} />
                        </a>
                      ) : (
                        <span
                          key={source.name}
                          className="rounded-full border border-zinc-200 px-3 py-1.5 text-[11px] text-zinc-600"
                        >
                          {source.name}
                        </span>
                      ),
                    )}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <ProfilePreviewMetric
                    label="Claims observed"
                    value={profile.claim_count.toLocaleString()}
                  />
                  <ProfilePreviewMetric
                    label="ATT&CK techniques"
                    value={professional.technique_count.toLocaleString()}
                  />
                  <ProfilePreviewMetric
                    label="First observed"
                    value={formatTime(profile.first_observed_at)}
                    compact
                  />
                  <ProfilePreviewMetric
                    label="Latest observed"
                    value={formatTime(profile.last_observed_at)}
                    compact
                  />
                </div>
              </section>

              <details className="group rounded-2xl border border-zinc-200 bg-white p-5">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-4 text-sm text-zinc-700">
                  <span>
                    Local observation layer · unverified victim-list claims
                  </span>
                  <CaretDown
                    size={17}
                    className="shrink-0 transition group-open:rotate-180"
                  />
                </summary>
                <div className="mt-4 grid gap-5 border-t border-zinc-100 pt-4 sm:grid-cols-2">
                  <ProfileList
                    title="Observed industries"
                    items={profile.top_industries}
                  />
                  <ProfileList
                    title="Observed geographies"
                    items={profile.top_countries}
                  />
                </div>
                <p className="mt-4 text-[11px] leading-5 text-zinc-500">
                  {profile.caveat}
                </p>
              </details>

              <InlineNotice tone="neutral">
                Actor CTI describes the retained identity and known reporting;
                it does not confirm this specific victim claim or attribution.
              </InlineNotice>
            </>
          ) : (
            <InlineNotice tone="danger">
              No professional profile is available for this actor label.
            </InlineNotice>
          )}
        </div>
      </motion.section>
    </motion.div>
  );
}

function ProfilePreviewMetric({
  label,
  value,
  compact = false,
}: {
  label: string;
  value: string;
  compact?: boolean;
}) {
  return (
    <div className="rounded-xl bg-zinc-50 p-3">
      <p className="text-[9px] font-medium uppercase tracking-wide text-zinc-400">
        {label}
      </p>
      <p
        className={`mt-1.5 text-zinc-700 ${compact ? "font-mono text-[10px] leading-4" : "font-mono text-sm"}`}
      >
        {value}
      </p>
    </div>
  );
}

function ClaimDetailModal({
  claim,
  enriching,
  drafting,
  error,
  onEnrich,
  onDraft,
  onClose,
}: {
  claim: Claim;
  enriching: boolean;
  drafting: boolean;
  error: string;
  onEnrich: () => void;
  onDraft: () => void;
  onClose: () => void;
}) {
  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [onClose]);
  const industry = claim.industry || claim.ai_industry;
  const geography = claim.country || claim.ai_country;
  return (
    <motion.div
      className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-zinc-950/40 p-4 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.section
        role="dialog"
        aria-modal="true"
        aria-label={`${claim.title} claim details`}
        className="my-6 max-h-[calc(100dvh-3rem)] w-full max-w-4xl overflow-y-auto rounded-[2rem] bg-white shadow-2xl"
        initial={{ opacity: 0, y: 24, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 16, scale: 0.98 }}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-zinc-200 bg-white/95 px-5 py-4 backdrop-blur">
          <div>
            <p className="eyebrow">Claim intelligence</p>
            <p className="mt-1 text-sm text-zinc-500">
              Evidence and enrichment record
            </p>
          </div>
          <button
            type="button"
            aria-label="Close details"
            onClick={onClose}
            className="grid h-10 w-10 place-items-center rounded-xl border border-zinc-200 hover:bg-zinc-50"
          >
            <X size={18} />
          </button>
        </div>
        <div className="space-y-6 p-5 sm:p-7">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <ClaimStatus value={claim.publication_status} />
              <span className="rounded-full bg-zinc-100 px-3 py-1 text-xs font-semibold text-zinc-600">
                Unverified allegation
              </span>
              {claim.source_tags.map((tag) => (
                <span
                  key={tag}
                  className="rounded-full bg-amber-50 px-3 py-1 text-xs text-amber-800"
                >
                  {tag}
                </span>
              ))}
            </div>
            <h2 className="mt-4 text-2xl font-semibold tracking-tight">
              {claim.title}
            </h2>
            <p className="mt-2 text-sm text-zinc-500">
              Claim by {claim.threat_actor}
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <DetailMetric
              label="Published"
              value={
                claim.published_at
                  ? formatTime(claim.published_at)
                  : "Not supplied"
              }
            />
            <DetailMetric
              label="Ingested"
              value={formatTime(claim.received_at)}
            />
            <DetailMetric
              label="Geography"
              value={geography || "Not established"}
              ai={!claim.country && !!claim.ai_country}
            />
            <DetailMetric
              label="Industry"
              value={industry || "Not established"}
              ai={!claim.industry && !!claim.ai_industry}
            />
            <DetailMetric
              label="Est. attack date"
              value={
                claim.attack_date
                  ? formatTime(claim.attack_date)
                  : "Not supplied"
              }
            />
            <DetailMetric
              label="Data exfiltrated"
              value={
                claim.leak_size
                  ? `${claim.leak_size} · source-reported`
                  : "Not reported"
              }
            />
          </div>
          <section className="rounded-2xl bg-zinc-50 p-5">
            <p className="text-xs font-bold uppercase tracking-wide text-zinc-400">
              Organization nature
            </p>
            <p className="mt-3 text-sm leading-7 text-zinc-700">
              {claim.ai_description ||
                claim.description ||
                "No reliable company description has been established yet."}
            </p>
            {claim.ai_organization_type && (
              <p className="mt-3 text-xs font-semibold text-zinc-500">
                {claim.ai_organization_type}
              </p>
            )}
          </section>
          <section className="rounded-2xl border border-violet-200 bg-violet-50/50 p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-xs font-bold uppercase tracking-wide text-violet-700">
                  AI assistance
                </p>
                <p className="mt-2 text-xs leading-5 text-zinc-500">
                  Run evidence-bounded public research or create a
                  four-paragraph internal awareness email.
                </p>
              </div>
              {claim.ai_confidence !== null && (
                <span className="rounded-full bg-white px-2.5 py-1 font-mono text-xs font-semibold text-violet-800">
                  {claim.ai_confidence}%
                </span>
              )}
            </div>
            {claim.ai_rationale && (
              <p className="mt-4 text-sm leading-6 text-zinc-700">
                {claim.ai_rationale}
              </p>
            )}
            {claim.ai_sources.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-2">
                {claim.ai_sources.map((source, index) => (
                  <a
                    key={source}
                    href={source}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded-full border border-violet-200 bg-white px-3 py-1.5 text-[11px] text-violet-800 hover:border-violet-400"
                  >
                    Evidence source {index + 1}
                  </a>
                ))}
              </div>
            )}
            <div className="mt-5 flex flex-wrap gap-3">
              <button
                type="button"
                disabled={enriching || drafting}
                onClick={onEnrich}
                className="button-primary !bg-violet-700 hover:!bg-violet-800"
              >
                {enriching ? (
                  <SpinnerGap className="animate-spin" size={18} />
                ) : (
                  <Cpu size={18} />
                )}
                {enriching
                  ? "Researching evidence…"
                  : claim.ai_enriched_at
                    ? "Refresh AI research"
                    : "Run AI research"}
              </button>
              <button
                type="button"
                disabled={enriching || drafting}
                onClick={onDraft}
                className="button-secondary !border-violet-200 text-violet-800"
              >
                {drafting ? (
                  <SpinnerGap className="animate-spin" size={18} />
                ) : (
                  <EnvelopeSimple size={18} />
                )}
                {drafting ? "Queueing draft…" : "Draft awareness email"}
              </button>
            </div>
            {error && <InlineNotice tone="danger">{error}</InlineNotice>}
            {claim.ai_enriched_at && (
              <p className="mt-3 font-mono text-[10px] text-zinc-400">
                Last enriched {formatTime(claim.ai_enriched_at)} ·{" "}
                {claim.ai_provider}
              </p>
            )}
          </section>
          <section>
            <div className="flex items-end justify-between gap-3">
              <div>
                <p className="text-xs font-bold uppercase tracking-wide text-zinc-400">
                  Past incident evidence
                </p>
                <h3 className="mt-2 text-lg font-semibold">
                  Previous observations and OSINT
                </h3>
              </div>
              {claim.ai_osint_checked_at && (
                <span className="font-mono text-[10px] text-zinc-400">
                  Checked {formatTime(claim.ai_osint_checked_at)}
                </span>
              )}
            </div>
            <div className="mt-4 space-y-3">
              {claim.ai_past_incidents.length ? (
                claim.ai_past_incidents.map((incident, index) => (
                  <div
                    key={`${incident.source_url}-${incident.published_at}-${index}`}
                    className="rounded-2xl border border-zinc-200 p-4"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-full bg-zinc-100 px-2 py-1 text-[10px] font-bold uppercase text-zinc-600">
                        {incident.evidence_type === "local_claim"
                          ? "Prior local claim"
                          : "News report"}
                      </span>
                      <span className="font-mono text-[10px] text-zinc-400">
                        {formatTime(incident.published_at)}
                      </span>
                    </div>
                    <p className="mt-3 text-sm leading-6 text-zinc-700">
                      {incident.summary}
                    </p>
                    {incident.source_url && (
                      <a
                        href={incident.source_url}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-3 inline-flex text-xs font-semibold text-teal-800 underline underline-offset-2"
                      >
                        Open supporting source
                      </a>
                    )}
                  </div>
                ))
              ) : (
                <div className="rounded-2xl border border-dashed border-zinc-200 p-5 text-sm leading-6 text-zinc-500">
                  {claim.ai_osint_checked_at
                    ? "No sufficiently supported past incident was returned by the bounded search. This does not prove that no prior incident exists."
                    : "Run AI research to check previous local claims and bounded public-news candidates."}
                </div>
              )}
            </div>
          </section>
          <section className="rounded-2xl border border-zinc-200 p-5">
            <p className="text-xs font-bold uppercase tracking-wide text-zinc-400">
              Source evidence
            </p>
            <p className="mt-3 text-sm leading-6 text-zinc-700">
              {claim.description || "No source description supplied."}
            </p>
            <div className="mt-4 flex flex-wrap gap-3">
              {claim.source_url && (
                <a
                  href={claim.source_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs font-semibold text-teal-800 underline underline-offset-2"
                >
                  Open claim source
                </a>
              )}
              {claim.source_screenshot_url && (
                <a
                  href={claim.source_screenshot_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs font-semibold text-teal-800 underline underline-offset-2"
                >
                  Open source screenshot
                </a>
              )}
              {claim.ai_sources.map((url, index) => (
                <a
                  key={url}
                  href={url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs font-semibold text-violet-800 underline underline-offset-2"
                >
                  Enrichment source {index + 1}
                </a>
              ))}
            </div>
          </section>
          <InlineNotice tone="neutral">
            A listing or news report is not independent confirmation of
            compromise. Review the supporting source and validate identity
            before escalation.
          </InlineNotice>
        </div>
      </motion.section>
    </motion.div>
  );
}

function DetailMetric({
  label,
  value,
  ai = false,
}: {
  label: string;
  value: string;
  ai?: boolean;
}) {
  return (
    <div className="rounded-2xl border border-zinc-200 p-4">
      <p className="text-[10px] font-bold uppercase tracking-wide text-zinc-400">
        {label}
        {ai && <span className="ml-1 text-violet-700">· AI</span>}
      </p>
      <p className="mt-2 text-sm font-semibold leading-5 text-zinc-700">
        {value}
      </p>
    </div>
  );
}

function ActorProfileMetric({
  actor,
  onOpen,
}: {
  actor: string;
  onOpen: () => void;
}) {
  return (
    <div className="rounded-2xl border border-violet-200 bg-violet-50/30 p-4">
      <p className="text-[10px] font-medium uppercase tracking-wide text-violet-700">
        Threat actor
      </p>
      <button
        type="button"
        onClick={onOpen}
        className="group mt-2 flex w-full cursor-pointer items-center justify-between gap-3 rounded-xl text-left text-sm font-medium leading-5 text-zinc-800 transition-colors duration-200 hover:text-violet-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-700 focus-visible:ring-offset-4 focus-visible:ring-offset-violet-50"
        aria-label={`Preview professional threat-actor profile for ${actor}`}
      >
        <span>{actor}</span>
        <span className="inline-flex shrink-0 items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-violet-700">
          Profile
          <ArrowRight
            size={14}
            className="transition-transform duration-200 group-hover:translate-x-0.5"
          />
        </span>
      </button>
    </div>
  );
}

function SourcesPage({
  sources,
  onUpdated,
}: {
  sources: SourceHealth[];
  onUpdated: () => Promise<void>;
}) {
  const [collecting, setCollecting] = useState(false);
  const [backfilling, setBackfilling] = useState(false);
  const [notice, setNotice] = useState("");
  const [sourceError, setSourceError] = useState("");
  const collect = async () => {
    setCollecting(true);
    setSourceError("");
    setNotice("");
    try {
      await api.collect();
      await onUpdated();
      setNotice(
        "Source test finished. The status cards below now show the latest result from each provider.",
      );
    } catch (reason) {
      setSourceError(
        reason instanceof Error ? reason.message : "Source check failed",
      );
    } finally {
      setCollecting(false);
    }
  };
  const backfill = async () => {
    setBackfilling(true);
    setSourceError("");
    setNotice("");
    try {
      const result = await api.backfill(2015);
      const incomplete = result.results.filter(
        (item) => item.error || item.truncated_partitions?.length,
      );
      setNotice(
        `Checked ${result.received.toLocaleString()} source records and stored ${result.created.toLocaleString()} new claims.${incomplete.length ? ` ${incomplete.length} source${incomplete.length === 1 ? " has" : "s have"} an upstream coverage limitation; see its status card.` : " All addressable partitions completed."}`,
      );
      await onUpdated();
    } catch (reason) {
      setSourceError(
        reason instanceof Error ? reason.message : "Historical import failed",
      );
    } finally {
      setBackfilling(false);
    }
  };
  const busy = collecting || backfilling;
  return (
    <div>
      <div className="flex flex-col justify-between gap-5 2xl:flex-row 2xl:items-end">
        <PageIntro
          eyebrow="Collection status"
          title="Sources"
          description="Check whether public data providers are reachable and returning current records."
        />
        <div className="grid w-full gap-3 sm:grid-cols-2 2xl:w-auto">
          <button
            type="button"
            className="button-secondary w-full whitespace-nowrap 2xl:min-w-[250px]"
            disabled={busy}
            aria-busy={backfilling}
            onClick={() => void backfill()}
          >
            {backfilling ? (
              <SpinnerGap className="animate-spin" size={18} />
            ) : (
              <ClockCounterClockwise size={18} />
            )}
            {backfilling
              ? "Synchronizing history…"
              : "Synchronize all available"}
          </button>
          <button
            type="button"
            className="button-primary w-full whitespace-nowrap 2xl:min-w-[220px]"
            disabled={busy}
            aria-busy={collecting}
            onClick={() => void collect()}
          >
            {collecting ? (
              <SpinnerGap className="animate-spin" size={18} />
            ) : (
              <GlobeHemisphereWest size={18} />
            )}
            {collecting ? "Testing sources…" : "Test active sources"}
          </button>
        </div>
      </div>
      {notice && <InlineNotice tone="neutral">{notice}</InlineNotice>}
      {sourceError && <InlineNotice tone="danger">{sourceError}</InlineNotice>}
      <div className="mt-8 grid gap-5 lg:grid-cols-2">
        {sources.map((source) => (
          <motion.div
            layout
            key={source.source}
            className="rounded-[2rem] border border-zinc-200 bg-white p-6 transition-shadow duration-300 md:p-8"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <StatusPulse
                  tone={
                    source.status === "working"
                      ? "healthy"
                      : source.status === "unavailable"
                        ? "danger"
                        : "warning"
                  }
                />
                <div>
                  <h2 className="text-xl font-semibold">
                    {sourceLabel(source.source)}
                  </h2>
                  <p className="mt-1 text-sm text-zinc-500">{source.message}</p>
                </div>
              </div>
              <StatusBadge status={source.status} />
            </div>
            <dl className="mt-8 grid grid-cols-2 gap-5 border-t border-zinc-100 pt-6 xl:grid-cols-4">
              <Stat
                label="Last checked"
                value={formatTime(source.last_checked_at)}
              />
              <Stat
                label="Canonical claims represented"
                value={source.observations_stored.toLocaleString()}
                mono
              />
              <Stat
                label="Oldest retained"
                value={formatTime(source.oldest_observation_at)}
              />
              <Stat
                label="Newest retained"
                value={formatTime(source.newest_observation_at)}
              />
            </dl>
            <div className="mt-5 rounded-2xl bg-zinc-50 px-4 py-3 text-sm text-zinc-600">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span>Historical coverage</span>
                <span className="font-mono text-xs uppercase tracking-wide text-zinc-500">
                  {source.coverage_status.replace("_", " ")}
                </span>
              </div>
              <p className="mt-2 leading-6">
                {source.coverage_message || "Run a full synchronization to audit historical coverage."}
              </p>
              {source.coverage_gaps.length > 0 && (
                <details className="mt-2">
                  <summary className="cursor-pointer text-zinc-700">
                    Review {source.coverage_gaps.length} incomplete partition{source.coverage_gaps.length === 1 ? "" : "s"}
                  </summary>
                  <p className="mt-2 break-words font-mono text-xs leading-5 text-zinc-500">
                    {source.coverage_gaps.join(", ")}
                  </p>
                </details>
              )}
            </div>
          </motion.div>
        ))}
      </div>
      <InlineNotice tone="neutral">
        Full synchronization imports RansomLook history through bounded yearly
        partitions, reconciles RansomFeed's public full-dataset export against
        its live aggregate total, and exhausts ransomware.live's
        documented monthly archive through the current month. Any failed or
        capped partition is reported as partial coverage on its source card.
        Routine monitoring continues to use recent feeds for prompt detection.
        Direct-site addresses remain restricted to the separately configured
        Kali capture worker.
      </InlineNotice>
    </div>
  );
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
  const [aiTestResult, setAITestResult] = useState<AIConnectionTest | null>(
    null,
  );
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
      .catch((reason) =>
        setError(
          reason instanceof Error
            ? reason.message
            : "Settings could not be loaded",
        ),
      );
  }, []);

  if (!runtime || !form)
    return (
      <div>
        <PageIntro
          eyebrow="Application"
          title="Settings"
          description="Loading operational controls…"
        />
        <LoadingStatusCard
          title="Loading operational controls"
          description="Retrieving local monitoring, AI, and notification settings."
          className="mt-8 max-w-xl"
        />
        <div className="mt-5 h-72 animate-pulse rounded-[2rem] bg-zinc-200" />
      </div>
    );
  const selectedProvider = providers.find(
    (provider) => provider.id === form.ai_provider,
  );
  const chooseProvider = (providerId: string) => {
    const provider = providers.find((item) => item.id === providerId);
    setApiKey("");
    setAITestResult(null);
    setAITestError("");
    setForm({
      ...form,
      ai_provider: providerId,
      ai_model: provider?.models[0] || "",
      ai_base_url: provider?.base_url || "",
    });
  };
  const replaceProvider = (updated: AIProvider) => {
    setProviders((current) =>
      current.map((provider) =>
        provider.id === updated.id ? updated : provider,
      ),
    );
  };
  const saveCredential = async () => {
    if (!selectedProvider?.api_key_env || !apiKey.trim()) return;
    setSavingCredential(true);
    setError("");
    setNotice("");
    try {
      const updated = await api.saveAIProviderCredential(
        selectedProvider.id,
        apiKey.trim(),
      );
      replaceProvider(updated);
      setApiKey("");
      setNotice(
        `${selectedProvider.name} API key saved locally. It is ready for connection tests and enrichment.`,
      );
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "API key could not be saved",
      );
    } finally {
      setSavingCredential(false);
    }
  };
  const clearCredential = async () => {
    if (!selectedProvider?.api_key_env) return;
    setSavingCredential(true);
    setError("");
    setNotice("");
    try {
      const updated = await api.clearAIProviderCredential(selectedProvider.id);
      replaceProvider(updated);
      setApiKey("");
      setNotice(`${selectedProvider.name} locally saved API key was removed.`);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "API key could not be removed",
      );
    } finally {
      setSavingCredential(false);
    }
  };
  const save = async () => {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const updated = await api.updateRuntimeSettings(form);
      setRuntime(updated);
      setForm(updated);
      setNotice(
        "Monitoring settings saved. The scheduler will use them on its next check.",
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Settings could not be saved",
      );
    } finally {
      setSaving(false);
    }
  };
  const testAI = async () => {
    setTestingAI(true);
    setError("");
    setNotice("");
    setAITestError("");
    setAITestResult(null);
    try {
      if (selectedProvider?.api_key_env && apiKey.trim()) {
        const updatedProvider = await api.saveAIProviderCredential(
          selectedProvider.id,
          apiKey.trim(),
        );
        replaceProvider(updatedProvider);
        setApiKey("");
      }
      const updatedSettings = await api.updateRuntimeSettings(form);
      setRuntime(updatedSettings);
      setForm(updatedSettings);
      await api.queueAIJob("provider_test");
      setNotice(
        "Provider verification queued. Continue browsing; connection checks will appear in the AI task center.",
      );
    } catch (reason) {
      const message =
        reason instanceof Error ? reason.message : "AI connection failed";
      setAITestError(message);
      setError(message);
    } finally {
      setTestingAI(false);
    }
  };
  const saveSMTPPassword = async () => {
    if (!smtpPassword) return;
    setSavingSMTP(true);
    setError("");
    setNotice("");
    try {
      await api.saveSMTPPassword(smtpPassword);
      setSMTPPassword("");
      setRuntime({ ...runtime, smtp_password_configured: true });
      setNotice("SMTP password saved locally.");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "SMTP password could not be saved",
      );
    } finally {
      setSavingSMTP(false);
    }
  };
  const clearSMTPPassword = async () => {
    setSavingSMTP(true);
    setError("");
    setNotice("");
    try {
      await api.clearSMTPPassword();
      setRuntime({ ...runtime, smtp_password_configured: false });
      setSMTPPassword("");
      setNotice("Locally saved SMTP password removed.");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "SMTP password could not be removed",
      );
    } finally {
      setSavingSMTP(false);
    }
  };
  const sendDigest = async () => {
    setSendingDigest(true);
    setError("");
    setNotice("");
    try {
      if (smtpPassword) {
        await api.saveSMTPPassword(smtpPassword);
        setSMTPPassword("");
        setRuntime({ ...runtime, smtp_password_configured: true });
      }
      const updated = await api.updateRuntimeSettings(form);
      setRuntime(updated);
      setForm(updated);
      await api.queueAIJob("victim_digest");
      setNotice(
        "Victim digest queued. Continue browsing; delivery status will appear in the AI task center.",
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Victim digest could not be sent",
      );
    } finally {
      setSendingDigest(false);
    }
  };
  const modes: { id: OperatingMode; title: string; description: string }[] = [
    {
      id: "off",
      title: "Off",
      description:
        "Pause all scheduled collection. Manual source checks still work.",
    },
    {
      id: "passive",
      title: "Passive",
      description:
        "Poll public feeds and match client profiles. No actor-site visits.",
    },
    {
      id: "active",
      title: "Active",
      description:
        "Also queue allowlisted captures for the isolated Kali worker.",
    },
  ];
  return (
    <div>
      <PageIntro
        eyebrow="Application"
        title="Monitoring settings"
        description="Choose how ExtortSignal collects signals, when it runs, and whether an AI model assists enrichment."
      />
      {notice && <InlineNotice tone="neutral">{notice}</InlineNotice>}
      {error && <InlineNotice tone="danger">{error}</InlineNotice>}
      <section className="mt-8 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="eyebrow">Collection mode</p>
            <h3 className="mt-2 text-xl font-semibold">
              Control the network boundary
            </h3>
          </div>
          <span
            className={`rounded-full px-3 py-1 text-xs font-bold uppercase ${form.operating_mode === "active" ? "bg-amber-100 text-amber-800" : form.operating_mode === "passive" ? "bg-teal-50 text-teal-800" : "bg-zinc-100 text-zinc-600"}`}
          >
            {form.operating_mode}
          </span>
        </div>
        <div className="mt-6 grid gap-3 lg:grid-cols-3">
          {modes.map((mode) => (
            <button
              key={mode.id}
              type="button"
              onClick={() => setForm({ ...form, operating_mode: mode.id })}
              className={`rounded-2xl border p-5 text-left transition ${form.operating_mode === mode.id ? "border-teal-700 bg-teal-50 ring-4 ring-teal-700/10" : "border-zinc-200 hover:border-zinc-400"}`}
            >
              <span className="flex items-center justify-between font-semibold">
                {mode.title}
                {form.operating_mode === mode.id && (
                  <Check size={18} className="text-teal-800" />
                )}
              </span>
              <span className="mt-2 block text-xs leading-5 text-zinc-600">
                {mode.description}
              </span>
            </button>
          ))}
        </div>
        {form.operating_mode === "active" && (
          <div
            className={`mt-5 rounded-2xl p-4 text-sm ${runtime.worker_online ? "bg-teal-50 text-teal-900" : "bg-amber-50 text-amber-900"}`}
          >
            <strong>
              {runtime.worker_online
                ? "Separate Kali capture worker online."
                : runtime.worker_configured
                  ? "Capture worker configured but offline."
                  : "Kali worker not configured."}
            </strong>{" "}
            Active mode queues only targets you enabled on Direct sites. Passive
            and Off modes are enforced when the worker reserves each job.
          </div>
        )}
      </section>

      <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="eyebrow">Scheduler</p>
            <h3 className="mt-2 text-xl font-semibold">Automatic checks</h3>
            <p className="mt-2 text-sm text-zinc-500">
              Intervals are applied without restarting the platform.
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={form.scheduling_enabled}
            onClick={() =>
              setForm({ ...form, scheduling_enabled: !form.scheduling_enabled })
            }
            className={`relative h-7 w-12 rounded-full transition ${form.scheduling_enabled ? "bg-teal-700" : "bg-zinc-300"}`}
          >
            <span
              className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition ${form.scheduling_enabled ? "left-6" : "left-1"}`}
            />
          </button>
        </div>
        <div className="mt-6 grid gap-5 md:grid-cols-3">
          <Field
            label="Public feeds"
            helper={`Last run: ${formatTime(runtime.last_public_run_at)}`}
          >
            <CustomSelect
              ariaLabel="Public feed interval"
              value={String(form.public_interval_minutes)}
              onChange={(value) =>
                setForm({ ...form, public_interval_minutes: Number(value) })
              }
              options={[
                { value: "1", label: "Every minute" },
                { value: "2", label: "Every 2 minutes" },
                { value: "5", label: "Every 5 minutes" },
                { value: "15", label: "Every 15 minutes" },
                { value: "60", label: "Hourly" },
              ]}
            />
          </Field>
          <Field
            label="Site catalog"
            helper={`Last run: ${formatTime(runtime.last_catalog_run_at)}`}
          >
            <CustomSelect
              ariaLabel="Site catalog interval"
              value={String(form.catalog_interval_hours)}
              onChange={(value) =>
                setForm({ ...form, catalog_interval_hours: Number(value) })
              }
              options={[
                { value: "1", label: "Hourly" },
                { value: "3", label: "Every 3 hours" },
                { value: "6", label: "Every 6 hours" },
                { value: "12", label: "Every 12 hours" },
                { value: "24", label: "Daily" },
              ]}
            />
          </Field>
          <Field
            label="Active captures"
            helper={`Last run: ${formatTime(runtime.last_active_run_at)}`}
          >
            <CustomSelect
              ariaLabel="Active capture interval"
              value={String(form.active_interval_minutes)}
              onChange={(value) =>
                setForm({ ...form, active_interval_minutes: Number(value) })
              }
              options={[
                { value: "5", label: "Every 5 minutes" },
                { value: "15", label: "Every 15 minutes" },
                { value: "30", label: "Every 30 minutes" },
                { value: "60", label: "Hourly" },
                { value: "360", label: "Every 6 hours" },
              ]}
            />
          </Field>
        </div>
        {!runtime.scheduler_process_enabled && (
          <InlineNotice tone="danger">
            The scheduler process is disabled by RANSOM_MONITOR_AUTO_COLLECT.
            Enable it and restart before schedules can run.
          </InlineNotice>
        )}
      </section>

      <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
        <p className="eyebrow">Geographic priorities</p>
        <h3 className="mt-2 text-xl font-semibold">Regions to focus</h3>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-500">
          These global priorities drive Intelligence highlighting, the Activity
          focus-region filter, the Home daily-victim list, and regional emphasis
          in email digests. Client-profile markets and cities remain additional
          matching signals.
        </p>
        <div className="mt-6">
          <FocusRegionEditor
            values={form.focus_regions}
            onChange={(focus_regions) => setForm({ ...form, focus_regions })}
          />
        </div>
      </section>

      <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="grid h-11 w-11 place-items-center rounded-xl bg-violet-50 text-violet-700">
              <Cpu size={23} />
            </span>
            <div>
              <p className="eyebrow">Optional enrichment</p>
              <h3 className="mt-1 text-xl font-semibold">AI provider</h3>
            </div>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={form.ai_enabled}
            onClick={() => setForm({ ...form, ai_enabled: !form.ai_enabled })}
            className={`relative h-7 w-12 rounded-full transition ${form.ai_enabled ? "bg-violet-700" : "bg-zinc-300"}`}
          >
            <span
              className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition ${form.ai_enabled ? "left-6" : "left-1"}`}
            />
          </button>
        </div>
        <p className="mt-4 max-w-3xl text-sm leading-6 text-zinc-600">
          AI is used only as an enrichment assistant; deterministic
          company/domain matching remains authoritative. For an 8–16 GB machine,
          start with Qwen3 4B. Use Qwen3 1.7B when memory is tight, or Qwen3 8B
          for better extraction on a larger system.
        </p>
        <div className="mt-6 grid gap-5 md:grid-cols-3">
          <Field label="Provider">
            <CustomSelect
              ariaLabel="AI provider"
              value={form.ai_provider}
              onChange={chooseProvider}
              options={providers.map((provider) => ({
                value: provider.id,
                label: provider.name,
              }))}
            />
          </Field>
          <Field label="Model">
            {selectedProvider?.models.length ? (
              <CustomSelect
                ariaLabel="AI model"
                value={form.ai_model}
                onChange={(value) => setForm({ ...form, ai_model: value })}
                options={selectedProvider.models.map((model) => ({
                  value: model,
                  label: model,
                }))}
              />
            ) : (
              <input
                className="input"
                value={form.ai_model}
                onChange={(event) =>
                  setForm({ ...form, ai_model: event.target.value })
                }
                placeholder="Provider model ID"
              />
            )}
          </Field>
          <Field label="OpenAI-compatible endpoint">
            <input
              className="input font-mono text-xs"
              value={form.ai_base_url}
              onChange={(event) =>
                setForm({ ...form, ai_base_url: event.target.value })
              }
            />
          </Field>
        </div>
        {selectedProvider?.api_key_env && (
          <div className="mt-5 rounded-2xl border border-violet-100 bg-violet-50/50 p-4 sm:p-5">
            <div className="grid gap-3 lg:grid-cols-[1fr_auto]">
              <Field
                label="API key"
                helper={
                  selectedProvider.credential_configured
                    ? "A credential is configured. Enter a new key only to replace it."
                    : `Required for ${selectedProvider.name}.`
                }
              >
                <input
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={apiKey}
                  onChange={(event) => setApiKey(event.target.value)}
                  className="input font-mono text-sm"
                  placeholder={
                    selectedProvider.credential_configured
                      ? "Saved key ••••••••"
                      : `Paste ${selectedProvider.api_key_env}`
                  }
                  aria-label={`${selectedProvider.name} API key`}
                />
              </Field>
              <div className="flex items-end gap-2">
                <button
                  type="button"
                  disabled={savingCredential || apiKey.trim().length < 8}
                  onClick={() => void saveCredential()}
                  className="button-primary whitespace-nowrap"
                >
                  {savingCredential ? (
                    <SpinnerGap className="animate-spin" size={17} />
                  ) : (
                    <ShieldCheck size={17} />
                  )}
                  Save API key
                </button>
                {selectedProvider.credential_source === "local_store" && (
                  <button
                    type="button"
                    disabled={savingCredential}
                    onClick={() => void clearCredential()}
                    className="button-secondary"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
            <p className="mt-3 text-xs leading-5 text-zinc-500">
              Stored only on this machine in a user-restricted file. The key is
              never sent back to the browser or included in exports. “Test
              connection” also saves a key currently entered above.
            </p>
          </div>
        )}
        {selectedProvider && (
          <div className="mt-4 flex flex-col justify-between gap-3 rounded-2xl bg-zinc-50 p-4 sm:flex-row sm:items-center">
            <div>
              <p className="text-sm font-semibold">{selectedProvider.region}</p>
              <p className="mt-1 text-xs leading-5 text-zinc-500">
                {selectedProvider.note}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`shrink-0 rounded-full px-3 py-1 text-xs font-semibold ${selectedProvider.credential_configured ? "bg-teal-50 text-teal-800" : "bg-amber-100 text-amber-800"}`}
              >
                {selectedProvider.api_key_env
                  ? selectedProvider.credential_source === "environment"
                    ? "Key from environment"
                    : selectedProvider.credential_configured
                      ? "API key saved"
                      : "API key required"
                  : "No API key needed"}
              </span>
              <button
                type="button"
                disabled={testingAI || savingCredential}
                onClick={() => void testAI()}
                className="button-secondary !min-h-9 px-3 text-xs"
              >
                {testingAI ? (
                  <SpinnerGap className="animate-spin" size={15} />
                ) : null}
                Test connection
              </button>
            </div>
          </div>
        )}
        {aiTestResult && (
          <div className="mt-3 rounded-2xl border border-teal-200 bg-teal-50 p-4 sm:p-5">
            <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
              <div className="flex items-start gap-3">
                <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-full bg-teal-700 text-white">
                  <Check size={17} />
                </span>
                <div>
                  <p className="text-sm font-semibold text-teal-950">
                    Live connection verified
                  </p>
                  <p className="mt-1 text-xs leading-5 text-teal-800">
                    A random challenge was returned correctly by{" "}
                    {aiTestResult.provider}; this was a real inference request.
                  </p>
                </div>
              </div>
              <span className="shrink-0 rounded-full bg-white px-3 py-1 font-mono text-xs font-semibold text-teal-800">
                {aiTestResult.latency_ms.toLocaleString()} ms
              </span>
            </div>
            <div className="mt-4 grid gap-2 sm:grid-cols-3">
              {aiTestResult.checks.map((check, index) => (
                <div
                  key={check.id}
                  className="flex items-center gap-2 rounded-xl border border-teal-200 bg-white px-3 py-2.5"
                >
                  <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-teal-700 text-[10px] font-bold text-white">
                    {index + 1}
                  </span>
                  <span className="min-w-0 truncate text-xs font-semibold text-teal-950">
                    {check.label}
                  </span>
                  <Check className="ml-auto shrink-0 text-teal-700" size={15} />
                </div>
              ))}
            </div>
            <dl className="mt-4 grid gap-3 border-t border-teal-200/70 pt-4 text-xs sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-teal-700">Endpoint</dt>
                <dd className="mt-1 break-all font-mono font-semibold text-teal-950">
                  {aiTestResult.endpoint_host}
                </dd>
              </div>
              <div>
                <dt className="text-teal-700">Configured model</dt>
                <dd className="mt-1 break-all font-mono font-semibold text-teal-950">
                  {aiTestResult.model}
                </dd>
              </div>
              <div>
                <dt className="text-teal-700">Responding model</dt>
                <dd className="mt-1 break-all font-mono font-semibold text-teal-950">
                  {aiTestResult.upstream_model}
                </dd>
              </div>
              <div>
                <dt className="text-teal-700">Checked</dt>
                <dd className="mt-1 font-semibold text-teal-950">
                  {formatTime(aiTestResult.checked_at)}
                </dd>
              </div>
            </dl>
          </div>
        )}
        {aiTestError && (
          <div className="mt-3">
            <InlineNotice tone="danger">
              <span>
                <strong>Connection test failed.</strong> {aiTestError}
              </span>
            </InlineNotice>
          </div>
        )}
      </section>
      <section className="mt-5 rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="grid h-11 w-11 place-items-center rounded-xl bg-teal-50 text-teal-800">
              <EnvelopeSimple size={23} />
            </span>
            <div>
              <p className="eyebrow">Outbound notification</p>
              <h3 className="mt-1 text-xl font-semibold">
                New-victim email digest
              </h3>
            </div>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={form.victim_digest_enabled}
            onClick={() =>
              setForm({
                ...form,
                victim_digest_enabled: !form.victim_digest_enabled,
              })
            }
            className={`relative h-7 w-12 shrink-0 rounded-full transition ${form.victim_digest_enabled ? "bg-teal-700" : "bg-zinc-300"}`}
          >
            <span
              className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition ${form.victim_digest_enabled ? "left-6" : "left-1"}`}
            />
          </button>
        </div>
        <p className="mt-4 max-w-3xl text-sm leading-6 text-zinc-600">
          Send a victim-by-victim listing of claims received since the previous
          digest. Selected focus-region victims are counted in the subject and
          listed first with actor, geography, industry, publish date, and ingest
          date. When AI is enabled it summarizes only local aggregates;
          otherwise ExtortSignal uses a deterministic summary. The switch enables
          scheduled delivery—“Send digest now” remains manual.
        </p>
        <div className="mt-6">
          <EmailRecipientEditor
            values={form.victim_digest_recipients}
            onChange={(victim_digest_recipients) =>
              setForm({ ...form, victim_digest_recipients })
            }
          />
        </div>
        <div className="mt-6 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
          <Field label="SMTP host">
            <input
              className="input font-mono text-sm"
              value={form.smtp_host}
              onChange={(event) =>
                setForm({ ...form, smtp_host: event.target.value })
              }
              placeholder="smtp.example.com"
            />
          </Field>
          <Field label="Port">
            <input
              type="number"
              min={1}
              max={65535}
              className="input"
              value={form.smtp_port}
              onChange={(event) =>
                setForm({ ...form, smtp_port: Number(event.target.value) })
              }
            />
          </Field>
          <Field label="Security">
            <CustomSelect
              ariaLabel="SMTP security"
              value={form.smtp_security}
              onChange={(value) =>
                setForm({
                  ...form,
                  smtp_security:
                    value as RuntimeSettingsUpdate["smtp_security"],
                })
              }
              options={[
                { value: "starttls", label: "STARTTLS" },
                { value: "ssl", label: "SSL/TLS" },
              ]}
            />
          </Field>
          <Field label="Digest interval">
            <CustomSelect
              ariaLabel="Digest interval"
              value={String(form.victim_digest_interval_hours)}
              onChange={(value) =>
                setForm({
                  ...form,
                  victim_digest_interval_hours: Number(value),
                })
              }
              options={[
                { value: "1", label: "Hourly" },
                { value: "6", label: "Every 6 hours" },
                { value: "12", label: "Every 12 hours" },
                { value: "24", label: "Daily" },
                { value: "168", label: "Weekly" },
              ]}
            />
          </Field>
        </div>
        <div className="mt-5 grid gap-5 md:grid-cols-2">
          <Field label="SMTP username">
            <input
              className="input"
              value={form.smtp_username}
              onChange={(event) =>
                setForm({ ...form, smtp_username: event.target.value })
              }
              placeholder="alerts@example.com"
            />
          </Field>
          <Field label="From address">
            <input
              type="email"
              className="input"
              value={form.smtp_from}
              onChange={(event) =>
                setForm({ ...form, smtp_from: event.target.value })
              }
              placeholder="alerts@example.com"
            />
          </Field>
        </div>
        <div className="mt-5 rounded-2xl bg-zinc-50 p-4 sm:p-5">
          <div className="grid gap-3 lg:grid-cols-[1fr_auto]">
            <Field
              label="SMTP password or app password"
              helper={
                runtime.smtp_password_configured
                  ? "A password is stored locally. Enter a value only to replace it."
                  : "Use an app password when your mailbox provider supports it."
              }
            >
              <input
                type="password"
                autoComplete="off"
                value={smtpPassword}
                onChange={(event) => setSMTPPassword(event.target.value)}
                className="input font-mono text-sm"
                placeholder={
                  runtime.smtp_password_configured
                    ? "Saved password ••••••••"
                    : "Enter SMTP password"
                }
              />
            </Field>
            <div className="flex flex-wrap items-end gap-2">
              <button
                type="button"
                disabled={savingSMTP || !smtpPassword}
                onClick={() => void saveSMTPPassword()}
                className="button-secondary"
              >
                {savingSMTP ? (
                  <SpinnerGap className="animate-spin" size={17} />
                ) : (
                  <ShieldCheck size={17} />
                )}
                Save password
              </button>
              {runtime.smtp_password_configured && (
                <button
                  type="button"
                  disabled={savingSMTP}
                  onClick={() => void clearSMTPPassword()}
                  className="button-secondary"
                >
                  Clear
                </button>
              )}
            </div>
          </div>
        </div>
        <div className="mt-5 flex flex-col justify-between gap-3 rounded-2xl border border-teal-100 bg-teal-50/50 p-4 sm:flex-row sm:items-center">
          <div>
            <p className="text-sm font-semibold text-teal-950">
              Last successful digest:{" "}
              {formatTime(runtime.last_victim_digest_at)}
            </p>
            <p className="mt-1 text-xs text-teal-800">
              Email is sent only to the configured recipients and never includes
              API or SMTP credentials.
            </p>
          </div>
          <button
            type="button"
            disabled={sendingDigest || savingSMTP}
            onClick={() => void sendDigest()}
            className="button-primary shrink-0"
          >
            {sendingDigest ? (
              <SpinnerGap className="animate-spin" size={18} />
            ) : (
              <EnvelopeSimple size={18} />
            )}
            {sendingDigest ? "Sending…" : "Send digest now"}
          </button>
        </div>
      </section>
      <div className="mt-6 flex justify-end">
        <button
          type="button"
          className="button-primary"
          disabled={saving}
          onClick={() => void save()}
        >
          {saving ? (
            <SpinnerGap className="animate-spin" size={18} />
          ) : (
            <ShieldCheck size={18} />
          )}
          Save monitoring settings
        </button>
      </div>
    </div>
  );
}

function EmailRecipientEditor({
  values,
  onChange,
}: {
  values: string[];
  onChange: (values: string[]) => void;
}) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const additions = draft
      .split(/[,;\s]+/)
      .map((value) => value.trim().toLowerCase())
      .filter((value) => value.includes("@"));
    if (additions.length)
      onChange(Array.from(new Set([...values, ...additions])));
    setDraft("");
  };
  return (
    <fieldset className="rounded-2xl border border-zinc-200 bg-zinc-50/70 p-4 sm:p-5">
      <legend className="px-1 text-sm font-semibold text-zinc-800">
        Digest recipients
      </legend>
      <p className="text-xs leading-5 text-zinc-500">
        Add one or more internal monitoring addresses. Separate multiple
        addresses with commas.
      </p>
      <div className="mt-3 flex gap-2">
        <input
          type="email"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              add();
            }
          }}
          className="input"
          placeholder="soc@example.com"
        />
        <button
          type="button"
          onClick={add}
          disabled={!draft.includes("@")}
          className="button-secondary shrink-0"
        >
          Add
        </button>
      </div>
      <div className="mt-3 flex min-h-7 flex-wrap gap-2">
        {values.length ? (
          values.map((value) => (
            <span
              key={value}
              className="inline-flex items-center gap-1 rounded-full bg-teal-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-teal-900"
            >
              {value}
              <button
                type="button"
                onClick={() =>
                  onChange(values.filter((item) => item !== value))
                }
                className="grid h-6 w-6 place-items-center rounded-full hover:bg-teal-100"
                aria-label={`Remove recipient ${value}`}
              >
                <X size={13} />
              </button>
            </span>
          ))
        ) : (
          <span className="text-xs text-zinc-400">
            No digest recipients configured
          </span>
        )}
      </div>
    </fieldset>
  );
}

function Onboarding({
  onComplete,
}: {
  onComplete: (destination?: Page) => void;
}) {
  const [step, setStep] = useState(1);
  return (
    <div className="min-h-[100dvh] bg-[#f5f7f6] p-4 sm:p-7">
      <div className="mx-auto grid min-h-[calc(100dvh-2rem)] max-w-[1400px] overflow-hidden rounded-[2.5rem] border border-zinc-200 bg-white shadow-[0_30px_75px_-45px_rgba(24,24,27,0.35)] lg:grid-cols-[.85fr_1.15fr]">
        <aside className="relative overflow-hidden bg-zinc-900 p-7 text-white sm:p-10 lg:p-14">
          <div className="flex items-center gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-xl bg-white p-1.5">
              <img
                src="/extortsignal-mark.svg"
                alt=""
                className="h-full w-full"
              />
            </div>
            <div>
              <p className="font-semibold tracking-[-0.02em]">ExtortSignal</p>
              <p className="text-xs text-zinc-400">
                Early signal. Clear action.
              </p>
            </div>
          </div>
          <div className="mt-20 max-w-md">
            <p className="eyebrow !text-teal-300">Learn the workflow</p>
            <h1 className="mt-5 text-4xl font-semibold tracking-[-0.045em] sm:text-5xl">
              Turn public claims into reviewable intelligence.
            </h1>
            <p className="mt-6 text-base leading-7 text-zinc-400">
              Take a short tour of the workspaces, safety boundaries, and daily
              analyst flow. You can add a client later, when you are ready to
              tailor monitoring.
            </p>
          </div>
          <div className="mt-12 space-y-4">
            {[
              "Public-source monitoring works without a client",
              "Direct-site access stays optional and isolated",
              "Claims remain allegations until verified",
            ].map((item) => (
              <div
                key={item}
                className="flex items-center gap-3 text-sm text-zinc-300"
              >
                <CheckCircle size={20} className="text-teal-400" />
                {item}
              </div>
            ))}
          </div>
        </aside>
        <main className="flex items-center p-6 sm:p-10 lg:p-14">
          <div className="w-full max-w-3xl">
            <div className="flex items-center justify-between gap-6">
              <div className="flex flex-1 items-center gap-2">
                {[1, 2, 3].map((number) => (
                  <div
                    key={number}
                    className={`h-1.5 flex-1 rounded-full transition-colors ${number <= step ? "bg-teal-700" : "bg-zinc-200"}`}
                  />
                ))}
              </div>
              <button
                type="button"
                onClick={() => onComplete("home")}
                className="shrink-0 text-sm font-medium text-zinc-500 underline-offset-4 hover:text-zinc-900 hover:underline"
              >
                Skip tour
              </button>
            </div>
            {step === 1 && (
              <div className="mt-10">
                <p className="eyebrow">Step 1 of 3</p>
                <h2 className="mt-3 text-3xl font-semibold tracking-tight">
                  Know where to look
                </h2>
                <p className="mt-3 max-w-xl text-zinc-600">
                  Start with the global threat picture. Organization-specific
                  monitoring is a separate layer that you can configure later.
                </p>
                <div className="mt-7 grid gap-3 sm:grid-cols-2">
                  {[
                    {
                      icon: ChartLineUp,
                      title: "Intelligence",
                      copy: "Explore deduplicated volume, groups, regions, and industries.",
                    },
                    {
                      icon: ClockCounterClockwise,
                      title: "Activity",
                      copy: "Review every retained claim and its complete source record.",
                    },
                    {
                      icon: FingerprintSimple,
                      title: "Threat actors",
                      copy: "Open professional actor dossiers and pivot to named victims.",
                    },
                    {
                      icon: Buildings,
                      title: "Clients & alerts",
                      copy: "Add profiles later to match names, domains, partners, and regions.",
                    },
                  ].map(({ icon: Icon, title, copy }) => (
                    <div
                      key={title}
                      className="rounded-2xl border border-zinc-200 bg-zinc-50 p-5"
                    >
                      <div className="grid h-10 w-10 place-items-center rounded-xl bg-teal-50 text-teal-700">
                        <Icon size={21} />
                      </div>
                      <h3 className="mt-4 text-base font-medium">{title}</h3>
                      <p className="mt-1.5 text-sm leading-6 text-zinc-600">
                        {copy}
                      </p>
                    </div>
                  ))}
                </div>
                <button
                  type="button"
                  className="button-primary mt-8"
                  onClick={() => setStep(2)}
                >
                  Continue <ArrowRight size={18} />
                </button>
              </div>
            )}
            {step === 2 && (
              <div className="mt-10">
                <p className="eyebrow">Step 2 of 3</p>
                <h2 className="mt-3 text-3xl font-semibold tracking-tight">
                  Start in Passive mode
                </h2>
                <p className="mt-3 max-w-xl text-zinc-600">
                  Collection modes are deliberately separate. Passive mode is
                  the safest default and provides useful coverage immediately.
                </p>
                <div className="mt-7 space-y-4">
                  <div className="rounded-2xl border border-teal-200 bg-teal-50/70 p-5">
                    <div className="flex items-start gap-4">
                      <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-white text-teal-700 shadow-sm">
                        <Database size={22} />
                      </div>
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="text-base font-medium">Passive monitoring</h3>
                          <span className="rounded-full bg-white px-2.5 py-1 text-[11px] font-medium uppercase tracking-wide text-teal-700">
                            Recommended
                          </span>
                        </div>
                        <p className="mt-2 text-sm leading-6 text-zinc-600">
                          Synchronizes maintained clear-web public sources. It
                          does not connect to a threat-actor site.
                        </p>
                      </div>
                    </div>
                  </div>
                  <div className="rounded-2xl border border-zinc-200 p-5">
                    <div className="flex items-start gap-4">
                      <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-zinc-100 text-zinc-700">
                        <Camera size={22} />
                      </div>
                      <div>
                        <h3 className="text-base font-medium">Active capture</h3>
                        <p className="mt-2 text-sm leading-6 text-zinc-600">
                          Optional evidence capture for an isolated Kali host and
                          explicit allowlist. Forms, authentication, messaging,
                          and stolen-data downloads remain blocked.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="mt-8 flex gap-3">
                  <button
                    type="button"
                    className="button-secondary"
                    onClick={() => setStep(1)}
                  >
                    Back
                  </button>
                  <button
                    type="button"
                    className="button-primary"
                    onClick={() => setStep(3)}
                  >
                    Continue <ArrowRight size={18} />
                  </button>
                </div>
              </div>
            )}
            {step === 3 && (
              <div className="mt-10">
                <p className="eyebrow">Step 3 of 3</p>
                <h2 className="mt-3 text-3xl font-semibold tracking-tight">
                  Use a simple analyst loop
                </h2>
                <p className="mt-3 max-w-xl text-zinc-600">
                  This repeatable sequence keeps source allegations, analyst
                  judgment, and client notification clearly separated.
                </p>
                <div className="mt-7 divide-y divide-zinc-100 rounded-2xl border border-zinc-200">
                  {[
                    ["1", "Check Sources", "Confirm feeds are current before interpreting a gap or spike."],
                    ["2", "Review Activity", "Filter new claims and open the archived source evidence."],
                    ["3", "Add context", "Enrich victim and actor records, then record analyst conclusions."],
                    ["4", "Tailor when ready", "Create client profiles to enable related-party and regional alerts."],
                  ].map(([number, title, copy]) => (
                    <div key={number} className="flex gap-4 px-5 py-4">
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-zinc-900 text-sm font-medium text-white">
                        {number}
                      </span>
                      <div>
                        <h3 className="text-sm font-medium text-zinc-900">{title}</h3>
                        <p className="mt-1 text-sm leading-6 text-zinc-600">{copy}</p>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-7 flex flex-wrap gap-3">
                  <button
                    type="button"
                    className="button-secondary"
                    onClick={() => setStep(2)}
                  >
                    Back
                  </button>
                  <button
                    type="button"
                    className="button-primary"
                    onClick={() => onComplete("home")}
                  >
                    <House size={18} />
                    Open dashboard
                  </button>
                  <button
                    type="button"
                    className="button-secondary"
                    onClick={() => onComplete("sources")}
                  >
                    Check sources <ArrowRight size={18} />
                  </button>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

function ClientForm({
  form,
  setForm,
  onSubmit,
  saving,
  error,
  submitLabel = "Add client",
}: {
  form: NewClient;
  setForm: (value: NewClient) => void;
  onSubmit: (event: FormEvent) => void;
  saving: boolean;
  error: string;
  submitLabel?: string;
}) {
  return (
    <form onSubmit={onSubmit} className="mt-7 space-y-6">
      <Field
        label="Company name"
        helper="Use the legal or most commonly recognized name."
      >
        <input
          required
          minLength={2}
          value={form.canonical_name}
          onChange={(event) =>
            setForm({ ...form, canonical_name: event.target.value })
          }
          className="input"
          placeholder="Meridian Harbour Group"
        />
      </Field>
      <Field
        label="Primary web domain"
        helper="Do not include a path. Example: company.hk"
      >
        <input
          required
          value={form.primary_domain}
          onChange={(event) =>
            setForm({ ...form, primary_domain: event.target.value })
          }
          className="input font-mono"
          placeholder="company.hk"
        />
      </Field>
      <Field
        label="Company description"
        helper="Briefly describe what the company does, its products, brands, and customers. This gives reviewers useful context."
      >
        <textarea
          value={form.description}
          onChange={(event) =>
            setForm({ ...form, description: event.target.value })
          }
          className="input min-h-28 resize-y"
          maxLength={2000}
          placeholder="Regional logistics provider serving ports and cold-chain operators across Asia…"
        />
      </Field>
      <div className="grid gap-6 sm:grid-cols-2">
        <MultiSelectField
          label="Markets and geographies"
          helper="Add every country or region where this organization operates. Hong Kong districts and Singapore regions/planning areas are included."
          placeholder="Add a country or region"
          options={GEOGRAPHY_OPTIONS}
          values={form.countries}
          onChange={(countries) => setForm({ ...form, countries })}
        />
        <MultiSelectField
          label="Industries"
          helper="Select all sectors relevant to this organization, including critical infrastructure."
          placeholder="Add an industry"
          options={INDUSTRY_OPTIONS}
          values={form.industries}
          onChange={(industries) => setForm({ ...form, industries })}
        />
      </div>
      <CityEditor
        values={form.cities}
        onChange={(cities) => setForm({ ...form, cities })}
      />
      <KeywordEditor
        values={form.keywords}
        onChange={(keywords) => setForm({ ...form, keywords })}
      />
      <RelatedEntitiesEditor
        values={form.related_entities}
        onChange={(related_entities) => setForm({ ...form, related_entities })}
      />
      <Field label="Monitoring priority">
        <CustomSelect
          ariaLabel="Monitoring priority"
          value={form.priority}
          onChange={(value) =>
            setForm({ ...form, priority: value as NewClient["priority"] })
          }
          options={[
            { value: "standard", label: "Standard" },
            { value: "high", label: "High" },
            { value: "critical", label: "Critical" },
          ]}
        />
      </Field>
      {error && <p className="text-sm font-medium text-rose-700">{error}</p>}
      <button type="submit" disabled={saving} className="button-primary">
        {saving ? (
          <SpinnerGap className="animate-spin" size={18} />
        ) : (
          <Plus size={18} />
        )}
        {submitLabel}
      </button>
    </form>
  );
}

function FocusRegionEditor({
  values,
  onChange,
}: {
  values: string[];
  onChange: (values: string[]) => void;
}) {
  const [draft, setDraft] = useState("");
  const available = GEOGRAPHY_OPTIONS.filter((name) => !values.includes(name));
  const add = (value: string) => {
    const cleaned = value.trim();
    if (cleaned.length < 2 || values.includes(cleaned)) return;
    onChange([...values, cleaned].slice(0, 50));
    setDraft("");
  };
  return (
    <div>
      <div className="grid gap-3 md:grid-cols-2">
        <SearchSelect
          ariaLabel="Focus country or region"
          placeholder="Choose a country or region"
          options={available}
          onSelect={add}
        />
        <div className="flex gap-2">
          <input
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                add(draft);
              }
            }}
            className="input"
            placeholder="Or add a city / custom region"
            maxLength={120}
          />
          <button
            type="button"
            onClick={() => add(draft)}
            disabled={draft.trim().length < 2}
            className="button-secondary shrink-0"
          >
            Add
          </button>
        </div>
      </div>
      <div className="mt-4 flex min-h-8 flex-wrap gap-2">
        {values.length ? (
          values.map((value) => (
            <span
              key={value}
              className="inline-flex items-center gap-1 rounded-full bg-sky-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-sky-900"
            >
              {value}
              <button
                type="button"
                onClick={() =>
                  onChange(values.filter((item) => item !== value))
                }
                className="grid h-6 w-6 place-items-center rounded-full hover:bg-sky-100"
                aria-label={`Remove focus region ${value}`}
              >
                <X size={13} />
              </button>
            </span>
          ))
        ) : (
          <span className="text-xs text-zinc-400">
            No global focus regions configured
          </span>
        )}
      </div>
    </div>
  );
}

function CityEditor({
  values,
  onChange,
}: {
  values: string[];
  onChange: (values: string[]) => void;
}) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const additions = draft
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length >= 2);
    if (!additions.length) return;
    onChange(Array.from(new Set([...values, ...additions])).slice(0, 50));
    setDraft("");
  };
  return (
    <fieldset className="rounded-2xl border border-zinc-200 bg-zinc-50/70 p-4 sm:p-5">
      <legend className="px-1 text-sm font-semibold text-zinc-800">
        Cities to highlight
      </legend>
      <p className="text-xs leading-5 text-zinc-500">
        Add headquarters and operational cities. Intelligence will highlight
        them when a source supplies matching geography.
      </p>
      <div className="mt-3 flex gap-2">
        <input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              add();
            }
          }}
          className="input"
          placeholder="Hong Kong, Singapore, London"
        />
        <button
          type="button"
          onClick={add}
          disabled={!draft.trim()}
          className="button-secondary shrink-0 px-4"
        >
          Add
        </button>
      </div>
      <div className="mt-3 flex min-h-7 flex-wrap gap-2">
        {values.length ? (
          values.map((value) => (
            <span
              key={value}
              className="inline-flex items-center gap-1 rounded-full bg-sky-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-sky-900"
            >
              {value}
              <button
                type="button"
                onClick={() =>
                  onChange(values.filter((item) => item !== value))
                }
                className="grid h-6 w-6 place-items-center rounded-full hover:bg-sky-100"
                aria-label={`Remove city ${value}`}
              >
                <X size={13} />
              </button>
            </span>
          ))
        ) : (
          <span className="text-xs text-zinc-400">No cities configured</span>
        )}
      </div>
    </fieldset>
  );
}

function MultiSelectField({
  label,
  helper,
  placeholder,
  options,
  values,
  onChange,
}: {
  label: string;
  helper: string;
  placeholder: string;
  options: readonly string[];
  values: string[];
  onChange: (values: string[]) => void;
}) {
  const available = options.filter((option) => !values.includes(option));
  return (
    <div>
      <span className="text-sm font-semibold text-zinc-800">{label}</span>
      <span className="mt-1 block text-xs text-zinc-500">{helper}</span>
      <div className="mt-2">
        <SearchSelect
          ariaLabel={label}
          placeholder={placeholder}
          options={available}
          onSelect={(value) => onChange([...values, value])}
        />
      </div>
      <div className="mt-3 flex min-h-7 flex-wrap gap-2">
        {values.length ? (
          values.map((value) => (
            <span
              key={value}
              className="inline-flex items-center gap-1 rounded-full bg-teal-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-teal-900"
            >
              {value}
              <button
                type="button"
                onClick={() =>
                  onChange(values.filter((item) => item !== value))
                }
                className="grid h-6 w-6 place-items-center rounded-full hover:bg-teal-100"
                aria-label={`Remove ${value}`}
              >
                <X size={13} />
              </button>
            </span>
          ))
        ) : (
          <span className="text-xs text-zinc-400">None selected</span>
        )}
      </div>
    </div>
  );
}

function SearchSelect({
  ariaLabel,
  placeholder,
  options,
  onSelect,
}: {
  ariaLabel: string;
  placeholder: string;
  options: readonly string[];
  onSelect: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const root = useRef<HTMLDivElement>(null);
  const filtered = options.filter((option) =>
    option.toLowerCase().includes(query.trim().toLowerCase()),
  );
  useEffect(() => {
    const close = (event: MouseEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  return (
    <div ref={root} className="relative">
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        className={`input flex items-center justify-between gap-3 text-left ${open ? "border-teal-700 ring-4 ring-teal-700/10" : ""}`}
      >
        <span className="text-zinc-500">{placeholder}</span>
        <CaretDown
          size={17}
          className={`shrink-0 text-zinc-400 transition ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && (
        <div className="absolute z-50 mt-2 w-full overflow-hidden rounded-2xl border border-zinc-200 bg-white p-2 shadow-[0_20px_50px_-20px_rgba(24,24,27,.35)]">
          <label className="flex items-center gap-2 rounded-xl bg-zinc-50 px-3">
            <MagnifyingGlass size={16} className="text-zinc-400" />
            <span className="sr-only">Search {ariaLabel}</span>
            <input
              autoFocus
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape") setOpen(false);
              }}
              className="min-h-10 w-full bg-transparent text-sm outline-none"
              placeholder={`Search ${ariaLabel.toLowerCase()}`}
            />
          </label>
          <div
            role="listbox"
            aria-label={ariaLabel}
            className="mt-1 max-h-56 overflow-y-auto p-1"
          >
            {filtered.length ? (
              filtered.map((option) => (
                <button
                  type="button"
                  role="option"
                  aria-selected="false"
                  key={option}
                  onClick={() => {
                    onSelect(option);
                    setQuery("");
                    setOpen(false);
                  }}
                  className="block w-full rounded-xl px-3 py-2.5 text-left text-sm text-zinc-700 transition hover:bg-teal-50 hover:text-teal-900"
                >
                  {option}
                </button>
              ))
            ) : (
              <p className="px-3 py-5 text-center text-xs text-zinc-400">
                No matching options
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function KeywordEditor({
  values,
  onChange,
}: {
  values: string[];
  onChange: (values: string[]) => void;
}) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const additions = draft
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length >= 3);
    if (!additions.length) return;
    onChange(Array.from(new Set([...values, ...additions])).slice(0, 30));
    setDraft("");
  };
  return (
    <fieldset className="rounded-2xl border border-zinc-200 bg-zinc-50/70 p-4 sm:p-5">
      <legend className="px-1 text-sm font-semibold text-zinc-800">
        Alert keywords
      </legend>
      <p className="text-xs leading-5 text-zinc-500">
        Add distinctive product names, brands, locations, or business-unit
        phrases. Keyword-only hits are sent to human review.
      </p>
      <div className="mt-3 flex gap-2">
        <input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              add();
            }
          }}
          className="input"
          placeholder="Product name or distinctive phrase"
          maxLength={240}
        />
        <button
          type="button"
          onClick={add}
          disabled={!draft.trim()}
          className="button-secondary shrink-0 px-4"
        >
          Add
        </button>
      </div>
      <div className="mt-3 flex min-h-7 flex-wrap gap-2">
        {values.length ? (
          values.map((value) => (
            <span
              key={value}
              className="inline-flex items-center gap-1 rounded-full bg-amber-50 py-1 pl-3 pr-1.5 text-xs font-semibold text-amber-900"
            >
              {value}
              <button
                type="button"
                onClick={() =>
                  onChange(values.filter((item) => item !== value))
                }
                className="grid h-6 w-6 place-items-center rounded-full hover:bg-amber-100"
                aria-label={`Remove keyword ${value}`}
              >
                <X size={13} />
              </button>
            </span>
          ))
        ) : (
          <span className="text-xs text-zinc-400">
            No keyword alerts configured
          </span>
        )}
      </div>
    </fieldset>
  );
}

function RelatedEntitiesEditor({
  values,
  onChange,
}: {
  values: RelatedEntity[];
  onChange: (values: RelatedEntity[]) => void;
}) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [relationship, setRelationship] =
    useState<RelatedEntity["relationship"]>("subsidiary");
  const add = () => {
    const cleanName = name.trim();
    if (!cleanName) return;
    onChange([
      ...values,
      { name: cleanName, domain: domain.trim(), relationship },
    ]);
    setName("");
    setDomain("");
  };
  return (
    <fieldset className="rounded-2xl border border-zinc-200 bg-zinc-50/70 p-4 sm:p-5">
      <legend className="px-1 text-sm font-semibold text-zinc-800">
        Related organizations
      </legend>
      <p className="text-xs leading-5 text-zinc-500">
        Add subsidiaries and important third parties. Their names and domains
        will participate in matching.
      </p>
      <div className="mt-4 grid gap-3 sm:grid-cols-[.8fr_1.2fr_1fr_auto]">
        <CustomSelect
          ariaLabel="Relationship type"
          value={relationship}
          onChange={(value) =>
            setRelationship(value as RelatedEntity["relationship"])
          }
          options={[
            { value: "subsidiary", label: "Subsidiary" },
            { value: "third_party", label: "Third party" },
          ]}
        />
        <input
          value={name}
          onChange={(event) => setName(event.target.value)}
          className="input"
          placeholder="Organization name"
          aria-label="Related organization name"
        />
        <input
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
          className="input font-mono"
          placeholder="domain.com (optional)"
          aria-label="Related organization domain"
        />
        <button
          type="button"
          onClick={add}
          disabled={!name.trim()}
          className="button-secondary px-3"
          aria-label="Add related organization"
        >
          <Plus size={18} />
        </button>
      </div>
      {values.length > 0 && (
        <div className="mt-4 divide-y divide-zinc-200 border-y border-zinc-200">
          {values.map((entity, index) => (
            <div
              key={`${entity.relationship}-${entity.name}-${index}`}
              className="flex items-center justify-between gap-4 py-3"
            >
              <div>
                <p className="text-sm font-semibold text-zinc-800">
                  {entity.name}
                </p>
                <p className="mt-1 text-xs text-zinc-500">
                  <span className="capitalize">
                    {entity.relationship.replace("_", " ")}
                  </span>
                  {entity.domain ? ` · ${entity.domain}` : ""}
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  onChange(values.filter((_, itemIndex) => itemIndex !== index))
                }
                className="icon-button !h-9 !w-9"
                aria-label={`Remove ${entity.name}`}
              >
                <X size={16} />
              </button>
            </div>
          ))}
        </div>
      )}
    </fieldset>
  );
}

function summarizeValues(values: string[], empty: string) {
  if (!values.length) return empty;
  return values.length > 2
    ? `${values.slice(0, 2).join(", ")} +${values.length - 2}`
    : values.join(", ");
}

function AlertRow({ alert, divided }: { alert: Alert; divided?: boolean }) {
  return (
    <div
      data-dashboard-row
      className={`group grid gap-4 p-5 transition hover:bg-zinc-50 sm:grid-cols-[auto_1fr] sm:items-center lg:grid-cols-[auto_minmax(0,1.2fr)_minmax(0,1fr)_auto] ${divided ? "border-t border-zinc-200" : ""}`}
    >
      <SeverityMark severity={alert.severity} />
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <p className="break-words font-semibold text-zinc-900">
            {alert.claim_title}
          </p>
          <AlertStatusBadge status={alert.status} />
        </div>
        <p className="mt-1 break-words text-xs text-zinc-500">
          Claim by {alert.threat_actor}
        </p>
      </div>
      <div className="min-w-0 sm:col-start-2 lg:col-start-auto">
        <p className="break-words text-sm font-medium text-zinc-700">
          {alert.client_name}
        </p>
        <p className="mt-1 break-words text-xs text-zinc-500">{alert.reason}</p>
      </div>
      <div className="flex items-center gap-3 sm:col-start-2 lg:col-start-auto lg:justify-end">
        <span className="whitespace-nowrap font-mono text-xs text-zinc-500">
          {formatTime(alert.updated_at || alert.created_at)}
        </span>
        <ArrowRight
          size={17}
          className="shrink-0 text-zinc-400 transition group-hover:translate-x-1"
        />
      </div>
    </div>
  );
}
function ClaimRow({ claim }: { claim: Claim }) {
  return (
    <div data-dashboard-row className="py-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-semibold">{claim.title}</p>
          <p className="mt-1 text-xs text-zinc-500">
            {claim.threat_actor} · {claim.source}
          </p>
        </div>
        <span className="font-mono text-[11px] text-zinc-400">
          {formatTime(claim.received_at)}
        </span>
      </div>
    </div>
  );
}
function Metric({ label, value }: { label: string; value: number }) {
  const reducedMotion = useReducedMotion();
  return (
    <div className="px-4 py-3 md:px-7">
      <motion.p
        key={value}
        initial={reducedMotion ? false : { opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ type: "spring", stiffness: 240, damping: 23 }}
        className="font-mono text-3xl font-semibold tracking-tight md:text-4xl"
      >
        <AnimatedNumber value={value} />
      </motion.p>
      <p className="mt-1 text-xs font-medium text-zinc-500 md:text-sm">
        {label}
      </p>
    </div>
  );
}

function AnimatedNumber({ value }: { value: number }) {
  const node = useRef<HTMLSpanElement>(null);
  const previousValue = useRef(0);
  const reducedMotion = useReducedMotion();

  useGSAP(
    () => {
      const target = node.current;
      if (!target) return;
      const decimals = Number.isInteger(value) ? 0 : 1;
      const format = (current: number) =>
        current.toLocaleString(undefined, {
          minimumFractionDigits: decimals,
          maximumFractionDigits: decimals,
        });
      if (reducedMotion) {
        target.textContent = format(value);
        previousValue.current = value;
        return;
      }
      const counter = { value: previousValue.current };
      previousValue.current = value;
      gsap.to(counter, {
        value,
        duration: 0.58,
        ease: "power2.out",
        onUpdate: () => {
          if (target.isConnected) target.textContent = format(counter.value);
        },
        onComplete: () => {
          if (target.isConnected) target.textContent = format(value);
        },
      });
    },
    { scope: node, dependencies: [value, reducedMotion], revertOnUpdate: true },
  );

  return <span ref={node}>{value.toLocaleString()}</span>;
}
function SectionHeading({
  title,
  description,
  action,
  onAction,
}: {
  title: string;
  description: string;
  action: string;
  onAction: () => void;
}) {
  return (
    <div className="flex items-end justify-between gap-5">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">{title}</h2>
        <p className="mt-1 max-w-xl text-sm text-zinc-500">{description}</p>
      </div>
      <button
        type="button"
        onClick={onAction}
        className="hidden text-sm font-semibold text-teal-800 sm:block"
      >
        {action}
      </button>
    </div>
  );
}
function PageIntro({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string;
  title: string;
  description: string;
}) {
  return (
    <div>
      <p className="eyebrow">{eyebrow}</p>
      <h2 className="mt-2 text-3xl font-semibold tracking-[-0.035em] md:text-4xl">
        {title}
      </h2>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-600 md:text-base">
        {description}
      </p>
    </div>
  );
}
function EmptyState({
  title,
  description,
  icon,
}: {
  title: string;
  description: string;
  icon: ReactNode;
}) {
  return (
    <div className="mt-6 rounded-[2rem] border border-dashed border-zinc-300 bg-white/50 p-10 text-center">
      <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-zinc-100 text-zinc-600">
        {icon}
      </div>
      <h3 className="mt-5 font-semibold">{title}</h3>
      <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-zinc-500">
        {description}
      </p>
    </div>
  );
}
function InlineNotice({
  tone,
  children,
  autoDismissMs,
}: {
  tone: "danger" | "neutral";
  children: ReactNode;
  autoDismissMs?: number;
}) {
  const reducedMotion = useReducedMotion();
  const [visible, setVisible] = useState(true);
  const noticeKey =
    typeof children === "string" || typeof children === "number"
      ? String(children)
      : tone;
  useEffect(() => {
    setVisible(true);
    const timeout = window.setTimeout(
      () => setVisible(false),
      autoDismissMs ?? (tone === "danger" ? 10_000 : 6_000),
    );
    return () => window.clearTimeout(timeout);
  }, [autoDismissMs, noticeKey, tone]);
  return (
    <AnimatePresence initial={false}>
      {visible && (
        <motion.div
          role={tone === "danger" ? "alert" : "status"}
          aria-live={tone === "danger" ? "assertive" : "polite"}
          initial={reducedMotion ? false : { opacity: 0, y: -5, height: 0 }}
          animate={{ opacity: 1, y: 0, height: "auto" }}
          exit={
            reducedMotion
              ? { opacity: 0 }
              : { opacity: 0, y: -4, height: 0, marginTop: 0 }
          }
          transition={{ duration: reducedMotion ? 0.01 : 0.24 }}
          className={`mx-auto mt-5 flex max-w-[1400px] items-start gap-3 overflow-hidden rounded-xl border px-4 py-3 text-sm ${tone === "danger" ? "border-rose-200 bg-rose-50 text-rose-800" : "border-zinc-200 bg-zinc-100 text-zinc-700"}`}
        >
          {tone === "danger" ? (
            <Warning className="mt-0.5 shrink-0" size={18} />
          ) : (
            <Info className="mt-0.5 shrink-0" size={18} />
          )}
          {children}
        </motion.div>
      )}
    </AnimatePresence>
  );
}
function Field({
  label,
  helper,
  children,
}: {
  label: string;
  helper?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="text-sm font-semibold text-zinc-800">{label}</span>
      {helper && (
        <span className="mt-1 block text-xs text-zinc-500">{helper}</span>
      )}
      <span className="mt-2 block">{children}</span>
    </label>
  );
}
function Modal({
  title,
  description,
  onClose,
  children,
  wide = false,
  fullScreen = false,
}: {
  title: string;
  description: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
  fullScreen?: boolean;
}) {
  return (
    <motion.div
      className={`fixed inset-0 z-30 grid place-items-center overflow-y-auto bg-zinc-950/30 backdrop-blur-sm ${fullScreen ? "p-2" : "p-4"}`}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        className={`w-full bg-white shadow-2xl ${
          fullScreen
            ? "my-0 max-w-[calc(100vw-1rem)] rounded-2xl p-4 sm:p-5"
            : `my-8 rounded-[2rem] p-6 sm:p-9 ${wide ? "max-w-6xl" : "max-w-2xl"}`
        }`}
        initial={{ opacity: 0, y: 24, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 15, scale: 0.98 }}
        transition={{ type: "spring", stiffness: 170, damping: 24 }}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-2xl font-semibold tracking-tight">{title}</h2>
            <p className="mt-2 max-w-lg text-sm leading-6 text-zinc-500">
              {description}
            </p>
          </div>
          <button
            type="button"
            className="icon-button"
            onClick={onClose}
            aria-label="Close"
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </motion.div>
    </motion.div>
  );
}
function SeverityMark({ severity }: { severity: Alert["severity"] }) {
  return (
    <span
      className={`grid h-10 w-10 place-items-center rounded-xl ${severity === "critical" ? "bg-rose-100 text-rose-700" : severity === "high" ? "bg-amber-100 text-amber-700" : "bg-zinc-100 text-zinc-600"}`}
    >
      {severity === "critical" ? (
        <Warning size={20} weight="fill" />
      ) : (
        <ListMagnifyingGlass size={20} />
      )}
    </span>
  );
}
function SeverityBadge({ severity }: { severity: Alert["severity"] }) {
  return (
    <span
      className={`inline-flex rounded-full px-3 py-1 text-xs font-bold uppercase tracking-wide ${severity === "critical" ? "bg-rose-100 text-rose-800" : severity === "high" ? "bg-amber-100 text-amber-800" : "bg-zinc-200 text-zinc-700"}`}
    >
      {severity}
    </span>
  );
}
function PriorityBadge({ priority }: { priority: Client["priority"] }) {
  return (
    <span className="w-fit rounded-full bg-zinc-100 px-3 py-1 text-xs font-semibold capitalize text-zinc-700">
      {priority}
    </span>
  );
}
function StatusBadge({ status }: { status: SourceHealth["status"] }) {
  return (
    <motion.span
      layout
      key={status}
      initial={{ opacity: 0.55, scale: 0.94 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ type: "spring", stiffness: 280, damping: 22 }}
      className={`shrink-0 rounded-full px-3 py-1 text-xs font-semibold capitalize transition-colors duration-300 ${status === "working" ? "bg-teal-50 text-teal-800" : status === "unavailable" ? "bg-rose-50 text-rose-800" : "bg-amber-50 text-amber-800"}`}
    >
      {status.replaceAll("_", " ")}
    </motion.span>
  );
}
function alertStatusLabel(status: AlertStatus) {
  return (
    {
      new: "New",
      investigating: "Investigating",
      client_notified: "Client notified",
      monitoring: "Monitoring",
      resolved: "Resolved",
      dismissed: "Dismissed",
    } as Record<AlertStatus, string>
  )[status];
}
function AlertStatusBadge({ status }: { status: AlertStatus }) {
  const tone =
    status === "new"
      ? "bg-rose-50 text-rose-800"
      : status === "investigating"
        ? "bg-amber-50 text-amber-800"
        : status === "client_notified"
          ? "bg-violet-50 text-violet-800"
          : status === "monitoring"
            ? "bg-sky-50 text-sky-800"
            : status === "resolved"
              ? "bg-teal-50 text-teal-800"
              : "bg-zinc-100 text-zinc-600";
  return (
    <motion.span
      layout
      key={status}
      initial={{ opacity: 0.55, scale: 0.94 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ type: "spring", stiffness: 280, damping: 22 }}
      className={`inline-flex w-fit max-w-full shrink-0 items-center justify-center rounded-full px-2.5 py-1 text-center text-[10px] font-bold uppercase leading-4 tracking-wide transition-colors duration-300 ${tone}`}
    >
      {alertStatusLabel(status)}
    </motion.span>
  );
}
function DetailBlock({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-zinc-400">
        {label}
      </p>
      <p
        className={`mt-2 text-sm font-medium text-zinc-800 ${mono ? "font-mono" : ""}`}
      >
        {value}
      </p>
    </div>
  );
}
function StepNumber({ value }: { value: string }) {
  return (
    <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-zinc-900 font-mono text-xs font-bold text-white">
      {value}
    </span>
  );
}
function Stat({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wide text-zinc-400">
        {label}
      </dt>
      <dd
        className={`mt-2 text-sm font-medium text-zinc-800 ${mono ? "font-mono" : ""}`}
      >
        {value}
      </dd>
    </div>
  );
}
function SettingRow({
  title,
  description,
  value,
}: {
  title: string;
  description: string;
  value: string;
}) {
  return (
    <div className="grid gap-3 py-6 sm:grid-cols-[1.3fr_1fr_auto] sm:items-center">
      <div>
        <p className="font-semibold">{title}</p>
        <p className="mt-1 text-sm text-zinc-500">{description}</p>
      </div>
      <span />
      <span className="w-fit rounded-full bg-zinc-100 px-3 py-1 text-xs font-semibold text-zinc-700">
        {value}
      </span>
    </div>
  );
}
function AppLoadingScreen({
  ready,
  onComplete,
}: {
  ready: boolean;
  onComplete: () => void;
}) {
  const root = useRef<HTMLDivElement>(null);
  const reducedMotion = useReducedMotion();
  const completeRef = useRef(onComplete);
  useEffect(() => {
    completeRef.current = onComplete;
  }, [onComplete]);

  useGSAP(
    (_context, contextSafe) => {
      if (!ready) return;
      const finish = contextSafe
        ? contextSafe(() => completeRef.current())
        : () => completeRef.current();
      if (reducedMotion) {
        gsap.to(root.current, {
          opacity: 0,
          duration: 0.12,
          onComplete: finish,
        });
        return;
      }
      gsap
        .timeline({ onComplete: finish })
        .to("[data-loading-status-card]", {
          opacity: 0,
          scale: 0.97,
          duration: 0.16,
          ease: "power1.in",
        })
        .to(
          root.current,
          { opacity: 0, duration: 0.16, ease: "power1.out" },
          "-=0.02",
        );
    },
    {
      scope: root,
      dependencies: [ready, reducedMotion],
      revertOnUpdate: true,
    },
  );

  return (
    <div
      ref={root}
      role="status"
      aria-live="polite"
      aria-label="Loading ExtortSignal intelligence workspace"
      className="fixed inset-0 z-[100] grid min-h-[100dvh] place-items-center bg-[#f5f7f6]"
    >
      <LoadingStatusCard
        title="Loading ExtortSignal"
        iconOnly
        announce={false}
      />
    </div>
  );
}
function ConnectionError({
  message,
  retry,
}: {
  message: string;
  retry: () => Promise<void>;
}) {
  return (
    <div className="grid min-h-[100dvh] place-items-center bg-[#f5f7f6] p-5">
      <div className="max-w-lg rounded-[2rem] border border-zinc-200 bg-white p-9 text-center shadow-sm">
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-rose-50 text-rose-700">
          <XCircle size={30} />
        </div>
        <h1 className="mt-5 text-2xl font-semibold tracking-tight">
          Local service unavailable
        </h1>
        <p className="mt-3 text-sm leading-6 text-zinc-500">
          {message}. Start the backend service, then try again.
        </p>
        <button
          type="button"
          className="button-primary mt-6"
          onClick={() => void retry()}
        >
          <SpinnerGap size={18} />
          Try again
        </button>
      </div>
    </div>
  );
}

export default App;
