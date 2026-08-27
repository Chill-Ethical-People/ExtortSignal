import { DownloadSimple, SpinnerGap } from "@phosphor-icons/react";
import { useReducedMotion } from "framer-motion";
import { useMemo, useRef, useState } from "react";
import { exportSvgAsPng } from "../chartExport";
import { WORLD_COUNTRY_PATHS } from "../worldMapPaths";

type CountryVolume = { name: string; count: number; is_monitored?: boolean };
type LocatedCountry = CountryVolume & { x: number; y: number };

const WIDTH = 800;
const HEIGHT = 400;

function hashText(value: string) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function seededUnit(seed: number) {
  const value = Math.sin(seed * 12.9898) * 43758.5453;
  return value - Math.floor(value);
}

function routePath(from: LocatedCountry, to: LocatedCountry, lift: number) {
  const middleX = (from.x + to.x) / 2;
  const distance = Math.abs(from.x - to.x);
  const middleY = Math.max(
    30,
    Math.min(from.y, to.y) - Math.min(92, 24 + distance * 0.13 + lift),
  );
  return `M ${from.x} ${from.y} Q ${middleX} ${middleY} ${to.x} ${to.y}`;
}

export function ThreatWorldMap({
  items,
  resolveCountry,
}: {
  items: CountryVolume[];
  resolveCountry: (name: string) => [number, number] | null;
}) {
  const reduceMotion = useReducedMotion();
  const svgRef = useRef<SVGSVGElement>(null);
  const [exporting, setExporting] = useState(false);
  const located = useMemo(
    () =>
      items.flatMap((item) => {
        const coordinate = resolveCountry(item.name);
        return coordinate
          ? [
              {
                ...item,
                x: ((coordinate[0] + 180) / 360) * WIDTH,
                y: ((90 - coordinate[1]) / 180) * HEIGHT,
              },
            ]
          : [];
      }),
    [items, resolveCountry],
  );
  const missing = items.filter((item) => !resolveCountry(item.name));
  const total = items.reduce((sum, item) => sum + item.count, 0);
  const mappedTotal = located.reduce((sum, item) => sum + item.count, 0);
  const max = Math.max(1, ...located.map((item) => item.count));
  const [activeName, setActiveName] = useState("");
  const [hoveredName, setHoveredName] = useState("");
  const active = located.find((item) => item.name === activeName) ?? located[0];
  const hovered = located.find((item) => item.name === hoveredName);

  const specks = useMemo(
    () =>
      located.flatMap((item) => {
        const amount = Math.min(
          28,
          5 + Math.round(23 * Math.sqrt(item.count / max)),
        );
        const seed = hashText(item.name);
        return Array.from({ length: amount }, (_, index) => {
          const angle = seededUnit(seed + index * 7) * Math.PI * 2;
          const spread = Math.sqrt(seededUnit(seed + index * 13 + 3));
          return {
            key: `${item.name}-${index}`,
            x: Math.max(
              8,
              Math.min(WIDTH - 8, item.x + Math.cos(angle) * spread * 34),
            ),
            y: Math.max(
              8,
              Math.min(HEIGHT - 8, item.y + Math.sin(angle) * spread * 20),
            ),
            monitored: item.is_monitored,
          };
        });
      }),
    [located, max],
  );

  const connections = useMemo(() => {
    if (located.length < 2) return [];
    const pairs: {
      from: LocatedCountry;
      to: LocatedCountry;
      key: string;
      lift: number;
    }[] = [];
    located.slice(1, 12).forEach((to, index) =>
      pairs.push({
        from: located[0],
        to,
        key: `hub-${to.name}`,
        lift: (index % 3) * 7,
      }),
    );
    located.slice(1, 5).forEach((from, index) => {
      const to = located[index + 2];
      if (to)
        pairs.push({
          from,
          to,
          key: `mesh-${from.name}-${to.name}`,
          lift: 12 + index * 4,
        });
    });
    return pairs;
  }, [located]);

  return (
    <section className="min-w-0 overflow-hidden rounded-[2rem] border border-zinc-200 bg-white p-6 md:p-8">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="eyebrow">Geographic distribution</p>
          <h3 className="mt-2 text-xl font-semibold">
            Most affected countries
          </h3>
          <p className="mt-2 text-xs leading-5 text-zinc-500">
            Hover or focus a hub for its region and observed volume. Click or
            tap to compare its network.
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-3 text-[10px] font-semibold text-zinc-500">
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
            Observed volume
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-400 ring-2 ring-sky-200" />
            Your region
          </span>
          <button
            type="button"
            disabled={exporting}
            onClick={() => {
              setExporting(true);
              void exportSvgAsPng(
                svgRef.current,
                "geographic-claim-distribution",
                "#021713",
              ).finally(() => setExporting(false));
            }}
            className="button-secondary !min-h-10 px-3 py-2 text-xs"
            aria-label="Export geographic distribution as PNG"
          >
            {exporting ? (
              <SpinnerGap className="animate-spin" size={16} />
            ) : (
              <DownloadSimple size={16} />
            )}
            PNG
          </button>
        </div>
      </div>

      <div className="relative mt-5 overflow-hidden rounded-[1.5rem] border border-emerald-800/70 bg-[#021713] shadow-[0_26px_70px_-32px_rgba(2,44,34,.95)]">
        {hovered && (
          <div
            id="country-map-tooltip"
            role="tooltip"
            className="pointer-events-none absolute z-30 min-w-[10rem] rounded-xl border border-emerald-200/25 bg-[#031813]/95 px-3 py-2.5 text-white shadow-[0_16px_40px_rgba(0,0,0,.6)] ring-1 ring-black/20 backdrop-blur"
            style={{
              left: `${(hovered.x / WIDTH) * 100}%`,
              top: `${(hovered.y / HEIGHT) * 100}%`,
              transform: `translate(${hovered.x > WIDTH * 0.72 ? "-100%" : hovered.x < WIDTH * 0.28 ? "0%" : "-50%"}, ${hovered.y < HEIGHT * 0.3 ? "24%" : "-118%"})`,
            }}
          >
            <div className="flex items-center gap-2">
              <span
                className={`h-2 w-2 rounded-full ${hovered.is_monitored ? "bg-sky-400" : "bg-emerald-300"}`}
              />
              <p className="max-w-[12rem] truncate text-xs font-semibold">
                {hovered.name}
              </p>
            </div>
            <div className="mt-2 flex items-baseline justify-between gap-4">
              <span className="text-[9px] uppercase tracking-[.14em] text-zinc-400">
                Volume
              </span>
              <strong className="font-mono text-base">
                {hovered.count.toLocaleString()}
              </strong>
            </div>
            <p className="mt-1 text-[9px] text-emerald-100/75">
              {total ? ((hovered.count / total) * 100).toFixed(1) : "0.0"}% of
              displayed deduplicated claims
              {hovered.is_monitored ? " · monitored region" : ""}
            </p>
          </div>
        )}

        <svg
          ref={svgRef}
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          className="h-auto min-h-[270px] w-full"
          role="img"
          aria-label="Interactive world map of countries appearing in retained public ransomware claims"
        >
          <defs>
            <radialGradient id="network-ocean" cx="50%" cy="48%" r="68%">
              <stop offset="0%" stopColor="#073e31" />
              <stop offset="62%" stopColor="#03251e" />
              <stop offset="100%" stopColor="#01110e" />
            </radialGradient>
            <linearGradient id="network-land" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#639b82" />
              <stop offset="55%" stopColor="#3e745f" />
              <stop offset="100%" stopColor="#285847" />
            </linearGradient>
            <pattern
              id="network-grid"
              width="32"
              height="32"
              patternUnits="userSpaceOnUse"
            >
              <path
                d="M 32 0 L 0 0 0 32"
                fill="none"
                stroke="#6ee7b7"
                strokeOpacity=".055"
                strokeWidth="1"
              />
            </pattern>
            <radialGradient id="hub-core">
              <stop offset="0%" stopColor="#fff" />
              <stop offset="28%" stopColor="#a7f3d0" />
              <stop offset="100%" stopColor="#10b981" />
            </radialGradient>
            <filter id="land-shadow">
              <feDropShadow
                dx="0"
                dy="6"
                stdDeviation="7"
                floodColor="#00110d"
                floodOpacity=".65"
              />
            </filter>
            <filter
              id="hub-glow"
              x="-200%"
              y="-200%"
              width="400%"
              height="400%"
            >
              <feGaussianBlur stdDeviation="5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <rect width={WIDTH} height={HEIGHT} fill="url(#network-ocean)" />
          <rect width={WIDTH} height={HEIGHT} fill="url(#network-grid)" />
          <ellipse
            cx="400"
            cy="208"
            rx="370"
            ry="174"
            fill="none"
            stroke="#86efac"
            strokeOpacity=".08"
          />
          {[90, 150, 210, 270, 330].map((y) => (
            <path
              key={`lat-${y}`}
              d={`M 18 ${y} Q 400 ${y - 20} 782 ${y}`}
              fill="none"
              stroke="#a7f3d0"
              strokeOpacity=".075"
              strokeDasharray="2 8"
            />
          ))}
          {[105, 250, 400, 550, 695].map((x) => (
            <path
              key={`lon-${x}`}
              d={`M ${x} 24 Q ${x - 38} 200 ${x} 376`}
              fill="none"
              stroke="#a7f3d0"
              strokeOpacity=".065"
              strokeDasharray="2 9"
            />
          ))}

          <g
            fill="url(#network-land)"
            fillOpacity=".78"
            stroke="#91c9ad"
            strokeOpacity=".42"
            strokeWidth=".55"
            filter="url(#land-shadow)"
          >
            {WORLD_COUNTRY_PATHS.map((country) => (
              <path key={country.name} d={country.d}>
                <title>{country.name}</title>
              </path>
            ))}
          </g>

          <g aria-hidden="true">
            {specks.map((point, index) => (
              <circle
                key={point.key}
                cx={point.x}
                cy={point.y}
                r={index % 7 === 0 ? 1.1 : 0.65}
                fill={point.monitored ? "#7dd3fc" : "#d1fae5"}
                opacity={index % 5 === 0 ? 0.82 : 0.48}
              />
            ))}
          </g>

          <g aria-hidden="true">
            {connections.map((connection, index) => {
              const d = routePath(
                connection.from,
                connection.to,
                connection.lift,
              );
              const selected =
                active &&
                (connection.from.name === active.name ||
                  connection.to.name === active.name);
              return (
                <g key={connection.key}>
                  <path
                    d={d}
                    fill="none"
                    stroke={selected ? "#a7f3d0" : "#34d399"}
                    strokeOpacity={selected ? 0.68 : 0.23}
                    strokeWidth={selected ? 1.7 : 0.8}
                  />
                  <path
                    d={d}
                    fill="none"
                    stroke="#ecfdf5"
                    strokeOpacity={selected ? 0.72 : 0.28}
                    strokeWidth=".8"
                    strokeDasharray="2 11"
                  >
                    {!reduceMotion && (
                      <animate
                        attributeName="stroke-dashoffset"
                        from="39"
                        to="0"
                        dur={`${2.4 + index * 0.12}s`}
                        repeatCount="indefinite"
                      />
                    )}
                  </path>
                  {!reduceMotion && (
                    <circle
                      r={selected ? 2.2 : 1.5}
                      fill={selected ? "#ecfdf5" : "#6ee7b7"}
                      opacity={selected ? 0.95 : 0.68}
                      filter="url(#hub-glow)"
                    >
                      <animateMotion
                        path={d}
                        dur={`${3.2 + index * 0.24}s`}
                        begin={`${index * -0.31}s`}
                        repeatCount="indefinite"
                      />
                      <animate
                        attributeName="opacity"
                        values="0;.95;.95;0"
                        dur={`${3.2 + index * 0.24}s`}
                        repeatCount="indefinite"
                      />
                    </circle>
                  )}
                </g>
              );
            })}
          </g>

          {located.map((item) => {
            const radius = 3.5 + Math.sqrt(item.count / max) * 6.5;
            const selected = item.name === active?.name;
            return (
              <g
                key={item.name}
                role="button"
                tabIndex={0}
                aria-describedby={
                  hoveredName === item.name ? "country-map-tooltip" : undefined
                }
                aria-label={`${item.name}: ${item.count} deduplicated claims${item.is_monitored ? ", monitored region" : ""}`}
                className="cursor-pointer outline-none"
                onMouseEnter={() => {
                  setActiveName(item.name);
                  setHoveredName(item.name);
                }}
                onMouseLeave={() => setHoveredName("")}
                onFocus={() => {
                  setActiveName(item.name);
                  setHoveredName(item.name);
                }}
                onBlur={() => setHoveredName("")}
                onClick={() => setActiveName(item.name)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    setActiveName(item.name);
                  }
                }}
              >
                <circle
                  cx={item.x}
                  cy={item.y}
                  r={radius + (selected ? 10 : 6)}
                  fill={item.is_monitored ? "#38bdf8" : "#34d399"}
                  opacity={selected ? 0.2 : 0.11}
                  filter="url(#hub-glow)"
                />
                {!reduceMotion && (
                  <circle
                    cx={item.x}
                    cy={item.y}
                    r={radius + 4}
                    fill="none"
                    stroke={item.is_monitored ? "#7dd3fc" : "#6ee7b7"}
                    strokeWidth="1"
                    opacity="0"
                  >
                    <animate
                      attributeName="r"
                      values={`${radius + 2};${radius + 15}`}
                      dur="2.8s"
                      begin={`${(hashText(item.name) % 17) / -10}s`}
                      repeatCount="indefinite"
                    />
                    <animate
                      attributeName="opacity"
                      values=".65;0"
                      dur="2.8s"
                      begin={`${(hashText(item.name) % 17) / -10}s`}
                      repeatCount="indefinite"
                    />
                  </circle>
                )}
                <circle
                  cx={item.x}
                  cy={item.y}
                  r={radius + 2}
                  fill="none"
                  stroke={item.is_monitored ? "#7dd3fc" : "#6ee7b7"}
                  strokeOpacity={selected ? 0.92 : 0.48}
                  strokeWidth={selected ? 1.8 : 0.8}
                />
                <circle
                  cx={item.x}
                  cy={item.y}
                  r={radius}
                  fill={item.is_monitored ? "#38bdf8" : "url(#hub-core)"}
                  stroke="#ecfdf5"
                  strokeWidth={selected ? 2 : 1}
                  filter="url(#hub-glow)"
                />
                <title>
                  {item.name}: {item.count} deduplicated claims
                  {item.is_monitored ? " · monitored region" : ""}
                </title>
              </g>
            );
          })}
        </svg>
      </div>

      <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {items.slice(0, 6).map((item, index) => (
          <button
            type="button"
            key={item.name}
            onClick={() => setActiveName(item.name)}
            className={`group grid cursor-pointer grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 rounded-xl border px-3 py-2.5 text-left text-xs transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-600 ${active?.name === item.name ? "border-teal-300 bg-teal-50 text-teal-950" : item.is_monitored ? "border-sky-200 bg-sky-50 text-sky-900 hover:border-sky-300" : "border-zinc-100 bg-zinc-50 text-zinc-700 hover:border-teal-200 hover:bg-teal-50/50"}`}
          >
            <span className="grid h-6 w-6 place-items-center rounded-lg bg-white font-mono text-[10px] text-zinc-400 shadow-sm">
              {index + 1}
            </span>
            <span className="min-w-0">
              <span className="block truncate font-semibold">{item.name}</span>
              {item.is_monitored && (
                <span className="mt-0.5 block text-[9px] font-bold uppercase tracking-wide text-sky-700">
                  Monitored region
                </span>
              )}
            </span>
            <span className="font-mono font-semibold">
              {item.count.toLocaleString()}
            </span>
          </button>
        ))}
      </div>
      <div className="mt-4 grid gap-3 border-t border-zinc-100 pt-4 sm:grid-cols-3">
        <div>
          <p className="text-[9px] font-bold uppercase tracking-widest text-zinc-400">
            Displayed volume
          </p>
          <p className="mt-1 font-mono text-sm font-semibold text-zinc-700">
            {total.toLocaleString()}
          </p>
        </div>
        <div>
          <p className="text-[9px] font-bold uppercase tracking-widest text-zinc-400">
            Map coverage
          </p>
          <p className="mt-1 font-mono text-sm font-semibold text-zinc-700">
            {total ? ((mappedTotal / total) * 100).toFixed(1) : "0.0"}%
          </p>
        </div>
        <div>
          <p className="text-[9px] font-bold uppercase tracking-widest text-zinc-400">
            Scale
          </p>
          <p className="mt-1 text-xs font-semibold text-zinc-700">
            Hub area by volume
          </p>
        </div>
      </div>
      {missing.length > 0 && (
        <p className="mt-3 text-[11px] text-zinc-500">
          Not positioned on the map:{" "}
          {missing.map((item) => item.name).join(", ")}.
        </p>
      )}
      <p className="mt-3 text-[11px] leading-5 text-zinc-500">
        Natural Earth public-domain boundaries are stored locally. Hubs and
        nearby points represent country-level deduplicated claims, not exact
        victim locations. Comparison arcs do not represent attack origin,
        infrastructure, actor movement, or network routing.
      </p>
    </section>
  );
}
