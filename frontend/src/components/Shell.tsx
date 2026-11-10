import { useState, type ReactNode } from "react";
import { Link, useLocation } from "react-router";
import { ChevronsLeft, ListOrdered, Upload, type LucideIcon } from "lucide-react";

/**
 * Collapsible icon rail + toolbar, in LogLens's layout.
 *
 * The rail carries one nav link per real destination -- the queue and ingest
 * -- and nothing else. The rule was never "one button", it was "no dead
 * controls": the mockup's other four icons would still do nothing, so they
 * stay out. With two destinations the collapsible rail earns itself; labels
 * are worth revealing when there is more than one place to go.
 *
 * The width transition is the one piece of motion in the app, and it is plain
 * CSS (reduced-motion users get none; see index.css).
 */

type Section = "queue" | "ingest";

/**
 * Which rail item the current route belongs to, derived from the location
 * rather than passed in by each view. The detail route belongs to the queue --
 * it is reached from a queue row and its breadcrumb leads back there -- and so
 * does the `*` fallback, which renders the queue.
 */
function sectionFor(pathname: string): Section {
  return pathname === "/ingest" || pathname.startsWith("/ingest/")
    ? "ingest"
    : "queue";
}

const EASE = "duration-300 ease-[cubic-bezier(0.4,0,0.2,1)]";

/**
 * Labels open after the rail has started widening and vanish before it
 * narrows, LogLens's stagger, so text never wraps inside a half-open rail.
 */
function labelMotion(expanded: boolean): string {
  return expanded
    ? "max-w-40 opacity-100 [transition:opacity_0.18s_ease_0.15s,max-width_0.3s_cubic-bezier(0.4,0,0.2,1)]"
    : "max-w-0 opacity-0 [transition:opacity_0.08s_ease,max-width_0.3s_cubic-bezier(0.4,0,0.2,1)]";
}

function BrandMark() {
  // Two interlocking blocks, one ink and one accent. Drawn bare rather than on
  // a filled tile, because half of it *is* the accent and would vanish on an
  // accent tile. Fills read the theme tokens so the mark follows the palette.
  return (
    <svg
      viewBox="0 0 64 64"
      className="size-[34px] shrink-0"
      fill="none"
      shapeRendering="crispEdges"
      aria-hidden="true"
    >
      <path d="M6 6 H22 V40 H40 V54 H6 Z" fill="var(--color-text)" />
      <path d="M58 58 H42 V24 H24 V10 H58 Z" fill="var(--color-accent)" />
    </svg>
  );
}

function RailLink({
  to,
  label,
  icon: Icon,
  active,
  expanded,
}: {
  to: string;
  label: string;
  icon: LucideIcon;
  active: boolean;
  expanded: boolean;
}) {
  return (
    <Link
      to={to}
      aria-current={active ? "page" : undefined}
      // Collapsed, the label is clipped to zero width; title keeps the name
      // discoverable on hover. The accessible name is the label text itself.
      title={expanded ? undefined : label}
      className={`flex h-11 shrink-0 items-center overflow-hidden transition-[background-color,color,width,padding,gap] ${EASE} ${
        expanded ? "w-full gap-2.5 pl-3.5" : "w-11 gap-0 pl-[11px]"
      } ${
        active
          ? "bg-accent text-on-accent shadow-[0_6px_16px_-6px_rgba(75,108,246,0.6)]"
          : "text-text-dim hover:bg-panel hover:text-text"
      }`}
    >
      <Icon className="size-[22px] shrink-0" strokeWidth={1.6} aria-hidden="true" />
      <span
        className={`overflow-hidden whitespace-nowrap text-subtitle font-medium tracking-[-0.01em] ${labelMotion(expanded)}`}
      >
        {label}
      </span>
    </Link>
  );
}

function Crumb({ children, muted }: { children: ReactNode; muted?: boolean }) {
  return (
    <span className={muted ? "text-text-dim" : "text-text"}>{children}</span>
  );
}

export function Shell({
  breadcrumb,
  actions,
  children,
}: {
  breadcrumb: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const section = sectionFor(useLocation().pathname);
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="flex h-full bg-bg-app">
      <nav
        aria-label="Sections"
        className={`flex shrink-0 flex-col overflow-hidden bg-rail py-5 transition-[width] ${EASE} ${
          expanded ? "w-rail-expanded" : "w-rail"
        }`}
      >
        {/* Logo row: the tile expands the rail when collapsed (LogLens's
            pattern), and a chevron collapses it again. Both are real
            controls with aria-expanded, not decoration. */}
        <div
          className={`mb-5 flex shrink-0 items-center transition-[padding] ${EASE} ${
            expanded ? "pl-4 pr-2.5" : "pl-[17px]"
          }`}
        >
          <button
            type="button"
            onClick={expanded ? undefined : () => setExpanded(true)}
            aria-label={expanded ? undefined : "Expand navigation"}
            aria-expanded={expanded ? undefined : false}
            tabIndex={expanded ? -1 : 0}
            aria-hidden={expanded || undefined}
            className={`flex shrink-0 items-center gap-2.5 ${
              expanded ? "cursor-default" : "cursor-pointer"
            }`}
          >
            <BrandMark />
            <span
              className={`overflow-hidden whitespace-nowrap text-[14px] font-bold tracking-[-0.02em] text-text ${labelMotion(expanded)}`}
            >
              SOC Triage
            </span>
          </button>

          <button
            type="button"
            onClick={() => setExpanded(false)}
            aria-label="Collapse navigation"
            aria-expanded={expanded}
            tabIndex={expanded ? 0 : -1}
            aria-hidden={!expanded}
            className={`ml-auto flex size-7 shrink-0 items-center justify-center text-text-dim hover:text-text ${
              expanded
                ? "opacity-100 [transition:opacity_0.18s_ease_0.15s]"
                : "pointer-events-none opacity-0 [transition:opacity_0.08s_ease]"
            }`}
          >
            <ChevronsLeft className="size-4" strokeWidth={1.8} aria-hidden="true" />
          </button>
        </div>

        <div className="flex flex-col gap-1.5 px-3">
          <RailLink
            to="/"
            label="Incident queue"
            icon={ListOrdered}
            active={section === "queue"}
            expanded={expanded}
          />
          <RailLink
            to="/ingest"
            label="Ingest a log file"
            icon={Upload}
            active={section === "ingest"}
            expanded={expanded}
          />
        </div>
      </nav>

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Toolbar -- 38px. No window-chrome dots: LogLens has no window
            metaphor, and they were decoration. */}
        <header className="flex h-toolbar shrink-0 items-center gap-3 border-b border-line-soft bg-rail px-6">
          <div className="flex min-w-0 items-center gap-1.5 text-meta">
            {breadcrumb}
          </div>
          <div className="ml-auto flex items-center gap-3">{actions}</div>
        </header>

        <main className="min-h-0 flex-1 overflow-auto">
          <div className="mx-auto w-full max-w-ceiling">{children}</div>
        </main>
      </div>
    </div>
  );
}

export { Crumb };
