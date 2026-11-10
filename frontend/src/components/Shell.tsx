import type { ReactNode } from "react";
import { Link, useLocation } from "react-router";

/**
 * Icon rail + window toolbar.
 *
 * The mockup draws this inside a 1400px window shell on a hatched desk. That
 * shell is presentation chrome for the PNG: here the content fills the viewport
 * and keeps the 1400px ceiling, exactly as DESIGN.md says to.
 *
 * The rail carries the logo tile and one nav link per real destination: the
 * queue and ingest. The rule was never "one button" -- it was "no dead
 * controls". The mockup's other four icons would still be dead, so they stay
 * out.
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

function RailLink({
  to,
  label,
  active,
  children,
}: {
  to: string;
  label: string;
  active: boolean;
  children: ReactNode;
}) {
  return (
    <Link
      to={to}
      aria-label={label}
      aria-current={active ? "page" : undefined}
      title={label}
      className={`flex size-8 items-center justify-center rounded-sunken border transition-colors ${
        active
          ? "border-accent-hair bg-accent-tint text-accent"
          : "border-transparent text-ink-faint hover:border-edge hover:bg-raised hover:text-ink"
      }`}
    >
      {children}
    </Link>
  );
}

function Crumb({ children, muted }: { children: ReactNode; muted?: boolean }) {
  return (
    <span className={muted ? "text-ink-faint" : "text-ink"}>{children}</span>
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

  return (
    <div className="flex h-full bg-panel">
      {/* Icon rail -- 54px */}
      <nav
        aria-label="Sections"
        className="flex w-rail shrink-0 flex-col items-center gap-2 border-r border-hair-1 bg-rail py-3"
      >
        <Link
          to="/"
          aria-label="SOC Triage - incident queue"
          className="flex size-[30px] items-center justify-center rounded-control bg-ink text-raised"
        >
          {/* Shield: the one piece of brand in the app. */}
          <svg
            viewBox="0 0 24 24"
            className="size-[15px]"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M12 3l7 3v5.5c0 4.2-2.9 7.9-7 9-4.1-1.1-7-4.8-7-9V6l7-3z" />
          </svg>
        </Link>

        <div className="mt-1 flex flex-col gap-1.5">
          <RailLink to="/" label="Incident queue" active={section === "queue"}>
            <svg
              viewBox="0 0 24 24"
              className="size-4"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <path d="M4 7h16M4 12h11M4 17h7" />
            </svg>
          </RailLink>
          <RailLink
            to="/ingest"
            label="Ingest a log file"
            active={section === "ingest"}
          >
            {/* Arrow into a tray: a file going in. */}
            <svg
              viewBox="0 0 24 24"
              className="size-4"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M12 4v10M8 10l4 4 4-4" />
              <path d="M4 14v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4" />
            </svg>
          </RailLink>
        </div>
      </nav>

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Window toolbar -- 38px */}
        <header className="flex h-toolbar shrink-0 items-center gap-3 border-b border-hair-1 bg-rail px-4">
          <div className="flex items-center gap-1.5" aria-hidden="true">
            <span className="size-[9px] rounded-full bg-[#D6D2CC]" />
            <span className="size-[9px] rounded-full bg-[#D6D2CC]" />
            <span className="size-[9px] rounded-full bg-[#D6D2CC]" />
          </div>
          <div className="ml-2 flex min-w-0 items-center gap-1.5 text-meta">
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
