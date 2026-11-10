import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Link, type LinkProps } from "react-router";

/**
 * LogLens's structural primitives, trimmed to what soc-triage has data for.
 *
 * `PageHead` is the single biggest borrow: an eyebrow, a large title, a
 * subtitle and a right-hand slot, sitting in a sticky view header. It is what
 * makes the three views read as the same design system as LogLens.
 */

export function PageHead({
  eyebrow,
  title,
  subtitle,
  right,
}: {
  eyebrow?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="min-w-0">
        {eyebrow && (
          <div className="mb-2.5 flex items-center gap-2 text-eyebrow font-medium uppercase text-text-dim">
            {eyebrow}
          </div>
        )}
        <h1 className="mb-1.5 text-h-page font-semibold text-text">{title}</h1>
        {subtitle && (
          <p className="max-w-[560px] text-subtitle text-text-mid">{subtitle}</p>
        )}
      </div>
      {right && <div className="flex shrink-0 items-center gap-4">{right}</div>}
    </div>
  );
}

/**
 * The sticky view header and the body under it -- LogLens's page rhythm:
 * 32/48/24 header on the app background with a soft rule, then a 28/48/40
 * body stacking sections 28px apart.
 */
export function ViewHeader({ children }: { children: ReactNode }) {
  return (
    <div className="sticky top-0 z-10 border-b border-line-soft bg-bg-app px-12 pb-6 pt-8">
      {children}
    </div>
  );
}

export function ViewBody({ children }: { children: ReactNode }) {
  return <div className="flex flex-col gap-7 px-12 pb-10 pt-7">{children}</div>;
}

/** 11px uppercase label with a trailing rule. */
export function SectionTitle({
  children,
  count,
  right,
  as: Tag = "h2",
}: {
  children: ReactNode;
  count?: ReactNode;
  right?: ReactNode;
  as?: "h2" | "h3";
}) {
  return (
    <div className="flex items-center gap-3">
      <Tag className="shrink-0 text-section font-medium uppercase text-text-dim">
        {children}
      </Tag>
      {count !== undefined && (
        <span className="shrink-0 font-mono text-label text-text-dim">{count}</span>
      )}
      <span aria-hidden="true" className="h-px flex-1 bg-line-soft" />
      {right && <div className="flex shrink-0 items-center gap-3">{right}</div>}
    </div>
  );
}

export type BtnVariant = "default" | "ghost" | "primary";

/** 11px uppercase 0.12em 600, 8px 14px, square, 1px rule. */
export function btnClass(variant: BtnVariant = "default"): string {
  const base =
    "inline-flex shrink-0 items-center gap-2 rounded-control border px-3.5 py-2 text-btn font-semibold uppercase transition-colors disabled:cursor-not-allowed disabled:opacity-40";
  switch (variant) {
    case "primary":
      return `${base} border-accent bg-accent text-on-accent hover:border-accent-hover hover:bg-accent-hover`;
    case "ghost":
      return `${base} border-transparent bg-transparent text-text-mid hover:text-text`;
    default:
      return `${base} border-line bg-transparent text-text hover:bg-card`;
  }
}

export function Btn({
  variant,
  className = "",
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant }) {
  return (
    <button type={type} className={`${btnClass(variant)} ${className}`} {...props} />
  );
}

/** A navigation that looks like a button. Only for real destinations. */
export function BtnLink({
  variant,
  className = "",
  ...props
}: LinkProps & { variant?: BtnVariant }) {
  return <Link className={`${btnClass(variant)} ${className}`} {...props} />;
}
