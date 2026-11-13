/**
 * The XenoProxy mark: a shield holding a wireframe globe, read through a
 * magnifying glass, wired into a circuit.
 *
 * Drawn as inline SVG rather than shipped as an image so it stays crisp at any
 * size, costs no request, and follows the theme. The shield and the globe take
 * the brand gradient; the glass takes the current text colour, which is what
 * keeps it legible in both themes where a fixed white would disappear on a
 * light surface. A knockout stroke under the glass separates it from the globe
 * behind, the way the lens does in the full logo.
 */

import { useId } from 'react';

const GRADIENT_FROM = '#1ddf6e';
const GRADIENT_TO = '#20c6e8';

export function LogoMark({
  size = 28,
  className,
  title,
}: {
  size?: number;
  className?: string;
  title?: string;
}) {
  // Two marks on one page must not share a gradient id. `useId` is stable
  // across renders, which a module-level counter is not: StrictMode renders
  // twice and would hand the same element two different ids.
  const gradientId = useId().replace(/:/g, '');

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      className={className}
      role={title ? 'img' : 'presentation'}
      aria-hidden={title ? undefined : true}
      aria-label={title}
    >
      {title ? <title>{title}</title> : null}
      <defs>
        <linearGradient id={gradientId} x1="9" y1="60" x2="55" y2="4" gradientUnits="userSpaceOnUse">
          <stop stopColor={GRADIENT_FROM} />
          <stop offset="1" stopColor={GRADIENT_TO} />
        </linearGradient>
        {/* The globe is drawn as a full sphere and cropped to the shield, so
            its lines meet the edge instead of floating inside it. */}
        <clipPath id={`${gradientId}-shield`}>
          <path d="M32 4.5 54.5 12.2V31C54.5 44 45 53.9 32 59 19 53.9 9.5 44 9.5 31V12.2Z" />
        </clipPath>
      </defs>

      <g stroke={`url(#${gradientId})`} strokeWidth="2.1" strokeLinejoin="round">
        <path d="M32 4.5 54.5 12.2V31C54.5 44 45 53.9 32 59 19 53.9 9.5 44 9.5 31V12.2Z" />
      </g>

      <g
        clipPath={`url(#${gradientId}-shield)`}
        stroke={`url(#${gradientId})`}
        strokeWidth="1.5"
        opacity="0.95"
      >
        {/* Meridians and parallels: a globe is recognisable from very few of
            each, and more would turn to mush at sixteen pixels. */}
        <circle cx="31" cy="30" r="15.5" />
        <ellipse cx="31" cy="30" rx="6.6" ry="15.5" />
        <path d="M15.5 30h31M18.2 21.4h25.6M18.2 38.6h25.6" />
      </g>

      {/* Traces leaving the shield on both sides. They are drawn outside the
          clip so they read as connections rather than as part of the globe. */}
      <g stroke={`url(#${gradientId})`} strokeWidth="1.3" strokeLinecap="round" fill="none">
        <path d="M9 24H3.5M9 40H5M55 20h5M55 36h4.5" />
      </g>
      <g fill={`url(#${gradientId})`}>
        <circle cx="2.4" cy="24" r="1.7" />
        <circle cx="3.9" cy="40" r="1.4" />
        <circle cx="60.8" cy="20" r="1.7" />
        <circle cx="60.3" cy="36" r="1.4" />
        <circle cx="50" cy="8" r="1.3" />
        <circle cx="14" cy="55" r="1.3" />
      </g>

      {/* Knockout first, glass second: the pair reads as a lens in front of the
          globe rather than as lines crossing it. */}
      <g fill="none" strokeLinecap="round">
        <g stroke="var(--color-surface)" strokeWidth="6.5">
          <circle cx="36.5" cy="34.5" r="10" />
          <path d="M43.8 41.8 52 50" />
        </g>
        <g stroke="currentColor" strokeWidth="3.2">
          <circle cx="36.5" cy="34.5" r="10" />
          <path d="M43.8 41.8 52 50" />
        </g>
      </g>
    </svg>
  );
}

export function LogoLockup({ size = 40, tagline }: { size?: number; tagline?: boolean }) {
  return (
    <span className="flex items-center gap-3">
      <LogoMark size={size} title="XenoProxy" />
      <span className="flex flex-col">
        <span
          style={{ fontSize: size * 0.52, fontWeight: 700, letterSpacing: '-0.02em', lineHeight: 1.1 }}
        >
          {/* Two words, two weights of the brand: the wordmark is split the way
              the shield is, green half and light half. */}
          <span
            className="bg-clip-text text-transparent"
            style={{ backgroundImage: `linear-gradient(100deg, ${GRADIENT_FROM}, ${GRADIENT_TO})` }}
          >
            Xeno
          </span>
          <span className="text-content">Proxy</span>
        </span>
        {tagline ? (
          <span
            className="text-faint"
            style={{ fontSize: size * 0.2, letterSpacing: '0.14em', lineHeight: 1.4 }}
          >
            SECURE OPEN-SOURCE OSINT PROXY
          </span>
        ) : null}
      </span>
    </span>
  );
}
