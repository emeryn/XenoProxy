/** @type {import('tailwindcss').Config} */

// Colours are declared flat rather than nested, so one token is exactly one
// class name: `bg-surface-raised`, not `bg-surface/raised`. Nesting would make
// two spellings generate the same utility.
const colors = {
  surface: 'var(--color-surface)',
  'surface-raised': 'var(--color-surface-raised)',
  'surface-sunken': 'var(--color-surface-sunken)',
  'surface-overlay': 'var(--color-surface-overlay)',
  'surface-hover': 'var(--color-surface-hover)',

  border: 'var(--color-border)',
  'border-strong': 'var(--color-border-strong)',
  'border-subtle': 'var(--color-border-subtle)',

  content: 'var(--color-content)',
  muted: 'var(--color-content-muted)',
  faint: 'var(--color-content-faint)',

  primary: 'var(--color-primary)',
  'primary-hover': 'var(--color-primary-hover)',
  'primary-content': 'var(--color-primary-content)',
  'primary-soft': 'var(--color-primary-soft)',
  'primary-border': 'var(--color-primary-border)',

  danger: 'var(--color-danger)',
  'danger-soft': 'var(--color-danger-soft)',
  'danger-border': 'var(--color-danger-border)',
  warning: 'var(--color-warning)',
  'warning-soft': 'var(--color-warning-soft)',
  'warning-border': 'var(--color-warning-border)',
  success: 'var(--color-success)',
  'success-soft': 'var(--color-success-soft)',
  'success-border': 'var(--color-success-border)',
  info: 'var(--color-info)',
  'info-soft': 'var(--color-info-soft)',
  'info-border': 'var(--color-info-border)',

  'verdict-malicious': 'var(--verdict-malicious)',
  'verdict-malicious-fg': 'var(--verdict-malicious-fg)',
  'verdict-suspicious': 'var(--verdict-suspicious)',
  'verdict-suspicious-fg': 'var(--verdict-suspicious-fg)',
  'verdict-clean': 'var(--verdict-clean)',
  'verdict-clean-fg': 'var(--verdict-clean-fg)',
  'verdict-unknown': 'var(--verdict-unknown)',
  'verdict-unknown-fg': 'var(--verdict-unknown-fg)',

  'accent-from': 'var(--color-accent-from)',
  'accent-to': 'var(--color-accent-to)',
};

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors,
      borderRadius: {
        sm: 'var(--radius-sm)',
        DEFAULT: 'var(--radius-md)',
        md: 'var(--radius-md)',
        lg: 'var(--radius-lg)',
        xl: 'var(--radius-xl)',
        pill: 'var(--radius-pill)',
      },
      boxShadow: {
        sm: 'var(--shadow-sm)',
        DEFAULT: 'var(--shadow-sm)',
        md: 'var(--shadow-md)',
        lg: 'var(--shadow-lg)',
        ring: 'var(--shadow-ring)',
        accent: 'var(--glow-accent)',
        focus: 'var(--focus-ring)',
      },
      fontFamily: {
        sans: 'var(--font-sans)',
        mono: 'var(--font-mono)',
      },
      fontSize: {
        xs: ['var(--text-xs)', { lineHeight: '1.45' }],
        sm: ['var(--text-sm)', { lineHeight: '1.5' }],
        base: ['var(--text-base)', { lineHeight: '1.55' }],
        lg: ['var(--text-lg)', { lineHeight: '1.5' }],
        xl: ['var(--text-xl)', { lineHeight: '1.35' }],
        '2xl': ['var(--text-2xl)', { lineHeight: '1.25' }],
        '3xl': ['var(--text-3xl)', { lineHeight: '1.15' }],
      },
      transitionTimingFunction: {
        out: 'var(--ease-out)',
        spring: 'var(--ease-spring)',
      },
      transitionDuration: {
        fast: 'var(--duration-fast)',
        base: 'var(--duration-base)',
        slow: 'var(--duration-slow)',
      },
      keyframes: {
        'fade-rise': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'none' },
        },
      },
      animation: {
        'fade-rise': 'fade-rise var(--duration-slow) var(--ease-out) both',
      },
    },
  },
  plugins: [],
};
