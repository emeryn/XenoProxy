/** Theme preference. Dark is the default; the choice is remembered per browser. */

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'xenoproxy.theme';

interface ThemeState {
  theme: Theme;
  setTheme: (theme: Theme) => void;
}

const ThemeContext = createContext<ThemeState | null>(null);

/** Dark is the product default; a stored choice overrides it. */
function readStoredTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') return stored;
  } catch {
    // Storage can be unavailable in a private window; the default then applies.
  }
  return 'dark';
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(readStoredTheme);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      window.localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // A failed write only costs the preference on the next visit.
    }
  }, [theme]);

  const value = useMemo<ThemeState>(
    () => ({ theme, setTheme: setThemeState }),
    [theme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeState {
  const context = useContext(ThemeContext);
  if (!context) throw new Error('useTheme must be used inside a ThemeProvider');
  return context;
}
