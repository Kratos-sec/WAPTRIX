import { useCallback, useEffect, useState } from 'react'

const KEY = 'waptrix-theme'

export function useTheme() {
  const [theme, setTheme] = useState(() => (document.documentElement.classList.contains('dark') ? 'dark' : 'light'))
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
  }, [theme])
  const toggle = useCallback(() => {
    setTheme((t) => {
      const next = t === 'dark' ? 'light' : 'dark'
      try { localStorage.setItem(KEY, next) } catch { /* storage unavailable */ }
      return next
    })
  }, [])
  return [theme, toggle]
}

// Chart colours as CSS-variable strings, so SVG marks follow the active theme.
export const chartColor = (token, alpha = 1) => `rgb(var(--c-${token}) / ${alpha})`
export const CHART = {
  grid: chartColor('slate-800'),
  tick: chartColor('slate-400'),
  tickMuted: chartColor('slate-500'),
  track: chartColor('ink-700'),
  cursor: chartColor('slate-500', 0.08),
}
