/** @type {import('tailwindcss').Config} */
import defaultColors from 'tailwindcss/colors'
import plugin from 'tailwindcss/plugin'

/*
 * Theme-relative palette.
 *
 * Every colour class resolves to a CSS variable, so one set of classes renders
 * both themes. Shades are *relative to the theme*: `slate-100` is always the
 * strongest foreground, `slate-800` always a hairline, `ink-900` always the
 * panel surface. In light mode the status hues (red, emerald, …) are mirrored
 * (300 ↔ 700) so `text-red-300` stays legible on white.
 */

const SHADES = ['50', '100', '200', '300', '400', '500', '600', '700', '800', '900', '950']
const mirror = (s) => (s === '50' ? '950' : s === '950' ? '50' : String(1000 - Number(s)))

const hexToChannels = (hex) => {
  const h = hex.replace('#', '')
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)).join(' ')
}

// Cool graphite neutrals (foreground + lines). Index = shade.
const NEUTRAL = {
  light: {
    50: '#0b0d14', 100: '#151925', 200: '#252a37', 300: '#3b4150', 400: '#565d6d', 500: '#767d8c',
    600: '#9da3b0', 700: '#c9ced7', 800: '#dfe2e8', 900: '#eceef2', 950: '#f5f6f8',
  },
  dark: {
    50: '#ffffff', 100: '#eceef3', 200: '#d7dae2', 300: '#b6bbc7', 400: '#8d94a3', 500: '#6a7181',
    600: '#4b5161', 700: '#353a46', 800: '#272b35', 900: '#1b1e26', 950: '#121419',
  },
}

// Surfaces. 950 = canvas/sunken, 900 = panel, 850 = card, 800 = raised/hover, 700 = track.
const INK = {
  light: { 950: '#f1f2f5', 900: '#ffffff', 850: '#fafbfc', 800: '#eef0f4', 700: '#e2e5eb', 600: '#c9ced7' },
  dark: { 950: '#0f1115', 900: '#16181e', 850: '#1a1d24', 800: '#21242d', 700: '#2b2f3a', 600: '#3b404d' },
}

// Ultramarine: the single accent. Mirrored per theme so 300 = accent text.
const ACCENT = {
  light: {
    50: '#0f1150', 100: '#161a78', 200: '#1f249c', 300: '#2c31c4', 400: '#2f34cc', 500: '#3b40dc',
    600: '#6e72ea', 700: '#a3a6f3', 800: '#c9cbf8', 900: '#e4e5fc', 950: '#f2f2fe',
  },
  dark: {
    50: '#f2f2ff', 100: '#e2e3ff', 200: '#c7c9ff', 300: '#a8abff', 400: '#7b7fff', 500: '#666bf2',
    600: '#5e62e6', 700: '#4044b8', 800: '#2c2f86', 900: '#1d1f57', 950: '#121335',
  },
}

const STATUS_HUES = ['red', 'rose', 'orange', 'yellow', 'amber', 'lime', 'emerald', 'sky', 'violet']

function varsFor(theme) {
  const vars = {}
  for (const s of Object.keys(NEUTRAL[theme])) vars[`--c-slate-${s}`] = hexToChannels(NEUTRAL[theme][s])
  for (const s of Object.keys(INK[theme])) vars[`--c-ink-${s}`] = hexToChannels(INK[theme][s])
  for (const s of Object.keys(ACCENT[theme])) vars[`--c-accent-${s}`] = hexToChannels(ACCENT[theme][s])
  for (const hue of STATUS_HUES) {
    for (const s of SHADES) {
      const src = theme === 'light' ? mirror(s) : s
      vars[`--c-${hue}-${s}`] = hexToChannels(defaultColors[hue][src])
    }
  }
  // "white" is the strongest foreground; on light it is ink.
  vars['--c-white'] = theme === 'light' ? hexToChannels('#0b0d14') : '255 255 255'
  return vars
}

const scale = (name, shades) =>
  Object.fromEntries(shades.map((s) => [s, `rgb(var(--c-${name}-${s}) / <alpha-value>)`]))

export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    colors: {
      transparent: 'transparent',
      current: 'currentColor',
      white: 'rgb(var(--c-white) / <alpha-value>)',
      black: '#000',
      slate: scale('slate', SHADES),
      ink: scale('ink', ['950', '900', '850', '800', '700', '600']),
      accent: scale('accent', SHADES),
      ...Object.fromEntries(STATUS_HUES.map((h) => [h, scale(h, SHADES)])),
    },
    extend: {
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        float: '0 12px 32px -12px rgb(0 0 0 / 0.28), 0 2px 6px -2px rgb(0 0 0 / 0.12)',
      },
    },
  },
  plugins: [
    plugin(({ addBase }) => {
      addBase({ ':root': varsFor('light'), '.dark': varsFor('dark') })
    }),
  ],
}
