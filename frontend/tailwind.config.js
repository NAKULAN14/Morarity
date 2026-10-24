/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: {
          main: '#07090B',
          secondary: '#0C1013',
          elevated: '#11171B',
          surface: '#151D22',
        },
        border: {
          subtle: '#1B2328',
          DEFAULT: '#222B30',
          focus: '#324048',
        },
        text: {
          primary: '#E8EEF0',
          secondary: '#8B989E',
          muted: '#536168',
        },
        verified: {
          DEFAULT: '#39E58C',
          bg: '#0B2418',
          border: 'rgba(57, 229, 140, 0.25)',
          glow: 'rgba(57, 229, 140, 0.15)',
        },
        rejected: {
          DEFAULT: '#FF5B64',
          bg: '#2B1014',
          border: 'rgba(255, 91, 100, 0.25)',
          glow: 'rgba(255, 91, 100, 0.15)',
        },
        inconclusive: {
          DEFAULT: '#FFBE55',
          bg: '#2A2010',
          border: 'rgba(255, 190, 85, 0.25)',
          glow: 'rgba(255, 190, 85, 0.15)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'Geist', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Geist Mono', 'Consolas', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'subtle-glow-verified': '0 0 20px -5px rgba(57, 229, 140, 0.2)',
        'subtle-glow-rejected': '0 0 20px -5px rgba(255, 91, 100, 0.2)',
        'subtle-glow-amber': '0 0 20px -5px rgba(255, 190, 85, 0.2)',
      },
    },
  },
  plugins: [],
}
