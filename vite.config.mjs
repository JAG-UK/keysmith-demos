/** Dev server for the single-page browser demo (web/). Devnet wiring is in lib/vite-devnet.mjs. */
import { defineConfig } from 'vite'
import { devnet } from './lib/vite-devnet.mjs'

export default defineConfig({
  root: 'web',
  server: { port: Number(process.env.PORT ?? 5780) },
  plugins: [devnet()],
})
