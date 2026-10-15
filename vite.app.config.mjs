/** Dev server and build for the Keysmith demo app (app/). Devnet wiring is in lib/vite-devnet.mjs. */
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { devnet } from './lib/vite-devnet.mjs'

export default defineConfig({
  root: 'app',
  server: { port: Number(process.env.PORT ?? 5790) },
  build: { outDir: '../dist-app', emptyOutDir: true, target: 'es2022' },
  plugins: [react(), devnet()],
})
