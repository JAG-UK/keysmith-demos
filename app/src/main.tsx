import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { WagmiProvider } from 'wagmi'
import { App } from './App.tsx'
import { loadNetworks } from './networks.ts'
import { makeConfig } from './wagmi.ts'
import './styles.css'

const networks = await loadNetworks()
const config = makeConfig(networks)
const queryClient = new QueryClient()

createRoot(document.getElementById('root') as HTMLElement).render(
  <StrictMode>
    <WagmiProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <App networks={networks} />
      </QueryClientProvider>
    </WagmiProvider>
  </StrictMode>
)
