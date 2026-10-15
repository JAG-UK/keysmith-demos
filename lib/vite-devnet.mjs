/**
 * Dev-server wiring shared by the browser demos (web/ and app/):
 *   /devnet.json     devnet-info.json without its users, so no private key reaches the page
 *   /rpc/v1          proxied to Lotus, which sends no CORS headers (Curio does, so it is called directly)
 *   @filoz/keysmith  the package source from a synapse-sdk checkout, not a copy
 *
 * With no devnet running, /devnet.json answers 404 and the pages offer only the public networks.
 */
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { validateDevnetInfo } from '@filoz/synapse-core/devnet'

const infoPath = process.env.DEVNET_INFO_PATH ?? join(homedir(), '.foc-devnet', 'state', 'latest', 'devnet-info.json')
const readInfo = () => (existsSync(infoPath) ? validateDevnetInfo(JSON.parse(readFileSync(infoPath, 'utf8'))) : null)
export const keysmithDir = resolve(process.env.KEYSMITH_DIR ?? '../../synapse-sdk/packages/keysmith')

export function devnet() {
  return {
    name: 'devnet',
    config() {
      // ponytail: Lotus's address is read once; restart the dev server after a devnet restart
      const lotus = readInfo()?.info.lotus.host_rpc_url
      return {
        resolve: { alias: { '@filoz/keysmith': join(keysmithDir, 'src/index.ts') }, dedupe: ['viem'] },
        server: {
          fs: { allow: ['.', resolve(keysmithDir, '../..')] },
          ...(lotus ? { proxy: { '/rpc': new URL(lotus).origin } } : {}),
        },
      }
    },
    configureServer(server) {
      server.middlewares.use('/devnet.json', (_req, res) => {
        const devnetInfo = readInfo()
        if (!devnetInfo) {
          res.statusCode = 404
          res.end('no devnet running')
          return
        }
        const { users: _keys, ...info } = devnetInfo.info
        res.setHeader('content-type', 'application/json')
        res.end(JSON.stringify({ info }))
      })
    },
  }
}
