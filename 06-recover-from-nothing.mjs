/**
 * 6. Recovery from nothing but the wallet.
 *
 * Delete every local file, every grant, every note. With the payer's wallet and
 * the chain, each dataset key comes back: the chain lists the datasets and
 * their clientDataSetIds, the wallet re-signs, and foc/kc proves the key is the
 * right one before any decryption is attempted.
 *
 * This demo reads NOTHING from out/state.json.
 */
import { getAllDataSetMetadata, getClientDataSets } from '@filoz/synapse-core/warm-storage'
import { decrypt, parseEnvelope } from 'foc-encryption'
import { clientFor, devnet, note, step } from './lib/devnet.mjs'
import * as Keys from './lib/keys.mjs'
import * as Trace from './lib/trace.mjs'
import { getPiece, listPiecesOnChain } from './lib/store.mjs'

const { chain, sp, users } = devnet()
const payer = users[0]
const client = clientFor(payer.private_key_hex, chain)

step('Ask the chain what this wallet pays for')
const page = await getClientDataSets(client, { address: payer.evm_addr })
note(`${page.items.length} dataset(s) for ${payer.evm_addr}`)

for (const info of page.items) {
  const { dataSetId, clientDataSetId } = info
  step(`Dataset ${dataSetId} — clientDataSetId ${clientDataSetId}`)

  const metadata = await getAllDataSetMetadata(client, { dataSetId: BigInt(dataSetId) })
  const kc = metadata['foc/kc']
  if (kc == null) {
    note('no foc/kc — not an encrypted dataset, skipping')
    continue
  }

  note('re-signing DatasetKey from the wallet alone')
  const { dk: DK, commitment: recomputed } = await Keys.datasetKeys(client.account, {
    chainId: chain.id,
    service: chain.contracts.fwss.address,
    payer: payer.evm_addr,
    clientDataSetId: BigInt(clientDataSetId),
  })

  note(`foc/kc on chain   ${kc}`)
  note(`foc/kc recomputed ${recomputed}`)
  if (recomputed !== kc) {
    note('MISMATCH — wrong wallet or a non-deterministic signer. Stopping loudly, not decrypting garbage.')
    continue
  }
  note('match: this is the right key, before a single byte is decrypted')

  const pieces = await listPiecesOnChain(client, dataSetId)
  note(`${pieces.length} live piece(s), listed from PDPVerifier`)
  for (const piece of pieces) {
    const blob = await getPiece(sp.serviceURL, piece.pieceCid)
    Trace.envelope(blob, `piece ${piece.pieceId}`)
    let appMetadata
    try {
      ;({ appMetadata } = parseEnvelope(blob))
    } catch {
      note(`  piece ${piece.pieceId} — not a FEE envelope (plaintext piece), skipping`)
      continue
    }
    const scope = appMetadata['foc/scope'] ?? '/'
    const text = new TextDecoder().decode(await decrypt(blob, Keys.keyForEnvelope(DK, appMetadata)))
    note(`  piece ${piece.pieceId} [${scope}] → "${text.slice(0, 44)}…"`)
  }
}

console.log('\nNo keystore, no backup file, no service. A wallet and a public chain were enough.')
