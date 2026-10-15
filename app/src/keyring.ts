import * as Keysmith from '@filoz/keysmith'
import type { Address, Hex } from 'viem'

export type KeyspaceKeys = Awaited<ReturnType<typeof Keysmith.keyspaceKeys>>

/**
 * Keysmith checks a new keyspace's signer by signing twice. Across page loads
 * the app remembers, per address, that this wallet has passed, so later new
 * keyspaces cost one prompt. Existing keyspaces never need it: their dataset's
 * commitment checks the key instead.
 */
const vettedKey = (owner: Address) => `keysmith:vetted:${owner.toLowerCase()}`
function vetted(owner: Address): boolean {
  try {
    return localStorage.getItem(vettedKey(owner)) === '1'
  } catch {
    return false
  }
}
function markVetted(owner: Address): void {
  try {
    localStorage.setItem(vettedKey(owner), '1')
  } catch {
    // a private window: the next page load checks again, at the cost of one prompt
  }
}

/** The owner's keyspace keys, in this tab's memory only. One signature per keyspace. */
export class Keyring {
  readonly keyspaces = new Map<Hex, KeyspaceKeys>()

  constructor(
    readonly owner: Address,
    private readonly signer: Keysmith.TypedDataSigner,
    private readonly announce: (text: string) => void
  ) {}

  /** `commitment`, for an existing keyspace: sign once, and let the dataset's `foc/kc` check the key. */
  async keysFor(keyspace: Hex, commitment?: string): Promise<KeyspaceKeys> {
    const held = this.keyspaces.get(keyspace)
    if (held) return held
    const once = commitment != null || vetted(this.owner)
    const which = `keyspace ${keyspace.slice(0, 10)}…`
    this.announce(
      once
        ? `sign KeyspaceKey for ${which}`
        : `sign KeyspaceKey for ${which} twice: the first time, Keysmith checks your wallet gives the same signature both times`
    )
    const options = commitment != null ? { commitment } : vetted(this.owner) ? { verifySigner: false } : {}
    const keys = await Keysmith.keyspaceKeys(this.signer, { owner: this.owner, keyspace }, options)
    markVetted(this.owner)
    this.keyspaces.set(keyspace, keys)
    return keys
  }

  forget(): void {
    this.keyspaces.clear()
  }
}

/** What the wallet is shown when it signs for a keyspace. */
export const keyspaceRequest = (owner: Address, keyspace: Hex) => ({
  domain: Keysmith.DOMAIN,
  types: Keysmith.KEYSPACE_KEY_TYPES,
  primaryType: 'KeyspaceKey' as const,
  message: Keysmith.keyspaceKeyMessage({ owner, keyspace }),
})
