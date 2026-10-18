# The demo app: how it fits together

```
 ┌─ Browser ──────────────────────────────────────────────────────────────────────────┐
 │                                                                                    │
 │   Owner's wallet                         Agents (session keys)                     │
 │   signs KeyspaceKey (EIP-712)            secp256k1 key + CBOR grants               │
 │        │                                     │                                     │
 │        ▼                                     ▼                                     │
 │  ┌─ @filoz/keysmith ──────────────────────────────────────────────────────────┐    │
 │  │ wallet signature → keyspace key → scope keys → piece keys (HKDF)           │    │
 │  │ grants: wrap / unwrap a scope key to a secp256k1 key                       │    │
 │  │ envelope labels ⇄ piece key                                                │    │
 │  └──────┬─────────────────────────────────────────────▲───────────────────────┘    │
 │      piece key + labels                      labels in, key out                    │
 │         ▼                                             │                            │
 │  ┌─ FEE (filecoin-encryption-envelope) ───────────────┴───────────────────────┐    │
 │  │ plaintext ⇄ envelope: COSE header (labels authenticated)                   │    │
 │  │           + AES-GCM chunks                                                 │    │
 │  └──────┬─────────────────────────────────────────────▲───────────────────────┘    │
 │      opaque bytes                               opaque bytes                       │
 │         ▼                                             │                            │
 │  ┌─ app/src/storage.ts (thin) ────────────────────────┴───────────────────────┐    │
 │  │ store(): upload, then confirm by the add-pieces receipts                   │    │
 │  │ keyspacePieces(): datasets recording this foc/ks → piece CIDs              │    │
 │  └──────┬─────────────────────────────────────────────▲───────────────────────┘    │
 │         ▼                                             │                            │
 │  ┌─ Synapse SDK ──────────────────────────────────────┴───────────────────────┐    │
 │  │ storage.upload(bytes, { metadata: { foc/ks, foc/kc } })                    │    │
 │  │ storage.download({ pieceCid })   payments   session-key signing            │    │
 │  └──────┬─────────────────────────────────────────────┬───────────────────────┘    │
 └─────────┼─────────────────────────────────────────────┼────────────────────────────┘
           ▼                                             ▼
   Storage providers (Curio)                 Chain: FWSS · PDPVerifier · SessionKeyRegistry
   picked by Synapse; hold ciphertext        datasets + metadata, pieces, agent authorizations
```

**Synapse never sees a key, a grant or plaintext. Keysmith never sees a provider, a dataset or a piece CID.**
The only things that cross between them are two dataset metadata strings and the labels inside each envelope.

## What goes into Synapse

| Call | What the app passes | Who calls it |
| --- | --- | --- |
| `storage.upload` | FEE ciphertext, plus dataset metadata `{foc/ks: keyspace, foc/kc: commitment}`. Synapse picks the providers, makes the copies and reuses datasets with exactly this metadata. | owner (wallet), agents (session key) |
| `storage.download` | a piece CID; Synapse finds a provider holding it | every read |
| `payments.*` | deposit and Warm Storage approval, once | owner |
| `Synapse.create({ sessionKey })` | the agent's session key, with the owner as the account | agents |

Synapse already does everything else: choosing providers, repair, the datasets themselves, and CDN.

## What the app has to know about Keysmith

1. **Get the keyspace key.** `keyspaceKeys(wallet, { owner, keyspace }, { commitment? })` returns `{ kk, commitment, descriptor }`. It costs one signature, or two for a brand-new keyspace. Keep `kk` in memory only.
2. **Record two strings.** Store `KEYSPACE_ID_KEY → keyspace` and `COMMITMENT_KEY → commitment` as dataset metadata. That is all that goes on chain, and recovery starts from it.
3. **Write a piece.**
   - `target = writeTarget(descriptor or grant, key)`; `salt = newSalt()`.
   - The piece key is `pieceKey(target.key, salt)`; that is the CEK for FEE.
   - The envelope labels are `pieceMetadata(target.ref, { salt, scope })`; they become FEE's `appMetadata`.
4. **Read a piece.** `fee.decrypt(keyResolver(heldKey, holding))`. Keysmith reads the labels and derives the key, or refuses.
5. **Delegate.**
   - Owner: `encodeGrant(wrapTo(publicKeyOf(agentKey), scopeKey(kk, scope), grantDescriptor(…)))`, which returns bytes.
   - Agent: `unwrapWith(privateKey, decodeGrant(bytes))`.
   - Delivering the bytes is the app's job; here they go to localStorage.

## The three flows

- **Write.** Keysmith derives the piece key and labels → FEE encrypts → `store()` → Synapse uploads with the keyspace metadata.
- **Read or recover.** List the datasets recording `foc/ks`, then their piece CIDs → `download()` → FEE parses the labels → Keysmith resolves the key → FEE decrypts. It goes by piece CID, so it works wherever repair has moved a piece.
- **Delegate.**
  - SessionKeyRegistry `login` lets the agent's key add pieces.
  - A Keysmith grant lets it derive keys for one scope.
  - The two are independent: revoking the login stops writes, but keys already given still open what they opened.

## App-side workarounds (`storage.ts`, `agents.ts`)

- **Upload confirmation.** Synapse confirms an upload through the provider's add-pieces status endpoint, and Curio's batching keeps that at 404 or "not yet" long after the transaction lands. `store()` takes the transaction receipts as the confirmation instead.
- **Session-key permissions.** `sessionKey.syncExpirations()` calls the chain as the session key, and Lotus rejects calls from an unknown address, so a fresh key reads as unauthorized. The agent checks `authorizationExpiry` with no account set and passes `requiredPermissions: []`.

Both workarounds go away if synapse-core fixes these.
