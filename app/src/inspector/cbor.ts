/**
 * A CBOR walker that remembers where every item sits in the bytes, so the
 * inspector can link a decoded field to its hex. Display only: FEE and
 * Keysmith do the real (strict) decoding. Definite lengths only, which is all
 * FEE envelopes and Keysmith grants use.
 */
export interface CborNode {
  /** First byte of the item, its header included. */
  start: number
  /** First byte after its header: where a string's content or a container's items begin. */
  head: number
  /** First byte after the whole item. */
  end: number
  major: number
  value?: number | bigint | string | Uint8Array | boolean | null
  tag?: number
  items?: CborNode[]
  entries?: [CborNode, CborNode][]
}

export function parseCbor(bytes: Uint8Array, offset = 0): CborNode {
  if (offset >= bytes.length) throw new Error('CBOR ends early')
  const initial = bytes[offset]
  const major = initial >> 5
  const info = initial & 31
  let at = offset + 1
  let arg: number | bigint
  if (info < 24) arg = info
  else if (info <= 27) {
    const size = 1 << (info - 24)
    if (at + size > bytes.length) throw new Error('CBOR ends early')
    let n = 0n
    for (let i = 0; i < size; i++) n = (n << 8n) | BigInt(bytes[at + i])
    at += size
    arg = n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n
  } else throw new Error(info === 31 ? 'indefinite-length CBOR: not a FEE envelope or Keysmith grant' : 'malformed CBOR')
  const count = Number(arg)
  switch (major) {
    case 0:
      return { start: offset, head: at, end: at, major, value: arg }
    case 1:
      return { start: offset, head: at, end: at, major, value: typeof arg === 'bigint' ? -1n - arg : -1 - arg }
    case 2:
    case 3: {
      if (at + count > bytes.length) throw new Error('CBOR ends early')
      const content = bytes.subarray(at, at + count)
      return { start: offset, head: at, end: at + count, major, value: major === 2 ? content : new TextDecoder().decode(content) }
    }
    case 4: {
      const items: CborNode[] = []
      let next = at
      for (let i = 0; i < count; i++) {
        const item = parseCbor(bytes, next)
        items.push(item)
        next = item.end
      }
      return { start: offset, head: at, end: next, major, items }
    }
    case 5: {
      const entries: [CborNode, CborNode][] = []
      let next = at
      for (let i = 0; i < count; i++) {
        const key = parseCbor(bytes, next)
        const value = parseCbor(bytes, key.end)
        entries.push([key, value])
        next = value.end
      }
      return { start: offset, head: at, end: next, major, entries }
    }
    case 6: {
      const inner = parseCbor(bytes, at)
      return { start: offset, head: at, end: inner.end, major, tag: count, items: [inner] }
    }
    default: {
      const simple: Record<number, boolean | null> = { 20: false, 21: true, 22: null }
      if (!(info in simple)) throw new Error(`unsupported CBOR simple value ${info}`)
      return { start: offset, head: at, end: at, major, value: simple[info] }
    }
  }
}
