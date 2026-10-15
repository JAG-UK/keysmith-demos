export type KeySource = {
    kind: 'hex';
    hex: string;
} | {
    kind: 'password';
    password: string;
};
export interface DerivedKey {
    cek: Uint8Array;
    salt?: Uint8Array;
}
declare function hexToBytes(hex: string): Uint8Array;
export { hexToBytes };
export declare function deriveKey(source: KeySource, existingSalt?: Uint8Array): Promise<DerivedKey>;
//# sourceMappingURL=kdf.d.ts.map