/**
 * Build the Enc_structure for AAD computation per RFC 9052 Section 5.3.
 * Enc_structure = [context: tstr, protected: bstr, external_aad: bstr]
 */
export declare function buildEncStructure(context: 'Encrypt0' | 'Encrypt', protectedHeaders: Uint8Array, externalAad: Uint8Array): Uint8Array;
//# sourceMappingURL=structures.d.ts.map