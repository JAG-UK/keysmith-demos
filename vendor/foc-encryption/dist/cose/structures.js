import * as cborg from 'cborg';
/**
 * Build the Enc_structure for AAD computation per RFC 9052 Section 5.3.
 * Enc_structure = [context: tstr, protected: bstr, external_aad: bstr]
 */
export function buildEncStructure(context, protectedHeaders, externalAad) {
    return cborg.encode([context, protectedHeaders, externalAad]);
}
//# sourceMappingURL=structures.js.map