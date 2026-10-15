export declare class FocEncryptionError extends Error {
    readonly code: string;
    constructor(message: string, options?: ErrorOptions);
}
export declare class InvalidKeyError extends FocEncryptionError {
    readonly code: "INVALID_KEY";
}
export declare class AuthenticationError extends FocEncryptionError {
    readonly code: "AUTHENTICATION_FAILED";
}
export declare class UnsupportedSchemeError extends FocEncryptionError {
    readonly code: "UNSUPPORTED_SCHEME";
    readonly algorithmId: number;
    constructor(algorithmId: number);
}
export declare class MalformedEnvelopeError extends FocEncryptionError {
    readonly code: "MALFORMED_ENVELOPE";
}
export declare class SchemeNotSeekableError extends FocEncryptionError {
    readonly code: "SCHEME_NOT_SEEKABLE";
}
//# sourceMappingURL=errors.d.ts.map