export class FocEncryptionError extends Error {
    code = 'FOC_ENCRYPTION_ERROR';
    constructor(message, options) {
        super(message, options);
        this.name = this.constructor.name;
    }
}
export class InvalidKeyError extends FocEncryptionError {
    code = 'INVALID_KEY';
}
export class AuthenticationError extends FocEncryptionError {
    code = 'AUTHENTICATION_FAILED';
}
export class UnsupportedSchemeError extends FocEncryptionError {
    code = 'UNSUPPORTED_SCHEME';
    algorithmId;
    constructor(algorithmId) {
        super(`Unsupported encryption scheme: algorithm ID ${algorithmId}`);
        this.algorithmId = algorithmId;
    }
}
export class MalformedEnvelopeError extends FocEncryptionError {
    code = 'MALFORMED_ENVELOPE';
}
export class SchemeNotSeekableError extends FocEncryptionError {
    code = 'SCHEME_NOT_SEEKABLE';
}
//# sourceMappingURL=errors.js.map