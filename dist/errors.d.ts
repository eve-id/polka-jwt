declare class HttpError extends Error {
    code: number;
    constructor(code: number, message?: string);
}
export declare class RevokedToken extends HttpError {
    reason: string;
    constructor(reason: string);
}
declare class InvalidToken extends HttpError {
    reason: string;
    constructor(reason: string);
}
interface JWTHeader {
    alg?: string;
    typ?: string;
}
export declare class InvalidTypeToken extends InvalidToken {
    typ?: string | undefined;
    constructor(typ?: string | undefined, header?: JWTHeader);
}
export declare class MalformedToken extends InvalidToken {
    constructor();
}
export declare class InvalidPayloadToken extends InvalidToken {
    constructor();
}
export declare class InvalidSignatureToken extends InvalidToken {
    constructor();
}
export declare class InvalidClaimToken extends InvalidToken {
    reason: string;
    constructor(reason: string);
}
export declare class CredentialsBadScheme extends HttpError {
    constructor();
}
export declare class CredentialsBadFormat extends HttpError {
    constructor();
}
export declare class CredentialsRequired extends HttpError {
    constructor();
}
export declare class ExpiredToken extends InvalidToken {
    reason: string;
    constructor(reason: string);
}
export declare class SecretFetchingError extends HttpError {
    reason: string;
    constructor(reason: string);
}
export {};
