class HttpError extends Error {
  constructor(public code: number, message?: string) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
  }
}

export class RevokedToken extends HttpError {
  constructor(public reason: string) {
    super(401, `Revoked token, reason: ${reason}`);
    this.reason = reason;
  }
}

class InvalidToken extends HttpError {
  constructor(public reason: string) {
    super(401, `Invalid token, reason: ${reason}`);
    this.reason = reason;
  }
}

interface JWTHeader {
  alg?: string;
  typ?: string;
}

export class InvalidTypeToken extends InvalidToken {
  constructor(public typ?: string, header?: JWTHeader) {
    super(
      typeof typ !== "undefined"
        ? `token must be of type '${typ}` +
            (typeof header?.typ !== "undefined"
              ? `' but is of type '${header.typ}.`
              : ".")
        : "token must be a string or a buffer."
    );
  }
}

export class MalformedToken extends InvalidToken {
  constructor() {
    super("token is malformed.");
  }
}

export class InvalidPayloadToken extends InvalidToken {
  constructor() {
    super(`token payload must be an object.`);
  }
}

export class InvalidSignatureToken extends InvalidToken {
  constructor() {
    super("token signature is invalid.");
  }
}

export class InvalidClaimToken extends InvalidToken {
  constructor(public reason: string) {
    super(reason.toLowerCase());
  }
}

export class CredentialsBadScheme extends HttpError {
  constructor() {
    super(401, "Credentials bad scheme");
  }
}

export class CredentialsBadFormat extends HttpError {
  constructor() {
    super(401, "Credentials bad format");
  }
}

export class CredentialsRequired extends HttpError {
  constructor() {
    super(401, "Credentials required");
  }
}

export class ExpiredToken extends InvalidToken {
  constructor(public reason: string) {
    super(reason.toLowerCase());
  }
}

export class SecretFetchingError extends HttpError {
  constructor(public reason: string) {
    super(401, reason.toLowerCase());
    this.reason = reason;
  }
}
