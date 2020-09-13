import { createDecoder, createVerifier, TokenError } from "fast-jwt";
import { Request, Next } from "polka";
import { ServerResponse } from "http";
import {
  CredentialsBadFormat,
  CredentialsBadScheme,
  CredentialsRequired,
  InvalidTypeToken,
  InvalidPayloadToken,
  InvalidSignatureToken,
  InvalidClaimToken,
  MalformedToken,
  ExpiredToken,
  SecretFetchingError,
  RevokedToken,
} from "./errors";
import set from "just-safe-set";

export type secretType = string | Buffer;

type SecretBasic = {
  type: "basic";
  content: secretType;
};

export type callback = (
  req: Request,
  header: any,
  payload: any,
  done: (err: any, secret?: secretType) => void
) => void;

type SecretCallback = {
  type: "callback";
  content: callback;
};

export type promise = (
  req: Request,
  header: any,
  payload: any
) => Promise<secretType>;

type SecretPromise = {
  type: "promise";
  content: promise;
};

type secret = secretType | callback | promise;

interface IsRevokedCallback {
  (
    req: Request,
    payload: any,
    done: (err: any, revoked?: boolean) => void
  ): void;
}

interface GetTokenCallback {
  (req: Request): any;
}

export interface MiddlewareOptions {
  userProperty?: string;
  resultProperty?: string;
  requestProperty?: string;
  is_revoked?: IsRevokedCallback;
  get_token?: GetTokenCallback;
}

export interface JWTOptions {
  secret: secret;
  algorithms: [string];
  credentialsRequired?: boolean;
  token_type?: string;
  audience?: [string] | string;
  issuer?: [string] | string;
}

export type Options = MiddlewareOptions & JWTOptions;

function wrapStaticAsync(secret: SecretBasic): SecretPromise {
  return {
    type: "promise",
    content: (_req: Request, _payload: any) =>
      new Promise((resolve) => {
        resolve(secret.content);
      }),
  };
}

function wrapCallbackAsync(fn_secret: SecretCallback): SecretPromise {
  return {
    type: "promise",
    content: (req: Request, header: any, payload: any) =>
      new Promise((resolve, reject) =>
        fn_secret.content(
          req,
          header,
          payload,
          (err: any, secret?: secretType) => {
            if (err) return reject(err);
            if (!secret)
              return reject(new Error("secret couldn't be retrieved"));
            return resolve(secret);
          }
        )
      ),
  } as SecretPromise;
}

const hasAuthInAccessControl = (req: Request) =>
  (req.headers["access-control-request-headers"] || "")
    .split(",")
    .map((x) => x.trim())
    .includes("authorization");

const bearer = /^Bearer$/i;

function buildSecret(secret: secret): SecretPromise {
  if (typeof secret === "string" || secret instanceof Buffer) {
    return wrapStaticAsync({
      type: "basic",
      content: secret,
    });
  } else if (
    secret instanceof Promise ||
    secret.constructor.name === "AsyncFunction" ||
    secret.constructor.name === "GeneratorFunction"
  ) {
    return {
      type: "promise",
      content: secret,
    } as SecretPromise;
  } else if (typeof secret === "function" && secret.length === 4) {
    return wrapCallbackAsync({
      type: "callback",
      content: secret,
    });
  } else {
    throw new Error(
      "jwt: secret field can be of type: string | Buffer | Promise | Function(req, jwtheader, payload, cb(err, ?secret))"
    );
  }
}

// The middleware validates JWT and let's the request complete or blocks it.
export const JWT = (opts: Options) => {
  if (!opts || Object.keys(opts).length === 0) {
    throw new Error(
      "options can't be missing or empty, has required fields: [secret, algorithms]"
    );
  }

  if (!opts.algorithms)
    throw new Error(
      "jwt: algorithms field can't be undefined, must be an array of type string: [string]"
    );

  if (!Array.isArray(opts.algorithms))
    throw new Error(
      "jwt: algorithms field must be an array of type string: [string]"
    );

  const _reqProperty = opts.userProperty || opts.requestProperty || "user";
  const _resProperty = opts.resultProperty;

  const credentialsRequired =
    opts.credentialsRequired == null ? true : opts.credentialsRequired;

  const secret = buildSecret(opts.secret);

  let customTokenFnProvided = opts.get_token != undefined;

  const check_revoked = (req: Request, payload: any) => {
    return new Promise((resolve, reject) => {
      if (!opts.is_revoked) return resolve(false);
      opts.is_revoked(req, payload, (err, revoked) => {
        if (err) return reject(err);
        resolve(revoked);
      });
    });
  };

  const execute = async (req: Request, res: ServerResponse, next: Next) => {
    try {
      let token: string = "";

      const isPreflightRequest: boolean =
        req.method === "OPTIONS" &&
        req.headers.hasOwnProperty("access-control-request-headers");

      if (isPreflightRequest && hasAuthInAccessControl(req)) return next();

      // Use opts.get_token to extract token from request
      // used for custom requests
      if (customTokenFnProvided) {
        token = (opts.get_token as GetTokenCallback)(req);
      } else if (req.headers && req.headers.authorization) {
        const parts = req.headers && req.headers.authorization.split(" ");
        if (parts.length === 2) {
          const scheme = parts[0];
          const credentials = parts[1];

          if (bearer.test(scheme)) {
            token = credentials;
          } else {
            if (credentialsRequired) {
              throw new CredentialsBadScheme();
            } else {
              return next();
            }
          }
        } else {
          throw new CredentialsBadFormat();
        }
      }

      if (!token) {
        if (credentialsRequired) {
          throw new CredentialsRequired();
        } else {
          return next();
        }
      }
      const decode = createDecoder({ complete: true });

      let decoded_token: {
        payload: object;
        header: object;
      } = decode(token, { checkTyp: opts.token_type });

      const verify = createVerifier({
        key: async () =>
          await secret.content(
            req,
            decoded_token.header,
            decoded_token.payload
          ),
        complete: true,
        allowedAud: opts.audience,
        allowedIss: opts.issuer,
      });

      const sections = await verify(token);

      const isRevoked = await check_revoked(req, decoded_token.payload);
      if (isRevoked) throw new RevokedToken("internal ruleset");

      if (_resProperty) {
        set(res, _resProperty, sections.payload);
      } else {
        set(req, _reqProperty, sections.payload);
      }

      next();
    } catch (e) {
      switch (e.code) {
        case TokenError.codes.invalidType:
          return next(new InvalidTypeToken(opts?.token_type, e.header));
        case TokenError.codes.malformed:
          return next(new MalformedToken());
        case TokenError.codes.invalidPayload:
          return next(new InvalidPayloadToken());
        case TokenError.codes.invalidSignature:
          return next(new InvalidSignatureToken());
        case TokenError.codes.invalidClaimValue:
          return next(new InvalidClaimToken(e.message));
        case TokenError.codes.expired:
          return next(new ExpiredToken(e.message));
        case TokenError.codes.keyFetchingError:
          return next(new SecretFetchingError(e.message));
        default:
          return next(e);
      }
    }
  };

  return execute;
};
