import { Request } from "polka";
import { createSigner } from "fast-jwt";
import { JWT } from "../src";
import {
  // CredentialsRequired,
  // CredentialsBadFormat,
  // CredentialsBadScheme,
  // MalformedToken,
  // InvalidSignatureToken,
  // InvalidClaimToken,
  // ExpiredToken,
  RevokedToken,
  SecretFetchingError,
} from "../src/errors";

describe("multitenancy - failing middleware requests", () => {
  const req: any = {};
  const res: any = {};

  const tenants: any = {
    a: {
      secret: "secret-a",
    },
  };

  const secretFn = (_req: Request, _header: any, payload: any, cb: any) => {
    const issuer = payload.iss;
    if (tenants[issuer]) {
      return cb(null, tenants[issuer].secret);
    }

    return cb(
      new SecretFetchingError(
        `could not retrieve secret for tenant: ${issuer}`
      ),
      undefined
    );
  };

  const middleware = JWT({
    secret: secretFn,
    algorithms: ["HS256"],
  });

  it("fail to retrieve secret from callback", async () => {
    const token = createSigner({
      key: tenants.a.secret,
      iss: "b",
    })({ foo: "bar" });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;
    return middleware(req, res, (err) => {
      expect(err).toBeDefined();
      expect(err).toBeInstanceOf(SecretFetchingError);
    });
  });

  it("request fails because token revoked", async () => {
    const token = createSigner({
      key: tenants.a.secret,
      iss: "a",
    })({ foo: "bar" });

    const mw = JWT({
      algorithms: ["HS256"],
      secret: secretFn,
      is_revoked: (_req, _payload, done) => done(null, true),
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;
    return mw(req, res, (err) => {
      expect(err).toBeDefined();
      expect(err).toBeInstanceOf(RevokedToken);
    });
  });
});

describe("multitenancy - working middleware requests", () => {
  const req: any = {};
  const res: any = {};

  const tenants: any = {
    a: {
      secret: "secret-a",
    },
  };

  const secretFn = (_req: Request, _header: any, payload: any, cb: any) => {
    const issuer = payload.iss;
    if (tenants[issuer]) {
      return cb(null, tenants[issuer].secret);
    }

    return cb(
      new SecretFetchingError(
        `could not retrieve secret for tenant: ${issuer}`
      ),
      undefined
    );
  };

  const middleware = JWT({
    secret: secretFn,
    algorithms: ["HS256"],
  });

  it("retrieve secret from callback", async () => {
    const token = createSigner({
      key: tenants.a.secret,
      iss: "a",
    })({ foo: "bar" });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;
    return middleware(req, res, (err) => {
      expect(err).toBeUndefined();
      expect(req.user.foo).toBe("bar");
    });
  });

  it("token check and not revoked", async () => {
    const token = createSigner({
      key: tenants.a.secret,
      iss: "a",
    })({ foo: "bar" });

    const mw = JWT({
      algorithms: ["HS256"],
      secret: secretFn,
      is_revoked: (_req, _payload, done) => done(null, false),
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;
    return mw(req, res, (err) => {
      expect(err).toBeUndefined();
      expect(req.user.foo).toBe("bar");
    });
  });
});
