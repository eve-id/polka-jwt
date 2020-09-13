import { Request } from "polka";
import { ServerResponse } from "http";
import { createSigner } from "fast-jwt";
import { JWT, Options } from "../src";
import {
  CredentialsRequired,
  CredentialsBadFormat,
  CredentialsBadScheme,
  MalformedToken,
  InvalidSignatureToken,
  InvalidClaimToken,
  ExpiredToken,
  RevokedToken,
} from "../src/errors";

describe("failing library initialization: bad middleware options", () => {
  const opts_throwing_combinations = [
    {
      title: "no options passed",
      options: undefined,
      throw_msg:
        "options can't be missing or empty, has required fields: [secret, algorithms]",
    },
    {
      title: "options is empty object (missing ",
      options: {} as Options,
      throw_msg:
        "options can't be missing or empty, has required fields: [secret, algorithms]",
    },
    {
      title: "missing algorithms",
      options: { secret: "jwt-secret" } as Options,
      throw_msg:
        "jwt: algorithms field can't be undefined, must be an array of type string: [string]",
    },
    {
      title: "algorithms is string instead of array",
      options: { secret: "jwt-secret", algorithms: "RS256" },
      throw_msg:
        "jwt: algorithms field must be an array of type string: [string]",
    },
    {
      title: "algorithms is int instead of array",
      options: { secret: "jwt-secret", algorithms: 154 },
      throw_msg:
        "jwt: algorithms field must be an array of type string: [string]",
    },
    {
      title: "algorithms is bool instead of array",
      options: { secret: "jwt-secret", algorithms: true },
      throw_msg:
        "jwt: algorithms field must be an array of type string: [string]",
    },
  ];

  opts_throwing_combinations.forEach(({ title, options, throw_msg }) => {
    it(title, async () =>
      expect(() => JWT(options as Options)).toThrowError(throw_msg)
    );
  });
});

describe("failing middleware requests", () => {
  let req = {} as Request,
    res = {} as ServerResponse;

  beforeEach(() => {
    req = {} as Request;
    res = {} as ServerResponse;
  });

  afterEach(() => {
    req = {} as Request;
    res = {} as ServerResponse;
  });

  it("unauthorized if no authorization header and credentials are set to required", async () => {
    const opts = {
      secret: "jwt-secret",
      algorithms: ["HS256"],
    } as Options;

    return JWT(opts)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(CredentialsRequired);
    });
  });

  it("credentials in bad format if authorization header not in right format", async () => {
    req.headers = {};
    req.headers.authorization = "not-a-good-authorization";

    const opts = {
      secret: "jwt-secret",
      algorithms: ["HS256"],
    } as Options;

    return JWT(opts)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(CredentialsBadFormat);
    });
  });

  it("credentials in bad scheme if authorization header right format but bad scheme", async () => {
    req.headers = {};
    req.headers.authorization = "Bad scheme";

    const opts = {
      secret: "jwt-secret",
      algorithms: ["HS256"],
    } as Options;

    return JWT(opts)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(CredentialsBadScheme);
    });
  });

  it("credentials in bad scheme and credentialsRequired if authorization header right format but bad scheme", async () => {
    req.headers = {};
    req.headers.authorization = "Bad scheme";

    const opts = {
      secret: "jwt-secret",
      algorithms: ["HS256"],
    } as Options;

    return JWT(opts)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(CredentialsBadScheme);
    });
  });

  it("authorization header is not Bearer", async () => {
    req.headers = {};
    req.headers.authorization = "Basic scheme";

    const opts = {
      secret: "jwt-secret",
      algorithms: ["HS256"],
    } as Options;

    return JWT(opts)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(CredentialsBadScheme);
    });
  });

  it("authorization header is not well-formatted jwt (not valid base64url json)", async () => {
    req.headers = {};
    req.headers.authorization = "Bearer wrongjwt";

    const opts = {
      secret: "jwt-secret",
      algorithms: ["HS256"],
    } as Options;

    return JWT(opts)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(MalformedToken);
    });
  });

  it("authorization header is not valid JSON", async () => {
    req.headers = {};
    req.headers.authorization =
      "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.yJ1c2VybmFtZSI6InNhZ3VpYXIiLCJpYXQiOjE0NzEwMTg2MzUsImV4cCI6MTQ3MzYxMDYzNX0.foo";

    const opts = {
      secret: "jwt-secret",
      algorithms: ["HS256"],
    } as Options;

    return JWT(opts)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(MalformedToken);
    });
  });

  it("authorization header is not valid jwt (different signing key)", async () => {
    const secret = "not-the-same-jwt-secret";
    const token = createSigner({ key: secret, algorithm: "HS256" })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    return JWT({
      secret: "another-jwt-secret",
      algorithms: ["HS256"],
    } as Options)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(InvalidSignatureToken);
    });
  });

  it("audience is not expected", async () => {
    const secret = "not-a-super-secret";
    const token = createSigner({ key: secret, algorithm: "HS256" })(
      {
        foo: "bar",
        aud: "expected-audience",
      },
      secret,
      { expiredsIn: 500 }
    );

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    return JWT({
      secret: "not-a-super-secret",
      algorithms: ["HS256"],
      audience: "not-expected-audience",
    } as Options)(req, res, (err: any) => {
      expect(err).not.toBeUndefined();
      expect(err).toBeInstanceOf(InvalidClaimToken);
      expect((err as Error).message).toContain("aud");
    });
  });

  it("token has expired", async () => {
    const secret = "a-jwt-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
      expiresIn: 3600,
    })({
      foo: "bar",
      iat: 1382412921,
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    return JWT({
      secret: "a-jwt-secret",
      algorithms: ["HS256"],
    } as Options)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(ExpiredToken);
    });
  });

  it("token issuer is wrong", async () => {
    const secret = "a-jwt-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
      iss: "http://foo",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    return JWT({
      secret: "a-jwt-secret",
      algorithms: ["HS256"],
      issuer: "http://wrong",
    } as Options)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(InvalidClaimToken);
      expect((err as Error).message).toContain("iss");
    });
  });

  it("bad custom getToken function", async () => {
    const get_token_that_throws = () => {
      throw new RevokedToken("no-reason");
    };

    return JWT({
      secret: "a-jwt-secret",
      algorithms: ["HS256"],
      get_token: get_token_that_throws,
    } as Options)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(RevokedToken);
      expect((err as Error).message).toContain("no-reason");
    });
  });

  it("bad signature", async () => {
    const secret = "a-jwt-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
      iss: "http://www",
    })({
      foo: "bar",
    });

    // manipulate the token
    const newContent = Buffer.from('{"foo":"bar"}', "utf-8")
      .toString("base64")
      .replace(/=/g, "");
    let token_parts = token.split(".");
    token_parts[1] = newContent;
    const newToken = token_parts.join(".");

    req.headers = {};
    req.headers.authorization = `Bearer ${newToken}`;
    return JWT({
      secret,
      algorithms: ["HS256"],
      issuer: "http://www",
    } as Options)(req, res, (err: any) => {
      expect(err).toBeInstanceOf(InvalidSignatureToken);
    });
  });

  it("token expired when credentials not required", async () => {
    const secret = "oh-my-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
      expiresIn: 3600,
    })({
      iat: 1382412921,
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    return JWT({ secret, credentialsRequired: false, algorithms: ["HS256"] })(
      req,
      res,
      (err: any) => {
        expect(err).toBeInstanceOf(ExpiredToken);
      }
    );
  });

  it("token invalid when credentials not required", async () => {
    const secret = "oh-my-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
      expiresIn: 3600,
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    return JWT({
      secret: "different-secret",
      credentialsRequired: false,
      algorithms: ["HS256"],
    })(req, res, (err: any) => {
      expect(err).toBeInstanceOf(InvalidSignatureToken);
    });
  });

  it("authorization header missing (not authorized)", async () => {
    const secret = "secret-service-secret";

    // @ts-ignore
    req = {};

    const middleware = JWT({
      secret,
      algorithms: ["HS256"],
    });
    const next_handler = (err: any) => {
      expect(err).toBeInstanceOf(CredentialsRequired);
    };

    return middleware(req, res, next_handler);
  });

  it("check returns correct error on unauthorized attempt", async () => {
    const signerSecret = "secret-service-secret-A";
    const middlewareSecret = "secret-service-secret-B";

    const token = createSigner({
      key: signerSecret,
      algorithm: "HS256",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    const middleware = JWT({
      secret: middlewareSecret,
      algorithms: ["HS256"],
    });
    const next_handler = (err: any) => {
      expect(err).toBeDefined();
      expect(err).toBeInstanceOf(InvalidSignatureToken);
    };

    return middleware(req, res, next_handler);
  });
});

describe("working middleware requests", () => {
  let req = {} as Request,
    res = {} as ServerResponse;

  beforeEach(() => {
    req = {} as Request;
    res = {} as ServerResponse;
  });

  afterEach(() => {
    req = {} as Request;
    res = {} as ServerResponse;
  });

  it("authorization header is a valid jwt", async () => {
    jest.setTimeout(2.5 * 1000);
    const secret = "secret-service-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    const middleware = JWT({ secret, algorithms: ["HS256"] });
    const next_handler = (err: any) => {
      expect(err).toBeUndefined();
      expect((req as any).user.foo).toBe("bar");
    };

    return middleware(req, res, next_handler);
  });

  it("nested properties set", async () => {
    const secret = "secret-service-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    const middleware = JWT({
      secret,
      algorithms: ["HS256"],
      requestProperty: "auth.token",
    });
    const next_handler = (err: any) => {
      expect(err).toBeUndefined();
      expect((req as any).auth.token.foo).toBe("bar");
    };

    return middleware(req, res, next_handler);
  });

  it("secret as a buffer", async () => {
    const secret = Buffer.from(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "base64"
    );
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    const middleware = JWT({
      secret,
      algorithms: ["HS256"],
    });
    const next_handler = (err: any) => {
      expect(err).toBeUndefined();
      expect((req as any).user.foo).toBe("bar");
    };

    return middleware(req, res, next_handler);
  });

  it("set userProperty if option provided", async () => {
    const secret = "secret-service-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    const middleware = JWT({
      secret,
      algorithms: ["HS256"],
      userProperty: "auth",
    });
    const next_handler = (err: any) => {
      expect(err).toBeUndefined();
      expect((req as any).auth.foo).toBe("bar");
    };

    return middleware(req, res, next_handler);
  });

  it("set resultProperty if option provided", async () => {
    const secret = "secret-service-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    const middleware = JWT({
      secret,
      algorithms: ["HS256"],
      resultProperty: "locals.user",
    });

    const next_handler = (err: any) => {
      expect(err).toBeUndefined();
      expect((res as any).locals.user.foo).toBe("bar");
    };

    return middleware(req, res, next_handler);
  });

  it("work without authorization header and credentials are not required", async () => {
    const secret = "secret-service-secret";

    // @ts-ignore
    req = {};

    const middleware = JWT({
      secret,
      algorithms: ["HS256"],
      credentialsRequired: false,
    });
    const next_handler = (err: any) => {
      expect(err).toBeUndefined();
    };

    return middleware(req, res, next_handler);
  });

  it("work with custom get_token function", async () => {
    const secret = "secret-service-secret";
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.query = {};
    req.query.token = token;

    const get_token_from_query = (req: Request) => req.query.token;

    const middleware = JWT({
      secret,
      algorithms: ["HS256"],
      get_token: get_token_from_query,
    });
    const next_handler = (err: any) => {
      expect(err).toBeUndefined();
      expect((req as any).user.foo).toBe("bar");
    };

    return middleware(req, res, next_handler);
  });

  it("work with callback to retrieve secret", async () => {
    const secret = "secret-service-a";

    const secretCB = (_req: Request, header: any, payload: any, cb: any) => {
      expect(header.alg).toBe("HS256");
      expect(payload.foo).toBe("bar");
      process.nextTick(() => {
        cb(null, secret);
      });
    };
    const token = createSigner({
      key: secret,
      algorithm: "HS256",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    const middleware = JWT({
      secret: secretCB,
      algorithms: ["HS256"],
    });
    const next_handler = (err: any) => {
      expect(err).toBeUndefined();
      expect((req as any).user.foo).toBe("bar");
    };

    return middleware(req, res, next_handler);
  });

  it("works with promise to retrieve secret", async () => {
    const secret = "secret-service-a";

    const secretPromise = async (_req: Request, header: any, payload: any) => {
      expect(header.alg).toBe("HS256");
      expect(payload.foo).toBe("bar");
      return secret;
    };

    const token = createSigner({
      key: secret,
      algorithm: "HS256",
    })({
      foo: "bar",
    });

    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;

    const middleware = JWT({
      secret: secretPromise,
      algorithms: ["HS256"],
    });
    const next_handler = (err: any) => {
      expect(err).toBeUndefined();
      expect((req as any).user.foo).toBe("bar");
    };

    return middleware(req, res, next_handler);
  });
});
