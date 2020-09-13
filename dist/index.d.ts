/// <reference types="node" />
import { Request, Next } from "polka";
import { ServerResponse } from "http";
export declare type secretType = string | Buffer;
export declare type callback = (req: Request, header: any, payload: any, done: (err: any, secret?: secretType) => void) => void;
export declare type promise = (req: Request, header: any, payload: any) => Promise<secretType>;
declare type secret = secretType | callback | promise;
interface IsRevokedCallback {
    (req: Request, payload: any, done: (err: any, revoked?: boolean) => void): void;
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
export declare type Options = MiddlewareOptions & JWTOptions;
export declare const JWT: (opts: Options) => (req: Request, res: ServerResponse, next: Next) => Promise<void>;
export {};
