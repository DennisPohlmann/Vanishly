export const VERSION: number;
export const PBKDF2_ITERATIONS: number;
export interface Payload { v?: number; ciphertext: string; iv: string; salt: string; iterations: number; verifier?: string }
export function toB64url(bytes: Uint8Array): string;
export function fromB64url(str: string): Uint8Array;
export function randomBytes(n: number): Uint8Array;
export function encryptSecret(plaintext: string, passphrase?: string): Promise<{ key: string; payload: Payload }>;
export function unlockKey(passphrase: string, meta: { salt: string; iterations: number }): Promise<Uint8Array>;
export function verifierFor(pk: Uint8Array, meta: { salt: string }): Promise<string>;
export function decryptSecret(payload: { ciphertext: string; iv: string; salt: string }, key: string, pk?: Uint8Array): Promise<string>;

export interface SecretOptions {
  ttl?: number; views?: number; confirmed?: boolean; recipients?: string[]; recipientGroups?: string[];
  responsible?: string[]; responsibleGroups?: string[]; comment?: string;
}
export interface ClientOptions { token?: string; runId?: string; comment?: string; onBehalfOf?: string; clientName?: string; fetch?: typeof fetch }
type Json = any;
export class ApiError extends Error { status: number; error: string; body: Record<string, any> }
export function parseLink(link: string): { base: string; id: string; key: string };
export class Client {
  constructor(baseUrl: string, opts?: ClientOptions);
  baseUrl: string;
  recommendedVersion: string | null;
  request(method: string, path: string, body?: unknown, query?: Record<string, unknown>, o?: { raw?: boolean }): Promise<Json>;
  create(secret: string, passphrase?: string, opts?: SecretOptions): Promise<Json & { shareUrl: string; receiptUrl: string | null }>;
  open(link: string, passphrase?: string): Promise<{ secret: string; viewsLeft: number }>;
  index(): Promise<Json>; config(): Promise<Json>; downloads(): Promise<Json>;
  createSecret(payload: Payload & SecretOptions): Promise<Json>;
  share(secret: string, passphrase?: string, opts?: SecretOptions): Promise<Json>;
  openOnServer(link: string, passphrase?: string): Promise<{ secret: string; viewsLeft: number }>;
  secretMeta(id: string): Promise<Json>; reveal(id: string, verifier?: string): Promise<Json>;
  receipt(id: string): Promise<Json>; burn(id: string): Promise<Json>;
  me(): Promise<Json>; mySecrets(q?: Record<string, unknown>): Promise<Json>; mySecret(ref: string): Promise<Json>; burnMySecret(ref: string): Promise<Json>;
  groups(q?: string): Promise<Json>; people(q?: string): Promise<Json>;
  tokens(): Promise<Json>; createToken(body: Record<string, unknown>): Promise<Json>; revokeToken(id: string): Promise<Json>;
  adminStatus(): Promise<Json>; adminTokens(): Promise<Json>; adminRevokeToken(id: string): Promise<Json>;
  audit(q?: Record<string, unknown>): Promise<Json>; auditVerify(): Promise<Json>;
  tokenPolicies(): Promise<Json>; setTokenPolicy(body: Record<string, unknown>): Promise<Json>;
  adminSecrets(q?: Record<string, unknown>): Promise<Json>; adminSecret(ref: string): Promise<Json>; adminBurn(ref: string): Promise<Json>;
  serviceAccounts(): Promise<Json>; createServiceAccount(body: Record<string, unknown>): Promise<Json>;
  changeServiceAccount(name: string, body: Record<string, unknown>): Promise<Json>; deleteServiceAccount(name: string): Promise<Json>;
  serviceAccountTokens(name: string): Promise<Json>; issueServiceAccountToken(name: string, body?: Record<string, unknown>): Promise<Json>;
  rotateServiceAccountToken(name: string, id: string, body?: Record<string, unknown>): Promise<Json>;
  users(): Promise<Json>; createUser(body: Record<string, unknown>): Promise<Json>; changeUser(user: string, body: Record<string, unknown>): Promise<Json>;
  resetUserPassword(user: string, body?: Record<string, unknown>): Promise<Json>; deleteUser(user: string): Promise<Json>;
}
