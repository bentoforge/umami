import type {
  AccessClaims,
  ApiErrorBody,
  ApiKeyView,
  AuditEntry,
  AuditPage,
  Config,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  CreatePatRequest,
  CreateTenantRequest,
  CreateTenantResponse,
  CreateUserRequest,
  CreateUserResponse,
  CustomFieldsSchema,
  ExchangeResponse,
  LoginResponse,
  MeResponse,
  MessagingCodeResponse,
  MessagingLink,
  MfaStatus,
  NameInput,
  PatchUserRequest,
  ResetPasswordResponse,
  ResolvedMessagingUser,
  SessionView,
  Tenant,
  TokenResponse,
  TotpSetup,
  UserView,
} from "./types.js";
import {
  assertionToJSON,
  b64urlToBuffer,
  registrationToJSON,
  toCreationOptions,
  toRequestOptions,
} from "./webauthn.js";

/** An error carrying the server's HTTP status and (parsed) body. */
export class UmamiError extends Error {
  readonly status: number;
  readonly body?: ApiErrorBody;
  constructor(status: number, message: string, body?: ApiErrorBody) {
    super(message);
    this.name = "UmamiError";
    this.status = status;
    this.body = body;
  }
}

export interface UmamiClientOptions {
  /** Base URL of the umami service, e.g. `https://umami.example.com`. */
  baseUrl: string;
  /** Called whenever the in-memory access token changes (login/refresh/logout). */
  onTokenChange?: (token: string | null) => void;
}

/**
 * Typed client for the umami API. Holds the access token **in memory only** and silently refreshes
 * it via the `HttpOnly` cookie on a 401. Never touches the refresh cookie's value.
 */
export class UmamiClient {
  private readonly baseUrl: string;
  private readonly onTokenChange?: (token: string | null) => void;
  private accessToken: string | null = null;
  /** In-flight refresh, if any — coalesces concurrent 401s into a single rotation. */
  private refreshing: Promise<boolean> | null = null;

  constructor(options: UmamiClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.onTokenChange = options.onTokenChange;
  }

  /** The current in-memory access token, if any. */
  getAccessToken(): string | null {
    return this.accessToken;
  }

  /** Decodes the current access token's claims (no signature verification). */
  getClaims(): AccessClaims | null {
    if (!this.accessToken) return null;
    const parts = this.accessToken.split(".");
    if (parts.length < 2) return null;
    try {
      const json = new TextDecoder().decode(b64urlToBuffer(parts[1] as string));
      return JSON.parse(json) as AccessClaims;
    } catch {
      return null;
    }
  }

  /** Whether the current token grants a permission. */
  hasPermission(permission: string): boolean {
    return this.getClaims()?.permissions?.includes(permission) ?? false;
  }

  private setToken(token: string | null): void {
    this.accessToken = token;
    this.onTokenChange?.(token);
  }

  // ── transport ───────────────────────────────────────────────────────────────

  private doFetch(path: string, init: RequestInit, useAuth: boolean): Promise<Response> {
    const headers = new Headers(init.headers);
    if (init.body != null && !headers.has("content-type")) {
      headers.set("content-type", "application/json");
    }
    if (useAuth && this.accessToken) {
      headers.set("authorization", `Bearer ${this.accessToken}`);
    }
    return fetch(`${this.baseUrl}${path}`, { ...init, headers, credentials: "include" });
  }

  /** Performs a request, refreshing once on a 401 for authenticated calls. */
  private async request<T>(path: string, init: RequestInit = {}, useAuth = true): Promise<T> {
    let response = await this.doFetch(path, init, useAuth);
    if (response.status === 401 && useAuth) {
      const refreshed = await this.refresh().catch(() => false);
      if (refreshed) response = await this.doFetch(path, init, useAuth);
    }
    return this.handle<T>(response);
  }

  private async handle<T>(response: Response): Promise<T> {
    if (!response.ok) {
      let body: ApiErrorBody | undefined;
      try {
        body = (await response.json()) as ApiErrorBody;
      } catch {
        // non-JSON error body
      }
      throw new UmamiError(response.status, body?.message ?? response.statusText, body);
    }
    if (response.status === 204) return undefined as T;
    const text = await response.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  // ── auth ────────────────────────────────────────────────────────────────────

  /** Password login by username. On success the access token is stored; if MFA is enabled and no
   * `totpCode` is given, the response has `mfaRequired: true` and no token. Pass `api` to mint the
   * token for a product API directly (default: the umami admin API); the session keeps that
   * audience across refreshes. */
  async login(
    username: string,
    password: string,
    totpCode?: string,
    api?: string,
  ): Promise<LoginResponse> {
    const data = await this.request<LoginResponse>(
      "/auth/login",
      { method: "POST", body: JSON.stringify({ username, password, totpCode, api }) },
      false,
    );
    if (data.accessToken) this.setToken(data.accessToken);
    return data;
  }

  /** Silent refresh via the cookie. Returns whether a fresh token was obtained.
   *
   * Single-flighted: concurrent callers (e.g. several requests that 401 at once) all await one
   * rotation. Without this, the second refresh would send the just-rotated-out cookie secret, which
   * the server treats as token reuse and revokes the whole session. */
  async refresh(): Promise<boolean> {
    if (this.refreshing) return this.refreshing;
    this.refreshing = this.doRefresh().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async doRefresh(): Promise<boolean> {
    const response = await this.doFetch("/auth/refresh", { method: "POST" }, false);
    if (!response.ok) {
      this.setToken(null);
      return false;
    }
    const data = (await response.json()) as TokenResponse;
    this.setToken(data.accessToken);
    return true;
  }

  /** Logs out this device and clears the in-memory token. */
  async logout(): Promise<void> {
    await this.request("/auth/logout", { method: "POST" }, false).catch(() => undefined);
    this.setToken(null);
  }

  /** Revokes all of the user's sessions (bumps `tokenVersion`). */
  async logoutAll(): Promise<void> {
    await this.request("/auth/logout-all", { method: "POST" }, true);
  }

  /** Lists the caller's active login sessions (the current one is flagged). */
  listSessions(): Promise<SessionView[]> {
    return this.request<SessionView[]>("/auth/sessions");
  }

  /** Revokes one of the caller's own sessions (single-device logout). */
  async deleteSession(sessionId: string): Promise<void> {
    await this.request(`/auth/sessions/${enc(sessionId)}`, { method: "DELETE" });
  }

  /** Current profile (user + tenant). */
  getMe(): Promise<MeResponse> {
    return this.request<MeResponse>("/auth/me");
  }
  /** Self-service profile edit: the structured name parts are always editable; custom fields only
   * when marked `selfEditable`. Blocked for `self:readonly` users. */
  patchMe(body: NameInput & { customFields?: Record<string, unknown> }): Promise<MeResponse> {
    return this.request<MeResponse>("/auth/me", {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  }
  /** Re-scope the access token to another tenant (requires `admin:system`). Access-token only —
   * a later silent refresh returns to the home tenant. Returns the active tenant id. */
  async switchTenant(tenantId: string): Promise<string> {
    const data = await this.request<TokenResponse>("/auth/switch-tenant", {
      method: "POST",
      body: JSON.stringify({ tenantId }),
    });
    this.setToken(data.accessToken);
    return this.getClaims()?.tenant ?? tenantId;
  }

  // ── MFA: TOTP ─────────────────────────────────────────────────────────────────

  totpSetup(): Promise<TotpSetup> {
    return this.request<TotpSetup>("/auth/mfa/totp/setup", { method: "POST" });
  }
  totpVerify(code: string): Promise<MfaStatus> {
    return this.request<MfaStatus>("/auth/mfa/totp/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }
  totpDisable(code: string): Promise<MfaStatus> {
    return this.request<MfaStatus>("/auth/mfa/totp/disable", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  // ── MFA: WebAuthn (passkeys) ──────────────────────────────────────────────────

  /** Enrols a passkey for the authenticated user via `navigator.credentials.create`. */
  async registerPasskey(): Promise<{ credentialId: string }> {
    const start = await this.request<{ ceremonyId: string; options: any }>(
      "/auth/webauthn/register/start",
      { method: "POST" },
    );
    const publicKey = toCreationOptions(start.options.publicKey);
    const credential = (await navigator.credentials.create({
      publicKey,
    })) as PublicKeyCredential | null;
    if (!credential) throw new Error("Passkey registration was cancelled");
    return this.request<{ credentialId: string }>("/auth/webauthn/register/finish", {
      method: "POST",
      body: JSON.stringify({
        ceremonyId: start.ceremonyId,
        credential: registrationToJSON(credential),
      }),
    });
  }

  /** Passwordless login with a passkey via `navigator.credentials.get`; stores the token. Pass
   * `api` to mint the token for a product API directly (default: umami); the session keeps that
   * audience across refreshes. */
  async loginWithPasskey(username: string, api?: string): Promise<void> {
    const start = await this.request<{ ceremonyId: string; options: any }>(
      "/auth/webauthn/login/start",
      { method: "POST", body: JSON.stringify({ username }) },
      false,
    );
    const publicKey = toRequestOptions(start.options.publicKey);
    const credential = (await navigator.credentials.get({
      publicKey,
    })) as PublicKeyCredential | null;
    if (!credential) throw new Error("Passkey login was cancelled");
    const data = await this.request<TokenResponse>(
      "/auth/webauthn/login/finish",
      {
        method: "POST",
        body: JSON.stringify({
          ceremonyId: start.ceremonyId,
          credential: assertionToJSON(credential),
          api,
        }),
      },
      false,
    );
    this.setToken(data.accessToken);
  }

  // ── API-key exchange (M2M / BFF) ──────────────────────────────────────────────

  /** Exchanges an `umk_…` API key for a short-lived token (stores it). Server-side/BFF use.
   * `api` selects the target API when the key allows more than one (see `docs/AUDIENCES.md`). */
  async exchangeApiKey(apiKey: string, api?: string): Promise<ExchangeResponse> {
    const data = await this.request<ExchangeResponse>(
      "/auth/token",
      { method: "POST", body: JSON.stringify(api ? { apiKey, api } : { apiKey }) },
      false,
    );
    this.setToken(data.accessToken);
    return data;
  }

  /** Downstream token exchange: mints a token for a product API (`api` from the config catalog)
   * for the currently-logged-in user, WITHOUT replacing the stored umami token. Returns the
   * downstream token for the caller to use against that API. */
  exchange(api: string): Promise<ExchangeResponse> {
    return this.request<ExchangeResponse>("/auth/exchange", {
      method: "POST",
      body: JSON.stringify({ api }),
    });
  }

  // ── tenants ────────────────────────────────────────────────────────────────────

  /** List every tenant (system-admin only; sorted newest-updated first, capped at 250). `q` is an
   * optional case-insensitive search: whitespace-separated terms must all match (over name / slug /
   * custom fields). `truncated` is true when more than 250 matched. */
  listTenants(q?: string, limit?: number): Promise<{ tenants: Tenant[]; truncated: boolean }> {
    return this.request<{ tenants: Tenant[]; truncated: boolean }>(`/tenants${listQs(q, limit)}`);
  }
  /** Create a tenant and its first owner (system-admin only). */
  createTenant(request: CreateTenantRequest): Promise<CreateTenantResponse> {
    return this.request<CreateTenantResponse>("/tenants", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }
  /** Delete a tenant — only succeeds when it has no users (system-admin only). */
  deleteTenant(tenantId: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(`/tenants/${enc(tenantId)}`, { method: "DELETE" });
  }

  getTenant(tenantId: string): Promise<Tenant> {
    return this.request<Tenant>(`/tenants/${enc(tenantId)}`);
  }
  patchTenant(
    tenantId: string,
    body: Partial<Pick<Tenant, "name" | "customFields">>,
  ): Promise<Tenant> {
    return this.request<Tenant>(`/tenants/${enc(tenantId)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  }

  // ── authorization: assignable roles/scopes/features + feature grant/revoke ─────

  /** Role codes assignable to a user given their tenant's features (feeds the UI role picker). */
  assignableRoles(userId: string): Promise<{ codes: string[] }> {
    return this.request<{ codes: string[] }>(`/users/${enc(userId)}/assignable-roles`);
  }
  /** Scope codes assignable to a service key in the given tenant. */
  assignableScopes(tenantId: string): Promise<{ codes: string[] }> {
    return this.request<{ codes: string[] }>(`/tenants/${enc(tenantId)}/assignable-scopes`);
  }
  /** Authorization features grantable to the given tenant right now (system admin). */
  assignableFeatures(tenantId: string): Promise<{ codes: string[] }> {
    return this.request<{ codes: string[] }>(`/tenants/${enc(tenantId)}/assignable-features`);
  }
  /** Grant an authorization feature to a tenant (system admin). */
  grantFeature(tenantId: string, code: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(`/tenants/${enc(tenantId)}/features/${enc(code)}`, {
      method: "POST",
    });
  }
  /** Revoke an authorization feature from a tenant (system admin). */
  revokeFeature(tenantId: string, code: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(`/tenants/${enc(tenantId)}/features/${enc(code)}`, {
      method: "DELETE",
    });
  }

  // ── users ────────────────────────────────────────────────────────────────────

  createUser(request: CreateUserRequest): Promise<CreateUserResponse> {
    return this.request<CreateUserResponse>("/users", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }
  /** List the caller's tenant's users (sorted by recent activity, capped at 250). `q` is an
   * optional case-insensitive search over username / email / name / custom fields. */
  listUsers(q?: string, limit?: number): Promise<{ users: UserView[]; truncated: boolean }> {
    return this.request<{ users: UserView[]; truncated: boolean }>(`/users${listQs(q, limit)}`);
  }
  /** Read one user in the caller's tenant (requires `manage:users`). */
  getUser(userId: string): Promise<UserView> {
    return this.request<UserView>(`/users/${enc(userId)}`);
  }
  patchUser(userId: string, body: PatchUserRequest): Promise<UserView> {
    return this.request<UserView>(`/users/${enc(userId)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  }
  /** Hard-delete a user in the caller's tenant (cannot delete your own account). */
  deleteUser(userId: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(`/users/${enc(userId)}`, { method: "DELETE" });
  }
  /** Admin reset of a user's password. Omit `newPassword` to have a temporary one generated and
   * returned once. Invalidates the user's existing sessions/tokens. */
  resetPassword(userId: string, newPassword?: string): Promise<ResetPasswordResponse> {
    return this.request<ResetPasswordResponse>(`/users/${enc(userId)}/password`, {
      method: "POST",
      body: JSON.stringify(newPassword ? { newPassword } : {}),
    });
  }

  // ── Self-service password + audit ──────────────────────────────────────────────

  /** Change the current user's own password (verifies the current one; logs out other sessions). */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.request("/auth/me/password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
    });
  }
  /** One page of the current user's own audit trail (newest first). Pass `cursor` to page. */
  myAudit(limit?: number, cursor?: string): Promise<AuditPage> {
    return this.request<AuditPage>(`/auth/me/audit${auditQs(limit, cursor)}`);
  }
  /** One page of a tenant's audit trail (requires `admin:tenant`; own tenant). */
  tenantAudit(tenantId: string, limit?: number, cursor?: string): Promise<AuditPage> {
    return this.request<AuditPage>(`/tenants/${enc(tenantId)}/audit${auditQs(limit, cursor)}`);
  }
  /** One page of a tenant user's audit trail (requires `manage:users`; own tenant). */
  userAudit(userId: string, limit?: number, cursor?: string): Promise<AuditPage> {
    return this.request<AuditPage>(`/users/${enc(userId)}/audit${auditQs(limit, cursor)}`);
  }
  /** A tenant user's active login sessions (requires `manage:users`; own tenant). */
  userSessions(userId: string): Promise<SessionView[]> {
    return this.request<SessionView[]>(`/users/${enc(userId)}/sessions`);
  }
  /** Revokes all of a tenant user's sessions by bumping their tokenVersion (requires `manage:users`). */
  async logoutUser(userId: string): Promise<void> {
    await this.request(`/users/${enc(userId)}/logout-all`, { method: "POST" });
  }

  // ── messaging links ─────────────────────────────────────────────────────────

  /** The caller's current link code (rotated if expired), with deep links when configured. */
  getMessagingCode(): Promise<MessagingCodeResponse> {
    return this.request<MessagingCodeResponse>("/auth/me/messaging-code");
  }
  /** Replace the caller's link code (invalidates the old). */
  regenerateMessagingCode(): Promise<MessagingCodeResponse> {
    return this.request<MessagingCodeResponse>("/auth/me/messaging-code/regenerate", {
      method: "POST",
    });
  }
  /** The caller's linked external identities. */
  listMessagingLinks(): Promise<{ links: MessagingLink[] }> {
    return this.request<{ links: MessagingLink[] }>("/auth/me/messaging-links");
  }
  /** Remove one of the caller's linked identities. */
  deleteMessagingLink(platform: string, externalId: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(
      `/auth/me/messaging-links/${enc(platform)}/${enc(externalId)}`,
      { method: "DELETE" },
    );
  }
  /** Machine (`messaging:link`): claim a `(platform, externalId)` mapping from a link code. */
  createMessagingLink(
    code: string,
    platform: string,
    externalId: string,
  ): Promise<{ userId: string; tenantId: string }> {
    return this.request<{ userId: string; tenantId: string }>("/messaging/links", {
      method: "POST",
      body: JSON.stringify({ code, platform, externalId }),
    });
  }
  /** Machine (`messaging:resolve`): resolve an identity to user info. */
  resolveMessaging(platform: string, externalId: string): Promise<ResolvedMessagingUser> {
    const qs = `?platform=${encodeURIComponent(platform)}&externalId=${encodeURIComponent(externalId)}`;
    return this.request<ResolvedMessagingUser>(`/messaging/resolve${qs}`);
  }
  /** Machine (`messaging:resolve`): resolve an identity to a minted token for `api`. */
  resolveMessagingToken(
    platform: string,
    externalId: string,
    api: string,
  ): Promise<{ accessToken: string; expiresIn: number }> {
    const qs =
      `?platform=${encodeURIComponent(platform)}&externalId=${encodeURIComponent(externalId)}` +
      `&format=jwt&api=${encodeURIComponent(api)}`;
    return this.request<{ accessToken: string; expiresIn: number }>(`/messaging/resolve${qs}`);
  }

  // ── config ────────────────────────────────────────────────────────────────────

  getConfig(): Promise<Config> {
    return this.request<Config>("/config");
  }
  putConfig(config: Config): Promise<Config> {
    return this.request<Config>("/config", { method: "PUT", body: JSON.stringify(config) });
  }
  /** The user + tenant custom-field schemas (any authenticated admin; no `manage:config` needed). */
  getCustomFields(): Promise<CustomFieldsSchema> {
    return this.request<CustomFieldsSchema>("/config/custom-fields");
  }

  // ── API keys: tenant service keys (write:members) ──────────────────────────────

  createApiKey(tenantId: string, request: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    return this.request<CreateApiKeyResponse>(`/tenants/${enc(tenantId)}/api-keys`, {
      method: "POST",
      body: JSON.stringify(request),
    });
  }
  async listApiKeys(tenantId: string): Promise<ApiKeyView[]> {
    const data = await this.request<{ keys: ApiKeyView[] }>(`/tenants/${enc(tenantId)}/api-keys`);
    return data.keys;
  }
  async deleteApiKey(tenantId: string, keyId: string): Promise<void> {
    await this.request(`/tenants/${enc(tenantId)}/api-keys/${enc(keyId)}`, { method: "DELETE" });
  }

  // ── Personal access tokens: your own (self-service) ────────────────────────────

  /** Create a personal access token that acts as the current user (optionally down-scoped).
   * The `apiKey` secret in the response is shown only once. */
  createMyPat(request: CreatePatRequest): Promise<CreateApiKeyResponse> {
    return this.request<CreateApiKeyResponse>("/auth/me/api-keys", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }
  async listMyPats(): Promise<ApiKeyView[]> {
    const data = await this.request<{ keys: ApiKeyView[] }>("/auth/me/api-keys");
    return data.keys;
  }
  async deleteMyPat(keyId: string): Promise<void> {
    await this.request(`/auth/me/api-keys/${enc(keyId)}`, { method: "DELETE" });
  }
  /** A tenant user's personal access tokens, read-only (requires `manage:users`; own tenant). */
  async listUserPats(userId: string): Promise<ApiKeyView[]> {
    const data = await this.request<{ keys: ApiKeyView[] }>(`/users/${enc(userId)}/pats`);
    return data.keys;
  }
}

function enc(value: string): string {
  return encodeURIComponent(value);
}

/** Builds a `?limit=&cursor=` query string for the audit endpoints (omitting absent params). */
function auditQs(limit?: number, cursor?: string): string {
  const params = new URLSearchParams();
  if (limit != null) {
    params.set("limit", String(limit));
  }
  if (cursor) {
    params.set("cursor", cursor);
  }
  const s = params.toString();
  return s ? `?${s}` : "";
}

/** Builds a `?q=&limit=` query string for the list endpoints (omitting absent params). */
function listQs(q?: string, limit?: number): string {
  const params = new URLSearchParams();
  if (q) {
    params.set("q", q);
  }
  if (limit != null) {
    params.set("limit", String(limit));
  }
  const s = params.toString();
  return s ? `?${s}` : "";
}
