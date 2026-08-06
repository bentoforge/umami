import type {
  AccessClaims,
  ApiErrorBody,
  ApiKeyView,
  Config,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  CreateTenantRequest,
  CreateTenantResponse,
  CreateUserRequest,
  EntitlementsResponse,
  ExchangeResponse,
  FeatureToggle,
  LoginResponse,
  MeResponse,
  MetricUsage,
  MfaStatus,
  PatchUserRequest,
  Tenant,
  TenantStatus,
  TokenResponse,
  TotpSetup,
  UsageResponse,
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
  private async request<T>(
    path: string,
    init: RequestInit = {},
    useAuth = true,
  ): Promise<T> {
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

  /** Silent refresh via the cookie. Returns whether a fresh token was obtained. */
  async refresh(): Promise<boolean> {
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

  /** Current profile (user + tenant). */
  getMe(): Promise<MeResponse> {
    return this.request<MeResponse>("/auth/me");
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
    const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
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
    const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
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
  listTenants(q?: string): Promise<{ tenants: Tenant[]; truncated: boolean }> {
    const qs = q ? `?q=${encodeURIComponent(q)}` : "";
    return this.request<{ tenants: Tenant[]; truncated: boolean }>(`/tenants${qs}`);
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
  patchTenant(tenantId: string, body: Partial<Pick<Tenant, "name" | "plan" | "customFields">>): Promise<Tenant> {
    return this.request<Tenant>(`/tenants/${enc(tenantId)}`, { method: "PATCH", body: JSON.stringify(body) });
  }
  patchStatus(tenantId: string, status: TenantStatus): Promise<Tenant> {
    return this.request<Tenant>(`/tenants/${enc(tenantId)}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    });
  }
  patchLicense(
    tenantId: string,
    body: { plan?: string; billedUntil?: string; seatsLimit?: number },
  ): Promise<Tenant> {
    return this.request<Tenant>(`/tenants/${enc(tenantId)}/license`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  }
  getEntitlements(tenantId: string): Promise<EntitlementsResponse> {
    return this.request<EntitlementsResponse>(`/tenants/${enc(tenantId)}/entitlements`);
  }
  assignPackage(tenantId: string, request: { code: string; monthlyPrice?: string }): Promise<Tenant> {
    return this.request<Tenant>(`/tenants/${enc(tenantId)}/packages`, {
      method: "POST",
      body: JSON.stringify(request),
    });
  }
  removePackage(tenantId: string, assignmentId: string): Promise<Tenant> {
    return this.request<Tenant>(`/tenants/${enc(tenantId)}/packages/${enc(assignmentId)}`, {
      method: "DELETE",
    });
  }
  setFeature(tenantId: string, code: string, value: FeatureToggle): Promise<Tenant> {
    return this.request<Tenant>(`/tenants/${enc(tenantId)}/features/${enc(code)}`, {
      method: "PUT",
      body: JSON.stringify({ value }),
    });
  }
  getUsage(tenantId: string): Promise<UsageResponse> {
    return this.request<UsageResponse>(`/tenants/${enc(tenantId)}/usage`);
  }
  incrementUsage(tenantId: string, metric: string, amount = 1): Promise<MetricUsage> {
    return this.request<MetricUsage>(`/tenants/${enc(tenantId)}/usage/${enc(metric)}`, {
      method: "POST",
      body: JSON.stringify({ amount }),
    });
  }

  // ── users ────────────────────────────────────────────────────────────────────

  createUser(request: CreateUserRequest): Promise<UserView> {
    return this.request<UserView>("/users", { method: "POST", body: JSON.stringify(request) });
  }
  /** List the caller's tenant's users (sorted by recent activity, capped at 250). `q` is an
   * optional case-insensitive search over username / email / name / custom fields. */
  listUsers(q?: string): Promise<{ users: UserView[]; truncated: boolean }> {
    const qs = q ? `?q=${encodeURIComponent(q)}` : "";
    return this.request<{ users: UserView[]; truncated: boolean }>(`/users${qs}`);
  }
  patchUser(userId: string, body: PatchUserRequest): Promise<UserView> {
    return this.request<UserView>(`/users/${enc(userId)}`, { method: "PATCH", body: JSON.stringify(body) });
  }
  /** Hard-delete a user in the caller's tenant (cannot delete your own account). */
  deleteUser(userId: string): Promise<{ status: string }> {
    return this.request<{ status: string }>(`/users/${enc(userId)}`, { method: "DELETE" });
  }

  // ── config ────────────────────────────────────────────────────────────────────

  getConfig(): Promise<Config> {
    return this.request<Config>("/config");
  }
  putConfig(config: Config): Promise<Config> {
    return this.request<Config>("/config", { method: "PUT", body: JSON.stringify(config) });
  }

  // ── API keys ──────────────────────────────────────────────────────────────────

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
}

function enc(value: string): string {
  return encodeURIComponent(value);
}
