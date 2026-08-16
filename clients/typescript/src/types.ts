// Wire types for the umami API. Mirrors the Rust server contract (camelCase JSON).

// ── Tokens ──────────────────────────────────────────────────────────────────

/** Claims carried by an umami access token (JWT payload). */
export interface AccessClaims {
  iss: string;
  sub: string;
  aud?: string;
  /** The active tenant this token is scoped to. */
  tenant: string;
  name: string;
  email: string;
  locale: string;
  permissions: string[];
  iat: number;
  exp: number;
  /** user.tokenVersion snapshot. */
  ver: number;
  /** Present on machine tokens issued via API-key exchange. */
  kind?: "api_key";
  /** Effective tenant features, when the config requests the `features` claim. */
  features?: string[];
  [claim: string]: unknown;
}

// ── Auth ────────────────────────────────────────────────────────────────────

export interface LoginRequest {
  username: string;
  password: string;
  totpCode?: string;
  /** Optional target API to mint the access token for directly (default: `umami`). The session
   * remembers it, so refreshes keep the same audience. See `docs/AUDIENCES.md`. */
  api?: string;
}

/** Either an MFA challenge (`mfaRequired: true`, no token) or success (an access token). */
export interface LoginResponse {
  mfaRequired: boolean;
  accessToken?: string;
  tenants: string[];
}

export interface TokenResponse {
  accessToken: string;
  tenants: string[];
}

export interface ExchangeResponse {
  accessToken: string;
  expiresIn: number;
}

export interface MfaStatus {
  enabled: boolean;
}

export interface TotpSetup {
  /** Base32 secret for manual entry. */
  secret: string;
  /** `otpauth://` URL for QR rendering. */
  otpauthUrl: string;
}

// ── Users ───────────────────────────────────────────────────────────────────

export type UserStatus = "Active" | "Locked" | "Invited";

export interface UserView {
  userId: string;
  tenantId: string;
  roles: string[];
  /** Login identifier — unique. */
  username: string;
  /** Optional contact email — not unique, may be null/absent. */
  email: string | null;
  name: string;
  locale: string;
  status: UserStatus;
  customFields: Record<string, unknown>;
  /** RFC3339 creation timestamp. */
  created: string;
  /** RFC3339 timestamp of the user's last authentication (login/refresh). */
  lastSeen: string;
}

export interface CreateUserRequest {
  /** Login username (unique). If omitted, `email` is used as the username. */
  username?: string;
  /** Optional contact email (not unique). */
  email?: string;
  password: string;
  name: string;
  locale?: string;
  roles?: string[];
  customFields?: Record<string, unknown>;
}

export interface PatchUserRequest {
  roles?: string[];
  status?: UserStatus;
  customFields?: Record<string, unknown>;
}

// ── Me ──────────────────────────────────────────────────────────────────────

export interface MeResponse {
  user: {
    userId: string;
    tenantId: string;
    roles: string[];
    username: string;
    email: string | null;
    name: string;
    locale: string;
    status: UserStatus;
  };
  tenant: Tenant | null;
}

// ── Tenants ──────────────────────────────────────────────────────────────────

export type TenantStatus = "Lead" | "Testing" | "Onboarding" | "Active" | "Suspended" | "Churned";

export type FeatureToggle = "standard" | "on" | "off";

export interface PackageAssignment {
  id: string;
  code: string;
  assignedAt: string;
  accountedUntil?: string | null;
  monthlyPrice?: string | null;
  priceFixedUntil?: string | null;
  active: boolean;
}

export interface Tenant {
  tenantId: string;
  version: number;
  packages: PackageAssignment[];
  limitOverrides: Record<string, string>;
  featureOverrides: Record<string, FeatureToggle>;
  /** Authorization features granted to the tenant (`feature:*`), fed to the token broker. */
  features: string[];
  customFields: Record<string, unknown>;
  name: string;
  slug: string;
  status: TenantStatus;
  plan: string;
  billedUntil?: string | null;
  seatsLimit?: number | null;
  created: string;
  lastUpdated: string;
}

export interface CreateTenantRequest {
  name: string;
  owner: {
    /** Owner login username (unique). If omitted, `email` is used as the username. */
    username?: string;
    /** Optional contact email (not unique). */
    email?: string;
    password: string;
    name: string;
    locale?: string;
  };
  /** Custom-field values, validated against `customTenantFields`. */
  customFields?: Record<string, unknown>;
}

export interface CreateTenantResponse {
  tenantId: string;
  ownerUserId: string;
}

export interface EntitlementsResponse {
  limits: Record<string, string>;
  features: string[];
  monthlyTotal: string;
  packages: PackageAssignment[];
}

export interface MetricUsage {
  metric: string;
  used: number;
  limit?: string;
  overQuota: boolean;
}

export interface UsageResponse {
  period: string;
  metrics: MetricUsage[];
}

// ── Config ────────────────────────────────────────────────────────────────────

/** A role assignable to a user (`role:*`). Permissions come from the per-API rules, not here. */
export interface RoleDef {
  code: string;
  name: string;
  /** Boolean expression over the tenant's `feature:*`/`is:*` gating whether it may be assigned. */
  assignableIf?: string | null;
}
/** A scope carried by an M2M service key (`scope:*`); same assignability gating as roles. */
export interface ScopeDef {
  code: string;
  name: string;
  assignableIf?: string | null;
}
/** An authorization feature granted to a tenant (`feature:*`). */
export interface FeatureDef {
  code: string;
  name: string;
  /** Boolean expression over the tenant's current features gating whether it may be granted. */
  assignableIf?: string | null;
}
export interface LimitDef {
  code: string;
  name: string;
  unit?: string;
  default?: string;
}
export interface PackageLimit {
  code: string;
  value: string;
}
export interface PriceEntry {
  validFrom: string;
  price: string;
}
export interface PackageDef {
  code: string;
  name: string;
  features: string[];
  limits: PackageLimit[];
  prices: PriceEntry[];
}
export interface CustomFieldDef {
  key: string;
  label: string;
  /** `"string"` | `"number"` | `"bool"` | `"select"`. */
  type: string;
  /** Allowed values for a `select` field (ignored otherwise). */
  options?: string[];
  required: boolean;
  /** Whether admin list tables surface this field as a column. */
  showInTable?: boolean;
}

/** The custom-field schemas for rendering user/tenant forms (`GET /config/custom-fields`). */
export interface CustomFieldsSchema {
  user: CustomFieldDef[];
  tenant: CustomFieldDef[];
}
export interface SecuritySettings {
  minPasswordLength: number;
  accessTtlSecs: number;
  refreshTtlSecs: number;
  /** Validity window for a messaging link code (seconds); older codes rotate on read / reject on link. */
  messagingCodeTtlSecs?: number;
}
/** An ordered permission rule: when `when` holds against the accumulated subject set, `grant` is
 * folded in (later rules see earlier grants). An empty `when` always applies. */
export interface PermissionRule {
  when: string;
  grant: string[];
}
/** A target API in the config catalog: its `aud`, eligibility gate, ordered permission projection,
 * and claim mapping. See `docs/PERMISSIONS.md`. */
export interface ApiDef {
  code: string;
  audience: string;
  /** Boolean expression (`,`=OR, `+`=AND, `!`=NOT) over the final subject set gating the exchange. */
  eligibility?: string | null;
  /** Ordered rules mapping subjects → granted permissions (accumulated top-to-bottom). */
  permissions: PermissionRule[];
  /** Claim mapping: claimName → source (`customUser:<k>`, `customTenant:<k>`, or a literal). */
  claims?: Record<string, string>;
}

export interface Config {
  version: number;
  roles: RoleDef[];
  /** Scopes assignable to M2M service keys. */
  scopes: ScopeDef[];
  features: FeatureDef[];
  limits: LimitDef[];
  packages: PackageDef[];
  customTenantFields: CustomFieldDef[];
  customUserFields: CustomFieldDef[];
  security: SecuritySettings;
  /** Messaging integration (Telegram/WhatsApp) settings. */
  messaging?: MessagingConfig;
  /** White-labeling for the management UI. */
  branding?: BrandingConfig;
  /** The catalog of target APIs umami can mint tokens for. */
  apis: ApiDef[];
}

// ── API keys ──────────────────────────────────────────────────────────────────

export type ApiKeyStatus = "Active" | "Revoked";

export interface ApiKeyView {
  keyId: string;
  tenantId: string;
  /** Present for personal access tokens (the user the token acts as); null for service keys. */
  userId: string | null;
  name: string;
  /** PAT role restriction — subset of the user's `role:*` (empty for service keys / all roles). */
  roles: string[];
  /** Service-key `scope:*` subjects (empty for PATs). */
  scopes: string[];
  /** Target API codes this key may mint tokens for. */
  apis: string[];
  status: ApiKeyStatus;
  allowedOrigins: string[];
  expiresAt?: string | null;
  lastUsedAt?: string | null;
  created: string;
}

/** Create a tenant **service** key (M2M machine principal; subjects are its `scope:*`). */
export interface CreateApiKeyRequest {
  name: string;
  /** The `scope:*` subjects this key carries (must be assignable given the tenant's features). */
  scopes?: string[];
  /** Target API codes this key may mint for; defaults to `["umami"]`. */
  apis?: string[];
  allowedOrigins?: string[];
  expiresAt?: string;
}

/** Create a **personal access token** (acts as the current user; optionally role-restricted). */
export interface CreatePatRequest {
  name: string;
  /** Restrict the token to this subset of your own `role:*` (empty = all your roles). */
  roles?: string[];
  /** Target API codes this PAT may mint for; defaults to `["umami"]`. */
  apis?: string[];
  expiresAt?: string;
}

export interface CreateApiKeyResponse {
  keyId: string;
  /** The full `umk_…` secret — returned only once. */
  apiKey: string;
  name: string;
}

/** White-labeling for the management UI. All optional; empty → built-in defaults. `logo`/`favicon`
 * may be a `data:` URI or an `http(s)` URL. Served at /app/branding.css, /app/logo, /app/favicon. */
export interface BrandingConfig {
  /** Extra CSS injected after the app stylesheet — override the accent via
   * `:root{--brand: <r> <g> <b>; --brand-dark: <r> <g> <b>}` (space-separated RGB channels). */
  customCss?: string;
  /** Logo for light backgrounds (data: URI or http(s) URL); falls back to logoDark, then default. */
  logoLight?: string;
  /** Logo for dark backgrounds; falls back to logoLight, then default. */
  logoDark?: string;
  favicon?: string;
}

/** Messaging integration settings (Telegram/WhatsApp). */
export interface MessagingConfig {
  /** WhatsApp business number (digits) for click-to-chat links. */
  whatsappNumber?: string;
  /** Telegram bot username (without `@`) for deep links. */
  telegramBot?: string;
}

// ── Messaging links ───────────────────────────────────────────────────────────

/** The caller's link code plus ready-made deep links (when the deployment is configured). */
export interface MessagingCodeResponse {
  code: string;
  telegramUrl?: string;
  whatsappUrl?: string;
}

/** An external messaging identity mapped to a user. */
export interface MessagingLink {
  linkKey: string;
  userId: string;
  tenantId: string;
  /** `"telegram"` | `"whatsapp"`. */
  platform: string;
  externalId: string;
  created: string;
}

/** Resolve output (default): compact user info for a messaging identity. */
export interface ResolvedMessagingUser {
  userId: string;
  tenantId: string;
  name: string;
  email?: string | null;
  locale: string;
  roles: string[];
}

// ── Audit log ───────────────────────────────────────────────────────────────

/** Outcome flavour of an audited event. */
export type AuditSeverity = "good" | "neutral" | "bad";

export interface AuditEntry {
  id: string;
  /** RFC3339 event time. */
  timestamp: string;
  tenant?: string | null;
  user?: string | null;
  severity: AuditSeverity;
  message: string;
}

/** Result of an admin password reset — `temporaryPassword` is set (once) only when generated. */
export interface ResetPasswordResponse {
  status: string;
  temporaryPassword?: string;
}

/** Error shape returned by the server (wasabi `ApiError`). */
export interface ApiErrorBody {
  message?: string;
  [k: string]: unknown;
}
