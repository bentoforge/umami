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

export type TenantStatus =
  | "Lead"
  | "Testing"
  | "Onboarding"
  | "Active"
  | "Suspended"
  | "Churned";

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

export interface RoleDef {
  code: string;
  name: string;
  permissions: string[];
}
export interface FeatureDef {
  code: string;
  name: string;
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
  type: string;
  required: boolean;
}
export interface SecuritySettings {
  minPasswordLength: number;
  accessTtlSecs: number;
  refreshTtlSecs: number;
}
/** A target API in the config catalog: its `aud`, eligibility gate, permission projection, and
 * claim mapping. See `docs/AUDIENCES.md`. */
export interface ApiDef {
  code: string;
  audience: string;
  /** If true, the token carries the requester's own role permissions verbatim. */
  passthrough?: boolean;
  /** Boolean expression (`,`=OR, `+`=AND over permissions∪features) gating the exchange. */
  eligibility?: string | null;
  /** Rule map: expression → injected permissions (union of all matching rules). */
  permissions?: Record<string, string[]>;
  /** Claim mapping: claimName → source (`features`, `customUser:<k>`, `customTenant:<k>`, literal). */
  claims?: Record<string, string>;
}

export interface Config {
  version: number;
  roles: RoleDef[];
  features: FeatureDef[];
  limits: LimitDef[];
  packages: PackageDef[];
  customTenantFields: CustomFieldDef[];
  customUserFields: CustomFieldDef[];
  security: SecuritySettings;
  /** The catalog of target APIs umami can mint tokens for. */
  apis: ApiDef[];
  /** @deprecated superseded by per-API `claims`; kept for back-compat. */
  tokenClaims: string[];
}

// ── API keys ──────────────────────────────────────────────────────────────────

export type ApiKeyStatus = "Active" | "Revoked";

export interface ApiKeyView {
  keyId: string;
  tenantId: string;
  /** Present for personal access tokens (the user the token acts as); null for service keys. */
  userId: string | null;
  name: string;
  /** Service-key role codes (empty for PATs). */
  roles: string[];
  /** PAT down-scoping — subset of the user's permissions (empty for service keys / full user perms). */
  scopes: string[];
  /** Target API codes this key may mint tokens for. */
  apis: string[];
  status: ApiKeyStatus;
  allowedOrigins: string[];
  expiresAt?: string | null;
  lastUsedAt?: string | null;
  created: string;
}

/** Create a tenant **service** key (machine principal, permissions from `roles`). */
export interface CreateApiKeyRequest {
  name: string;
  roles?: string[];
  /** Target API codes this key may mint for; defaults to `["umami"]`. */
  apis?: string[];
  allowedOrigins?: string[];
  expiresAt?: string;
}

/** Create a **personal access token** (acts as the current user; optionally down-scoped). */
export interface CreatePatRequest {
  name: string;
  /** Restrict the token to this subset of your own permissions (empty = all your permissions). */
  scopes?: string[];
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
