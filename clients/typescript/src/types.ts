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
  email: string;
  password: string;
  totpCode?: string;
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
  email: string;
  name: string;
  locale: string;
  status: UserStatus;
  customFields: Record<string, unknown>;
}

export interface CreateUserRequest {
  email: string;
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
    email: string;
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
    email: string;
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
export interface Config {
  version: number;
  roles: RoleDef[];
  features: FeatureDef[];
  limits: LimitDef[];
  packages: PackageDef[];
  customTenantFields: CustomFieldDef[];
  customUserFields: CustomFieldDef[];
  security: SecuritySettings;
  tokenClaims: string[];
}

// ── API keys ──────────────────────────────────────────────────────────────────

export type ApiKeyStatus = "Active" | "Revoked";

export interface ApiKeyView {
  keyId: string;
  tenantId: string;
  name: string;
  roles: string[];
  status: ApiKeyStatus;
  allowedOrigins: string[];
  expiresAt?: string | null;
  lastUsedAt?: string | null;
  created: string;
}

export interface CreateApiKeyRequest {
  name: string;
  roles?: string[];
  allowedOrigins?: string[];
  expiresAt?: string;
}

export interface CreateApiKeyResponse {
  keyId: string;
  /** The full `umk_…` secret — returned only once. */
  apiKey: string;
  name: string;
  roles: string[];
  allowedOrigins: string[];
}

/** Error shape returned by the server (wasabi `ApiError`). */
export interface ApiErrorBody {
  message?: string;
  [k: string]: unknown;
}
