// Wire types for the umami API. Mirrors the Rust server contract (camelCase JSON).

// ── Tokens ──────────────────────────────────────────────────────────────────

/** Claims carried by an umami access token (JWT payload). */
export interface AccessClaims {
  iss: string;
  sub: string;
  aud?: string;
  /** The active tenant this token is scoped to. */
  tenant: string;
  email: string;
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
  /** Ready-to-render QR-code SVG of `otpauthUrl` (dark on white). */
  qrSvg: string;
}

// ── Users ───────────────────────────────────────────────────────────────────

/** How to address a user; the rendered word is composed server-side from the config labels. */
export type Salutation = "" | "SIR" | "MADAM";

/** Structured name parts (editable) plus the server-composed display names (read-only). */
export interface NameParts {
  title: string | null;
  /** BCP-47 tag, or `null` for the deployment's `defaultLocale`. */
  locale?: string | null;
  salutation: Salutation;
  firstname: string | null;
  lastname: string | null;
  /** `title firstname lastname` — **no** salutation. Render this in a localized UI and prepend
   * the salutation word from your own catalogue; the two fields below carry the server's word. */
  name: string;
  /** `salutation title firstname lastname`, salutation in the user's (or deployment's) language. */
  fullName: string;
  /** `salutation title lastname`, same language rule. For addressing in mail/messaging. */
  addressableName: string;
}

export interface UserView extends NameParts {
  userId: string;
  tenantId: string;
  roles: string[];
  /** Login identifier — unique. */
  username: string;
  /** Optional contact email — not unique, may be null/absent. */
  email: string | null;
  /** Admin lock — a locked user cannot log in. */
  locked: boolean;
  customFields: Record<string, unknown>;
  /** RFC3339 creation timestamp. */
  created: string;
  /** RFC3339 timestamp of the last change to this record. */
  lastUpdated: string;
  /** RFC3339 timestamp of the user's last authentication (login/refresh); null until first active. */
  lastSeen: string | null;
  /** User id that created / last changed this user (audit; not surfaced in the UI yet). */
  createdBy?: string | null;
  lastChangedBy?: string | null;
  /** Whether TOTP MFA is configured (never exposes the secret). */
  mfaEnabled: boolean;
  /** Whether the current password came from an admin reset and hasn't been changed since. */
  passwordGenerated: boolean;
  /** Whether the user has at least one registered passkey. */
  hasPasskey: boolean;
}

/** The editable structured name parts (all optional; omitted = unset, `""` clears). */
export interface NameInput {
  title?: string;
  /** BCP-47 tag; `""` clears it back to the deployment default. */
  locale?: string;
  salutation?: Salutation;
  firstname?: string;
  lastname?: string;
}

export interface CreateUserRequest extends NameInput {
  /** Login username (unique). If omitted, `email` is used as the username. */
  username?: string;
  /** Optional contact email (not unique). */
  email?: string;
  /** Optional initial password. Omit (the normal case) to have a temporary one generated and
   * returned once in {@link CreateUserResponse.temporaryPassword}. */
  password?: string;
  roles?: string[];
  customFields?: Record<string, unknown>;
}

/** The created user, plus the one-time temporary password when one was generated. */
export type CreateUserResponse = UserView & {
  /** Present only when the server generated the initial password — shown once. */
  temporaryPassword?: string | null;
};

export interface PatchUserRequest extends NameInput {
  /** New login username (globally unique). Omit to leave unchanged; must not be empty. */
  username?: string;
  /** Contact email. Omit to leave unchanged; empty string clears it. */
  email?: string;
  roles?: string[];
  locked?: boolean;
  customFields?: Record<string, unknown>;
}

// ── Me ──────────────────────────────────────────────────────────────────────

export interface MeUser extends NameParts {
  userId: string;
  tenantId: string;
  roles: string[];
  username: string;
  email: string | null;
  locked: boolean;
  customFields: Record<string, unknown>;
  /** Whether TOTP MFA is configured (never exposes the secret). */
  mfaEnabled: boolean;
  /** Whether the caller has at least one registered passkey. */
  hasPasskey: boolean;
}

export interface MeResponse {
  user: MeUser;
  /** The user's **home** tenant — where their roles and entitlements live. */
  tenant: Tenant | null;
  /**
   * The tenant this session is currently acting for, present only while it
   * differs from home. Without it a client can tell *that* it is impersonating
   * but not *whom*, and falls back to announcing the user's own tenant.
   */
  activeTenant?: Tenant | null;
}

/** One of the caller's active login sessions (device). Never exposes the refresh secret. */
export interface SessionView {
  sessionId: string;
  userAgent?: string;
  ip?: string;
  /** RFC3339 creation timestamp. */
  created: string;
  /** RFC3339 timestamp of the last refresh. */
  lastSeen: string;
  /** RFC3339 absolute expiry. */
  expiresAt: string;
  /** Whether this is the session making the request. */
  current: boolean;
}

// ── Tenants ──────────────────────────────────────────────────────────────────

export interface Tenant {
  tenantId: string;
  version: number;
  /** Authorization features granted to the tenant (`feature:*`), fed to the token broker. */
  features: string[];
  customFields: Record<string, unknown>;
  name: string;
  slug: string;
  created: string;
  lastUpdated: string;
  /** RFC3339 timestamp of the last token activity (refresh / exchange) scoped to this tenant;
   * null until the first activity. */
  lastActive?: string | null;
  /** Sort key backing the tenant listing: `lastActive` when present, else `created`. */
  lastActiveOrCreated?: string;
  /** User id that created this tenant (audit; not surfaced in the UI yet). */
  createdBy?: string | null;
  /** User id of the last change to this tenant (audit; not surfaced in the UI yet). */
  lastChangedBy?: string | null;
}

export interface CreateTenantRequest {
  name: string;
  /** Optional first owner. Omit to create an empty tenant (add users afterwards by impersonating
   * it on the Tenants screen). */
  owner?: {
    /** Owner login username (unique). If omitted, `email` is used as the username. */
    username?: string;
    /** Optional contact email (not unique). */
    email?: string;
    password: string;
  };
  /** Custom-field values, validated against `customTenantFields`. */
  customFields?: Record<string, unknown>;
}

export interface CreateTenantResponse {
  tenantId: string;
  /** The created owner's user id — only present when an `owner` was supplied. */
  ownerUserId: string | null;
}

// ── Config ────────────────────────────────────────────────────────────────────

/** A role assignable to a user (`role:*`). Permissions come from the per-API rules, not here. */
export interface RoleDef {
  code: string;
  name: string;
  /** Optional human-readable description (shown muted under the name in the admin UI). */
  description?: string | null;
  /** Boolean expression over the tenant's `feature:*`/`is:*` gating whether it may be assigned. */
  assignableIf?: string | null;
}
/** A scope carried by an M2M service key (`scope:*`); same assignability gating as roles. */
export interface ScopeDef {
  code: string;
  name: string;
  /** Optional human-readable description (shown muted under the name in the admin UI). */
  description?: string | null;
  assignableIf?: string | null;
}
/** An authorization feature granted to a tenant (`feature:*`). */
export interface FeatureDef {
  code: string;
  name: string;
  /** Optional human-readable description (shown muted under the name in the admin UI). */
  description?: string | null;
  /** Boolean expression over the tenant's current features gating whether it may be granted. */
  assignableIf?: string | null;
}
export interface CustomFieldDef {
  code: string;
  label: string;
  /** `"string"` | `"number"` | `"bool"` | `"select"`. */
  type: string;
  /** Allowed values for a `select` field (ignored otherwise). */
  options?: string[];
  required: boolean;
  /** Whether admin list tables surface this field as a column. */
  showInTable?: boolean;
  /** Whether the user may edit this field on themselves via `PATCH /auth/me`. */
  selfEditable?: boolean;
}

/** The custom-field schemas for rendering user/tenant forms (`GET /config/custom-fields`). */
export interface CustomFieldsSchema {
  user: CustomFieldDef[];
  tenant: CustomFieldDef[];
  /** Languages the deployment can actually answer in — the message catalogue, narrowed by
   *  `config.locales`. Render the language picker from this, never from a list of your own: a
   *  UI-side list offers languages the server will then answer in English. */
  locales: string[];
  /** Used when a user expresses no preference. */
  defaultLocale: string;
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
  /** Claim mapping: claimName → source. A source is a literal string, a `$user.<field>` /
   * `$tenant.<field>` reference (`id`, `username`, `email`, `name`, `fullName`, `addressableName`,
   * `roles`, `name`/`slug`/`features`, …), or `$user.custom.<key>` / `$tenant.custom.<key>`. */
  claims?: Record<string, string>;
}

export interface Config {
  version: number;
  roles: RoleDef[];
  /** Scopes assignable to M2M service keys. */
  scopes: ScopeDef[];
  features: FeatureDef[];
  customTenantFields: CustomFieldDef[];
  customUserFields: CustomFieldDef[];
  /** Language umami renders in when no user preference applies (BCP-47). A user's own `locale`
   * wins. Salutation *words* are per-locale constants in umami, not configuration. */
  defaultLocale: string;
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
  /** Whether the raw-secret (Mode 1) exchange is allowed; false ⇒ HMAC-only (Mode 2). */
  allowSecretLogin: boolean;
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
  /** Allow the raw-secret (Mode 1) exchange; omitted/false ⇒ HMAC-only (Mode 2). */
  allowSecretLogin?: boolean;
  allowedOrigins?: string[];
  expiresAt?: string;
}

/** Create a **personal access token** (acts as the current user; optionally role-restricted). */
export interface CreatePatRequest {
  name: string;
  /** Restrict the token to this subset of your own `role:*` (empty = all your roles). */
  roles?: string[];
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
  /** Browser tab title (document `<title>`); served at /app/branding.json, applied at runtime.
   * Empty → "umami". */
  title?: string;
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
  email?: string | null;
  roles: string[];
}

// ── Audit log ───────────────────────────────────────────────────────────────

/** Outcome flavour of an audited event. */
export type AuditSeverity = "good" | "neutral" | "bad";

/** One page of audit entries plus the cursor to fetch the next (absent when the trail is exhausted). */
export interface AuditPage {
  entries: AuditEntry[];
  nextCursor?: string;
}

export interface AuditEntry {
  id: string;
  /** RFC3339 event time. */
  timestamp: string;
  tenant?: string | null;
  user?: string | null;
  severity: AuditSeverity;
  message: string;
  /** Best-effort client IP, present on security-relevant events (logins, credential/account
   * changes). Absent on events with no request IP. */
  ip?: string | null;
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
