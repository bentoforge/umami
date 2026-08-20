import type { CustomFieldDef, FeatureDef, Tenant } from "@bentoforge/umami-iam";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, useParams } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import {
  Banner,
  CustomFieldsForm,
  DropdownMenu,
  errMsg,
  Field,
  formatDateTime,
  formatFieldValue,
  Loader,
  Toggle,
} from "../components";
import { card, ghostButton, input, primaryButton } from "../ui";

/** Per-tenant edit view: a details card (read + inline edit), a features card, and an in-app Back. */
export function EditTenantPage() {
  const { client, me, activeTenantId, switchTenant } = useUmami();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { tenantId = "" } = useParams();

  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [defs, setDefs] = useState<CustomFieldDef[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);

  // The system tenant (home) and the tenant currently being acted in must not be deletable.
  const homeTenantId = me?.user.tenantId;
  const currentTenantId = activeTenantId ?? homeTenantId;
  const isProtected = (id: string) => id === homeTenantId || id === currentTenantId;

  const reload = useCallback(async () => {
    setError(null);
    try {
      setTenant(await client.getTenant(tenantId));
    } catch (err) {
      setError(errMsg(err));
      setMissing(true);
    }
  }, [client, tenantId]);

  useEffect(() => {
    void reload();
  }, [reload]);

  useEffect(() => {
    client
      .getCustomFields()
      .then((r) => setDefs(r.tenant))
      .catch(() => setDefs([]));
  }, [client]);

  const onDelete = async () => {
    if (!tenant || !window.confirm(t("tenants.deleteConfirm", { name: tenant.name }))) {
      return;
    }
    try {
      await client.deleteTenant(tenant.tenantId);
      navigate("/tenants");
    } catch (err) {
      setError(errMsg(err));
    }
  };

  // Back that stays inside our SPA history (never bounces to another site / the login page).
  const goBack = () => {
    const idx = (window.history.state as { idx?: number } | null)?.idx ?? 0;
    if (idx > 0) {
      navigate(-1);
    } else {
      navigate("/tenants");
    }
  };

  if (missing) {
    return (
      <div className="space-y-4">
        <Banner tone="error">{error ?? t("tenants.notFound")}</Banner>
        <button className={ghostButton} onClick={goBack}>
          {t("tenants.back")}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
          {t("tenants.editTitle")}
        </h1>
        {tenant && (
          <DropdownMenu
            label={t("tenants.actions")}
            triggerLabel={t("common.moreActions")}
            actions={[
              {
                label: t("tenants.impersonate"),
                onSelect: () => void switchTenant(tenant.tenantId, tenant.name),
              },
              ...(isProtected(tenant.tenantId)
                ? []
                : [
                    {
                      label: t("tenants.delete"),
                      danger: true,
                      onSelect: () => void onDelete(),
                    },
                  ]),
            ]}
          />
        )}
      </div>

      {error && <Banner tone="error">{error}</Banner>}
      {notice && <Banner tone="ok">{notice}</Banner>}

      {tenant === null ? (
        <Loader />
      ) : (
        <>
          <DetailsCard
            tenant={tenant}
            defs={defs}
            onSaved={async () => {
              setNotice(t("tenants.saved"));
              await reload();
            }}
            onError={setError}
          />
          <FeaturesCard tenant={tenant} onChanged={reload} onError={setError} />
          <MetaBox tenant={tenant} />
        </>
      )}

      <button className={ghostButton} onClick={goBack}>
        {t("tenants.back")}
      </button>
    </div>
  );
}

/** Read-only detail rows with an Edit toggle that turns Name + custom fields into inputs. Dates and
 * the ID are never editable. */
function DetailsCard({
  tenant,
  defs,
  onSaved,
  onError,
}: {
  tenant: Tenant;
  defs: CustomFieldDef[];
  onSaved: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(tenant.name);
  const [fields, setFields] = useState<Record<string, unknown>>({ ...tenant.customFields });
  const [saving, setSaving] = useState(false);

  // Reset the draft whenever the underlying tenant reloads.
  useEffect(() => {
    setName(tenant.name);
    setFields({ ...tenant.customFields });
  }, [tenant]);

  const cancel = () => {
    setName(tenant.name);
    setFields({ ...tenant.customFields });
    setEditing(false);
  };

  const save = async () => {
    setSaving(true);
    onError("");
    try {
      await client.patchTenant(tenant.tenantId, { name, customFields: fields });
      setEditing(false);
      await onSaved();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className={`${card} space-y-4`}>
      <div className="flex items-center justify-between">
        <h2 className="font-medium text-slate-800 dark:text-slate-200">
          {t("tenants.detailsTitle")}
        </h2>
        {!editing && (
          <button className={ghostButton} onClick={() => setEditing(true)}>
            {t("tenants.edit")}
          </button>
        )}
      </div>

      {editing ? (
        <>
          <div className="grid grid-cols-2 gap-3">
            <Field label={t("tenants.nameLabel")}>
              <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <CustomFieldsForm defs={defs} values={fields} onChange={setFields} />
          </div>
          <div className="flex gap-2">
            <button className={primaryButton} disabled={saving} onClick={() => void save()}>
              {t("tenants.save")}
            </button>
            <button className={ghostButton} disabled={saving} onClick={cancel}>
              {t("tenants.cancel")}
            </button>
          </div>
        </>
      ) : (
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
          <DetailRow label={t("tenants.nameLabel")}>{tenant.name}</DetailRow>
          {defs.map((def) => (
            <DetailRow key={def.key} label={def.label}>
              {formatFieldValue(tenant.customFields[def.key])}
            </DetailRow>
          ))}
        </dl>
      )}
    </section>
  );
}

/** Muted gray box with the read-only system metadata: ID, last active, last updated, created.
 * Two columns on desktop, one below. */
function MetaBox({ tenant }: { tenant: Tenant }) {
  const { t } = useTranslation();
  const rows: { label: string; value: ReactNode }[] = [
    {
      label: t("tenants.id"),
      value: <span className="font-mono text-xs break-all">{tenant.tenantId}</span>,
    },
    {
      label: t("tenants.lastActive"),
      value: tenant.lastActive ? formatDateTime(tenant.lastActive) : "—",
    },
    { label: t("tenants.updatedAt"), value: formatDateTime(tenant.lastUpdated) },
    { label: t("tenants.createdAt"), value: formatDateTime(tenant.created) },
  ];
  return (
    <section className="rounded border border-slate-200 dark:border-slate-700/50 bg-slate-100 dark:bg-slate-900/50 p-6">
      <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-3">
        {rows.map((row) => (
          <div key={row.label}>
            <dt className="text-xs text-slate-400">{row.label}</dt>
            <dd className="text-sm text-slate-600 dark:text-slate-300">{row.value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-800 dark:text-slate-200">{children}</dd>
    </>
  );
}

/** Grant/revoke a tenant's authorization features (`feature:*`) as a toggle list: a switch on the
 * left, the feature's name in bold, and its description (or code) muted below. A feature that is
 * neither granted nor currently grantable (unmet prerequisite) shows as a disabled switch. */
function FeaturesCard({
  tenant,
  onChanged,
  onError,
}: {
  tenant: Tenant;
  onChanged: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [defs, setDefs] = useState<FeatureDef[]>([]);
  const [grantable, setGrantable] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    client
      .getConfig()
      .then((c) => setDefs(c.features))
      .catch(() => setDefs([]));
  }, [client]);

  const loadGrantable = useCallback(() => {
    client
      .assignableFeatures(tenant.tenantId)
      .then((r) => setGrantable(r.codes))
      .catch(() => setGrantable([]));
  }, [client, tenant.tenantId]);

  useEffect(() => loadGrantable(), [loadGrantable]);

  const toggle = async (code: string, granted: boolean) => {
    setBusy(true);
    onError("");
    try {
      if (granted) {
        await client.revokeFeature(tenant.tenantId, code);
      } else {
        await client.grantFeature(tenant.tenantId, code);
      }
      await onChanged();
      loadGrantable();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  // The catalog, plus any already-granted code the catalog no longer defines (never hide a grant).
  const catalog: FeatureDef[] = [
    ...defs,
    ...tenant.features
      .filter((code) => !defs.some((d) => d.code === code))
      .map((code) => ({ code, name: code })),
  ];

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">
        {t("tenants.featuresTitle")}
      </h2>
      {catalog.length === 0 ? (
        <span className="text-xs text-slate-400">{t("tenants.featuresNone")}</span>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {catalog.map((def) => {
            const granted = tenant.features.includes(def.code);
            const canToggle = granted || grantable.includes(def.code);
            const subtitle = def.description || def.code;
            return (
              <li key={def.code} className="flex items-start gap-3 py-3">
                <div className="pt-0.5">
                  <Toggle
                    checked={granted}
                    disabled={busy || !canToggle}
                    label={def.name}
                    onChange={() => void toggle(def.code, granted)}
                  />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-slate-900 dark:text-white">
                    {def.name}
                  </div>
                  {subtitle && (
                    <div className="text-xs text-slate-400 dark:text-slate-500">{subtitle}</div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
