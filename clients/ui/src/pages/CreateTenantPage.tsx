import type { CustomFieldDef } from "@bentoforge/umami-iam";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, CustomFieldsForm, errMsg, Field } from "../components";
import { card, ghostButton, input, primaryButton } from "../ui";

/** Dedicated view: create an (initially empty) tenant from name + custom fields, then jump straight
 * into its edit view. Owner/users are added afterwards by impersonating the tenant. */
export function CreateTenantPage() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [defs, setDefs] = useState<CustomFieldDef[]>([]);
  const [name, setName] = useState("");
  const [fields, setFields] = useState<Record<string, unknown>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    client
      .getCustomFields()
      .then((r) => setDefs(r.tenant))
      .catch(() => setDefs([]));
  }, [client]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await client.createTenant({ name, customFields: fields });
      navigate(`/tenants/${encodeURIComponent(res.tenantId)}`, { replace: true });
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
        {t("tenants.createTitle")}
      </h1>

      {error && <Banner tone="error">{error}</Banner>}

      <section className={`${card} space-y-4`}>
        <div className="grid grid-cols-2 gap-3">
          <Field label={t("tenants.nameLabel")}>
            <input
              className={input}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </Field>
          <CustomFieldsForm defs={defs} values={fields} onChange={setFields} />
        </div>
        <div className="flex gap-2">
          <button
            className={primaryButton}
            disabled={busy || !name.trim()}
            onClick={() => void submit()}
          >
            {t("tenants.create")}
          </button>
          <button className={ghostButton} disabled={busy} onClick={() => navigate("/tenants")}>
            {t("tenants.cancel")}
          </button>
        </div>
      </section>
    </div>
  );
}
