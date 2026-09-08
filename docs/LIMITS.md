# Limits

Mandantenweite Kontingente — verbrauchbare Guthaben (AI-Credits/Tokens) und absolute
Obergrenzen — die in der Config als Katalog definiert, je Mandant mit Werten belegt und zur
Laufzeit atomar verbucht werden.

Limits reihen sich in umamis Katalog-Konzepte (Rollen, Scopes, Features) ein: eine **globale
Definition** sagt, *was* ein Limit ist; ein **Wert je Mandant** sagt, *wie viel*; ein
**Laufzeit-State** hält die Zähler. Anders als Rollen/Scopes/Features tragen Limits echten,
ständig veränderlichen Zustand — deshalb die dritte Schicht.

## Herkunft

Der verbrauchbare Kern ist eine Verallgemeinerung des AI-Budget-Subsystems aus `pip-core`
(`src/ai/limits/`): pro `(issuer, tenant)` ein monatliches Credit-Kontingent mit Overuse und
optionalem Tages-Cap, atomar gebucht, Limits auf die Periodenzeile gestempelt. Neu gegenüber
pip sind: **Sonderguthaben** (persistentes Top-up), **Gauge-Limits** mit Watermarks, ein
**Transaktions-Ledger**, eine **Monats-History** und ein backend-agnostischer Schnitt zwischen
Buchungslogik und Speicher.

## Die drei Schichten

| Schicht | Ort | Inhalt | Änderungsrate |
|---|---|---|---|
| **L1 Katalog** | `Config.limits: Vec<LimitDef>` | *Was* ein Limit ist: Typ, aktive Facetten, Watermarks, Labels | selten (Deploy) |
| **L2 Mandanten-Konfig** | `Tenant.limits: BTreeMap<String, LimitSettings>` | *Wie viel* je Mandant: monthly, overuse, daily, gauge-max | selten (Admin/UI) |
| **L3 Laufzeit-State** | `limits`-Repository (drei Tabellen) | Zähler, Sonderguthaben, Ledger, History | ständig (jeder Call) |

L1 folgt exakt `FeatureDef`, L2 exakt `custom_fields` — beide sind reine umami-Muster. L3 ist
neu und nutzt das atomare Update-Muster aus `auth/ratelimit` und `tenants` (OCC).

## L1 — `LimitDef` (Katalog)

In `src/config/mod.rs` neben `FeatureDef`, als Feld `limits: Vec<LimitDef>` auf `Config` mit
`#[serde(default)]` (Back-Compat wie alle Katalog-Listen).

```rust
pub enum LimitKind {
    /// Verbrauchbares Guthaben, das runtergebucht wird (AI-Credits, Tokens).
    Consumable,
    /// Absolute Obergrenze mit aktuellem Wert (nur setzen, nie buchen).
    Gauge,
}

pub struct LimitDef {
    pub code: String,
    pub name: LocalizedText,
    pub description: Option<LocalizedText>,
    pub kind: LimitKind,

    // Consumable-Facetten (opt-in; das monatliche Guthaben ist immer vorhanden):
    #[serde(default)] pub overuse: bool,          // Overuse-Bucket erlaubt?
    #[serde(default)] pub custom_balance: bool,    // Sonderguthaben zubuchbar?
    #[serde(default)] pub daily: bool,             // Daily-Throttle aktiv?

    // Gauge-Facetten (Prozent des max; UI hebt ab Schwelle hervor):
    #[serde(default)] pub low_watermark_percent: Option<u8>,
    #[serde(default)] pub high_watermark_percent: Option<u8>,

    // Anzeige-/Relevanz-Hinweis (DSL über feature:*/is:*): welche Limits man für einen Mandanten
    // überhaupt einblendet. KEINE Eligibility/Durchsetzung — ein Limit mit Settings + State wird
    // unabhängig davon gebucht. None = für jeden Mandanten relevant.
    #[serde(default)] pub relevant_if: Option<String>,
}
```

**Validierung** beim `PUT /config`:

- `validate_labels` um Limit-Namen erweitern (nicht-leer).
- Neues `validate_limits`: Facetten-Konsistenz (`overuse`/`custom_balance`/`daily` nur bei
  `Consumable`, Watermarks nur bei `Gauge`), Prozente ≤ 100, `low < high`.

**Katalog-Endpoint** `GET /config/catalogue` liefert die aufgelösten Limit-Defs mit (dann fällt
UI-Arbeit für die Definitionen weg; die `ConfigPage` editiert das Roh-JSON ohnehin schon).

## L2 — `Tenant.limits` (Werte je Mandant)

Neues Feld auf `Tenant` (`src/tenants/mod.rs`), analog `custom_fields`:

```rust
pub struct LimitSettings {          // je (tenant, limitCode)
    pub monthly: Option<i64>,       // Consumable: inkludiert pro Monat
    pub overuse: Option<i64>,       // Consumable: zusätzlich tolerierbar pro Monat
    pub daily:   Option<i64>,       // Consumable: Tages-Cap
    pub max:     Option<i64>,       // Gauge: absolute Obergrenze
}
```

Validiert gegen die `LimitDef` (nur aktive Facetten dürfen Werte tragen; Muster
`Config::validate_custom_fields`). Gesetzt über `PUT /tenants/{id}/limits/{code}/settings`,
gestempelt mit `last_changed_by` + Tenant-OCC-`version`, wie `grant_feature`.

### Kluges Reconciliation beim Settings-Change

Ändert sich `monthly`/`overuse` mit-Monat, wird die existierende L3-State-Zeile abgeglichen
(pure Funktion `accounting::apply_settings_change`) über
`usedMonthly = monthlySnapshot − monthlyRemaining`:

| Fall | Ergebnis |
|---|---|
| `newMonthly > oldMonthly` | `remaining += (newMonthly − oldMonthly)` — vergrößern |
| `oldMonthly > newMonthly > usedMonthly` | `remaining = newMonthly − usedMonthly` — verkleinern |
| `newMonthly ≤ usedMonthly` | `remaining = 0` — auf Usage gedeckelt, **Warnung** in der Response |

`used = snapshot − remaining`. Analog `overuse`. `customBalance` bleibt unberührt (nur `topup`).
Gauge-`max`-Änderung lässt den aktuellen Wert stehen (kann danach >max sein → Warnung). Existiert
noch keine State-Zeile (Limit nie benutzt), wird nur `Tenant.limits` geschrieben — nichts zu
reconcilen (der erste Call baut den State aus den neuen Settings).

**Zweistufig, nicht cross-table-atomar**: erst wird `Tenant.limits` (L2, die Quelle der Wahrheit)
per `put_tenant` geschrieben, dann der L3-State über dieselbe OCC-Schleife + `compare_and_swap`
abgeglichen (mit `settings`-Ledger-Eintrag). Kein `TransactWriteItems` über beide Tabellen — ein
Abbruch nach dem L2-Write verzögert die Wirkung höchstens bis zum nächsten Monat (Rollover baut aus
L2) und der Retry ist idempotent (`used`-basiert). Warnungen kommen sofort in der Response.

## L3 — State, Ledger, History

Drei Tabellen, provisioniert in `DynamoLimitRepository::with_client`.

### `limit-state` — Hash `tenantId`, Range `limitCode`

Eine Zeile je Mandant×Limit, der heiße atomare Datensatz:

```
periodYearMonth    "2026-09"   für welchen Monat monthly/overuse gerade gelten
monthlyRemaining               verfällt am Monatsende
overuseRemaining               verfällt am Monatsende
monthlySnapshot                aus Tenant.limits bei Periodenstart kopiert
overuseSnapshot                aus Tenant.limits bei Periodenstart kopiert
customBalance                  persistent, verfällt NICHT
dailyRemaining, dailyDate      Daily-Throttle (Facette)
gaugeValue, gaugeMonth         Gauge: aktueller Wert, immer aktueller Monat
version                        OCC
```

`monthlySnapshot`/`overuseSnapshot` sind lasttragend: `usedMonthly = snapshot − remaining` ist
so auch bei Mitte-Monat-Settings-Änderung wohldefiniert.

### `limit-ledger` — Hash `tenantId#limitCode`, Range `timestamp#id`

Append-only, jede Bewegung mit Bucket-Aufschlüsselung. Optional TTL.

```
type: consume | topup | reset | gaugeSet | settings
amount
monthlyDrawn, customDrawn, overuseDrawn     (consume; Reihenfolge = Kaskade)
overdrawn                                    (consume, falls über alle Buckets hinaus)
customAdded                                  (topup)
monthlyForfeited, overuseForfeited           (reset)
resultingMonthly, resultingCustom, resultingOveruse
// Actor/Kontext — optional, caller-provided, KEINE umami-Validierung:
actorUserId, actorUserName, txnName, txnId
```

`actorUserName` ist GDPR-sensibel; eine strenge Umgebung schickt ihn nicht und verknüpft nur
über `actorUserId`/`txnId`, oder schwärzt/TTL't den Ledger. Kein Deploy-Schalter in v1.

### `limit-history` — Hash `tenantId`, Range `limitCode#YYYY-MM`

Eine Zeile je abgeschlossenem Monat, geschrieben beim Rollover (s.u.), Guard
`attribute_not_exists` → idempotent.

```
monthlyIncluded, monthlyUsed, monthlyForfeited
overuseLimit, overuseUsed
customDrawnDuringMonth, endingCustomBalance
txnCount
```

## Buchungslogik

### Kaskade (Consumable)

Abzug in fester Reihenfolge: **monthly → custom → overuse**. Zuerst das inkludierte
Monatsguthaben, dann das persistente Sonderguthaben, zuletzt der (teure) Overuse. Reicht die
Summe nicht, greift die Overdraw-Policy.

### Rollover (bei jedem Zugriff)

Ein gemeinsamer `load_current(tenant, code)` liegt vor *jedem* Pfad (`consume`, `check`, `GET`).
Sieht er `periodYearMonth != aktueller Monat`, schließt er den Vormonat: schreibt `limit-history`
(idempotent), lässt monthly/overuse verfallen (Ledger-`reset`), füllt aus dem aktuellen
`Tenant.limits`-Snapshot neu, `customBalance` bleibt. Kosten: **ein Extra-Write je Limit je
Monat**, vom ersten Zugriff getragen. Für lückenlose History bei nie abgefragten Limits gibt es
zusätzlich `POST /tenants/{id}/limits/{code}/rollover` bzw. einen Sweep, den ein
Reporting-Service/Cron zum Monatswechsel anstößt.

### Overdraw-Policy

`check` (mutationsfrei) ist das Vorab-Gate, `consume` bucht post-hoc die *tatsächliche* Nutzung.
Reicht bei `consume` die Summe nicht, wird auf 0 gebucht und der Rest als `overdrawn` im Ledger
vermerkt (der Call ist bereits passiert — Buchhaltung bleibt ehrlich). Hartes 429 ist als Modus
für Prepaid-Gating vorgesehen, Default ist book-to-zero.

### Gauge

Nur `set`: `gaugeValue`/`gaugeMonth` auf aktuellen Monat setzen, Watermark-Status
(`value/max` gegen low/high %) zurückgeben. Kein Buchen, keine Kaskade.

### Fail-closed

`check`/`consume` verweigern bei Store-Fehler (deny) — Kostenschutz vor Verfügbarkeit, wie pip.

## Backend-Schnitt: zentrale Logik, dünnes Repo

Die Buchungslogik ist **backend-agnostisch und pur**; das Repository-Trait ist bewusst dünn, damit
ein neues DB-Backend die schwere Logik nicht nachprogrammiert.

**Pures `accounting`-Modul** (kein I/O, voll unit-testbar):

```rust
fn apply_consume(state, settings, amount, now, actor) -> Outcome
fn apply_topup(state, amount, now, actor) -> Outcome
fn apply_settings_change(state, old, new, now) -> (Outcome, Vec<Warning>)
fn set_gauge(state, value, now) -> Outcome
// Outcome { new_state, ledger: LedgerEntry, history: Option<HistoryRow> }
```

**Dünnes Repo-Trait** — nur mechanische Primitive:

```rust
async fn load_state(tenant, code) -> Option<(LimitState, Version)>;
async fn compare_and_swap(tenant, code, expected: Option<Version>, outcome: Outcome)
    -> Result<Committed, Conflict>;   // atomar: State (Version-Cond) + Ledger + History?
async fn read_ledger(tenant, code, cursor) -> LedgerPage;
async fn read_history(tenant, code) -> Vec<HistoryRow>;
async fn set_gauge_value(tenant, code, value, month) -> LimitState;  // eigenes SET
```

**Die OCC-Retry-Schleife lebt genau einmal** im Service — **bounded**, mit jittered Backoff, und
begeht nach `LIMIT_CAS_MAX_ATTEMPTS` kontrolliert Selbstmord (Fehler statt Endlosschleife):

```rust
for attempt in 0..LIMIT_CAS_MAX_ATTEMPTS {
    let (state, ver) = repo.load_state(tenant, code).await?;
    let outcome = accounting::apply_consume(state, settings, amount, now, actor); // pure
    match repo.compare_and_swap(tenant, code, ver, outcome).await? {
        Committed(r) => return Ok(r),
        Conflict => {
            backoff_jitter(attempt).await;  // randomisierter, leicht wachsender yield/sleep
            continue;
        }
    }
}
status_bail!(StatusCode::SERVICE_UNAVAILABLE,
    "limit '{code}' contended, aborting after {LIMIT_CAS_MAX_ATTEMPTS} attempts");
```

`backoff_jitter` ist ein kleiner randomisierter Sleep (Vollzitter, mit `attempt` leicht wachsend),
damit konkurrierende Bucher nicht im Gleichtakt kollidieren. Der Abbruch ist fail-closed (deny),
konsistent mit der Store-Fehler-Politik. Konstanten in `src/constants.rs`
(`LIMIT_CAS_MAX_ATTEMPTS`, Backoff-Ober-/Untergrenze).

Dynamo committet `compare_and_swap` als ein `TransactWriteItems` (State-Put mit
`#version = :expected`, Ledger-Put, History-Put-if-not-exists) → State und Ledger driften nie
auseinander. Ein Postgres-Backend implementiert dieselben zwei Methoden mit `UPDATE … WHERE
version = $n` in einer Transaktion. Kaskade, Rollover, Reconciliation stehen nur im `accounting`.

## Testing

Der Schnitt existiert genau, um Vollgas beim Testen zu erlauben — der schwere Teil ist pur.

- **`accounting` (pur, kein I/O)** — der Löwenanteil. Tabellen-getriebene Unit-Tests, keine DB:
  - Kaskade `monthly → custom → overuse` inkl. exakter Bucket-Aufschlüsselung im `Outcome`.
  - Rollover-Grenzen: Monatswechsel füllt neu, `customBalance` bleibt, `reset`-/History-Werte
    stimmen; kein Rollover innerhalb des Monats.
  - Overdraw: book-to-zero + `overdrawn`-Betrag; Prepaid-Hard-Reject-Modus.
  - Reconciliation: die drei `apply_settings_change`-Fälle (vergrößern / verkleinern / auf Usage
    gedeckelt + Warnung), analog `overuse`; `customBalance` unberührt.
  - Gauge: `set` + Watermark-Schwellen (unter low / zwischen / über high / über 100 %).
  - Topup: `customBalance` wächst, Ledger-`topup`.
- **Service / OCC-Schleife** — `mockall`-`LimitRepository`:
  - Repo liefert k-mal `Conflict`, dann `Committed` → Schleife retryt und committet (Assert: k+1
    `load_state`/`compare_and_swap`-Aufrufe).
  - Repo liefert immer `Conflict` → Abbruch nach `LIMIT_CAS_MAX_ATTEMPTS` mit
    `503`-Fehler (kein Endlosloop).
  - Store-Fehler in `load_state`/`compare_and_swap` → fail-closed (deny).
  - Route-Guards: `book:limits` / `manage:limits` via `warp::test::request()`.
- **Repository (Dynamo)** — Integrationstest (gegen AWS, wie die übrigen Repo-Tests): `TransactWriteItems`
  hält die Version-Condition (paralleler Schreiber verliert), History-Put ist idempotent.

## API-Fläche

Alles unter `/tenants/{id}/limits/...` (`tenantId` im Pfad — opake ID, kein PII in Query).

**Maschine (Produktdienste), `book:limits`:**

- `POST /tenants/{id}/limits/{code}/check` `{amount}` → `{allowed, remaining:{monthly,custom,overuse,total}}`; Gauge: `{value,max,watermark}`. Mutationsfrei.
- `POST /tenants/{id}/limits/{code}/consume` `{amount, actorUserId?, actorUserName?, txnName?, txnId?, reference?}` → bucht, liefert Bucket-Breakdown + neue Stände (429 je Policy).
- `POST /tenants/{id}/limits/{code}/report` `{value}` (Gauge) → setzt Wert, liefert Watermark-Status.

**Admin/UI, `manage:limits`:**

- `GET /tenants/{id}/limits` → alle Limits: Def + Settings + aktueller State.
- `PUT /tenants/{id}/limits/{code}/settings` `{monthly,overuse,daily,max}` → schreibt `Tenant.limits`, reconciled State, liefert Warnungen.
- `POST /tenants/{id}/limits/{code}/topup` `{amount}` → Sonderguthaben zubuchen.
- `GET /tenants/{id}/limits/{code}/transactions` → Ledger, paginiert (Cursor wie Audit-Log).
- `GET /tenants/{id}/limits/{code}/history` → Monatsreihe fürs Billing.
- `POST /tenants/{id}/limits/{code}/rollover` (+ Sweep) → Reporting/Cron erzwingt Monatsabschluss.

Route-Builder als `pub fn x_route(deps) -> BoxedFilter`, dünne `into_response`-Handler über pure
`anyhow::Result`-Business-Fns, `enforce_user_with_any_permission`,
`#[tracing::instrument(name = "POST /tenants/{id}/limits/{code}/consume", skip_all)]`.

## Permissions

`src/constants.rs`:

- `MANAGE_LIMITS_PERMISSION = "manage:limits"` — Admin: Settings, Topup, Ledger/History, Rollover.
- `BOOK_LIMITS_PERMISSION = "book:limits"` — Maschine: check, consume, report.

`book:limits` wird Produktdienst-Keys über eine Scope→Permission-Regel (`ApiDef`) zugeteilt. Da
das Backend für beliebige Mandanten bucht, steht die `tenantId` im Pfad; der JWT identifiziert
den *Dienst*.

## Verdrahtung

`Repositories` ist ein Bündel — ein vergessener Draht ist ein Compile-Fehler.

- `src/main.rs`: `mod limits;`
- `src/limits/`: `mod.rs` (Entities, `LimitKind`), `accounting.rs` (pur), `repository.rs`
  (Trait + `DynamoLimitRepository` + `with_client`), `service.rs` (Routes + Handler + Business).
- `src/storage/mod.rs`: Feld `limits: Arc<dyn LimitRepository>` im `Repositories`-Bündel.
- `src/storage/dynamodb.rs`: `DynamoLimitRepository::with_client(client)` in `repositories()`.
- `src/api/limits.rs`: `pub fn routes(&Platform) -> BoxedFilter<(impl Reply + use<>,)>`.
- `src/api/mod.rs`: `pub mod limits;` + `limits::routes(platform)` in `serve`.

## Client & UI

- `clients/typescript`: Typen (`LimitDef`, `LimitSettings`, `LimitState`, `LimitTransaction`, `LimitHistory`) + Methoden.
- `clients/ui`: Definitionen über `ConfigPage` (Roh-JSON, 0 Aufwand); pro Mandant eine „Limits"-Card in `EditTenantPage.tsx` (gespiegelt von `FeaturesCard`): Settings-Inputs, State-Anzeige mit Watermark-Highlighting, „Sonderguthaben zubuchen", Transaktions-/History-Ansicht.

## Implementierungsstand

**Gebaut** (Durchstich, `src/limits/` + `src/config/` + `src/tenants/`):

- L1 Katalog: `LimitKind`, `LimitDef` (mit `relevantIf`), `Config.limits`, `validate_limits`,
  `validate_limit_settings`, Katalog-Endpoint (`GET /config/catalogue` mit `limits`).
- L2 Werte: `Tenant.limits`, `PUT /tenants/{id}/limits/{code}/settings`, `GET /tenants/{id}/limits`
  (dual: `manage:limits` cross-tenant, `view:limits` eigener Mandant).
- L3 State + Buchung: `limit-state`-Tabelle, `accounting` (pur, Kaskade monthly→custom→overuse,
  Rollover in-memory, Overdraw book-to-zero, Topup, Gauge-`set`), dünnes CAS-Repo, bounded
  OCC-Schleife, `check`/`consume`/`report`/`topup`. Permissions `book:limits`/`manage:limits`.
- L3 Ledger + History: `limit-ledger` (append-only, Bucket-Breakdown + optionale Actor-Felder
  `actorUserId`/`actorUserName`/`txnName`/`txnId`/`reference` aus dem Request), `limit-history`
  (Monatsabschluss am Rollover, idempotent). `compare_and_swap` committet State + Ledger + History
  als **ein `TransactWriteItems`** (Version-Guard + History-if-not-exists) — kein Drift. Reads:
  `GET .../ledger`, `GET .../history` (self-service `view:limits` / cross-tenant `manage:limits`).

- L3 Daily-Throttle: Tages-Counter (`dailyRemaining`/`dailyDate`) im State, Reset bei Tageswechsel
  aus dem `daily`-Setting, unabhängiges Gate in `check` (zusätzlich zu den Buckets), Dekrement um
  die tatsächlich gebuchte Menge in `consume` (Floor 0). `daily` erscheint in `remaining`, sobald
  der Throttle aktiv ist.

- L3 Reconciliation: `PUT .../settings` gleicht die Live-Zähler an die neuen Werte an
  (`apply_settings_change`, pur): monthly/overuse **grow/shrink/cap** über `used = snapshot −
  remaining`, `customBalance` unberührt, Gauge-Wert bleibt (Warnung wenn > neues max),
  `settings`-Ledger-Eintrag. Warnungen (auf Usage gedeckelt) kommen in der Response. Zweistufig
  (L2-Write, dann L3-CAS), idempotent.

- L3 Ledger-Paginierung: `GET .../ledger?cursor=&limit=` liefert eine Seite (newest-first) plus
  `nextCursor` (opak, base64url über den letzten `ledgerSk`), via `Limit` + `ExclusiveStartKey` —
  nie den ganzen Ledger. Default 50, Cap 100.
- Live-State in der Liste: `GET /tenants/{id}/limits` → `{ code, settings, state? }` je Limit
  (projizierter aktueller Stand, kein Write, ohne `book:limits`) — die Read-Basis der UI.
- TS-Client (`clients/typescript`): Typen + Methoden (`getTenantLimits`, `setTenantLimitSettings`,
  `topupLimit`, `getLimitLedger`, `getLimitHistory`, `checkLimit`, `consumeLimit`, `reportGauge`),
  Katalog um `limits` erweitert.
- UI (`clients/ui`): `LimitsCard` in `EditTenantPage.tsx` (gespiegelt von `FeaturesCard`) — je Limit
  Settings-Inputs (facetten-abhängig), Live-State, Gauge-Watermark-Highlight, Top-up, aufklappbare
  History + paginierter Ledger; i18n en/de.

**Bewusst weggelassen**:

- **Rollover-Sweep** für inaktive Mandanten — die History entsteht lazy beim ersten Zugriff im
  neuen Monat; ein Mandant ohne jeden Zugriff hat nichts zu verbuchen, ein leerer Monatsrecord wäre
  nutzlos. Lücken sind akzeptiert.
- **`persistActorName`-Deploy-Schalter** — eine strenge Umgebung schickt den Namen einfach nicht
  (oder TTL't/schwärzt den Ledger); ein zentraler Schalter lohnt erst, wenn er wirklich gebraucht
  wird.

## Phasen

Jede Phase `cargo fmt` + `clippy -D warnings` + `test` clean.

1. **Katalog & Settings** — `LimitDef`/`LimitKind` + Validierung + Katalog-Endpoint; `Tenant.limits` + `PUT settings` (mit Reconciliation-Gerüst) + Tenant-UI-Card. Noch keine Buchung.
2. **Consumable-Kern** — `accounting` (pur) + dünnes Repo (`load_state`/`compare_and_swap`), monthly-Buchung, Rollover schreibt `limit-history`, Ledger mit Actor-Feldern, `check`/`consume`.
3. **Sonderguthaben** — `topup` + Kaskade `monthly → custom → overuse` + UI.
4. **Gauge + Watermarks** — `report`/Query (nur `set`) + UI-Highlighting.
5. **Daily-Throttle** — Daily-Bucket, in `check` integriert.
6. **Abschluss** — Ledger-/History-/Transaktions-UI, Rollover-Sweep/Cron, Feinschliff.

## Spätere Optionen (nicht v1)

- **`actAsUserId`-Claim** im `api-token → JWT`-Exchange: heute ist `sub` fix ans Key-Prinzipal
  gebunden, das Claim-Mapping geschlossen (`CLAIM_REFERENCES` eingefroren). Das `locale`-Feld im
  `ExchangeRequest` ist der Präzedenzfall für einen caller-gelieferten, im Namen des End-Users
  gesetzten Wert. Ein optionaler, advisory `act`-Claim (gated durch `scope:act-as`,
  tenant-contained, audited, ohne `sub`/Permissions/Audience zu berühren) würde die Ledger-Actor-
  Identität *vertrauenswürdig* machen — dann bevorzugt `consume` den Claim vor dem Body.
- **`limits.persistActorName`**-Schalter, falls eine Umgebung das zentral erzwingen will.
- **Cron-Backfill** für lückenlose History über völlig inaktive Mandanten.
