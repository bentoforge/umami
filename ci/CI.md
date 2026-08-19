# Corporate Identity

The brand assets in this folder are the built-in defaults umami serves for the management UI when
the config `branding` block leaves a field empty (see `src/web_ui.rs`, embedded via `include_str!`).

## Accent color

**`#AD1E6B`** — `rgb(173, 30, 107)` (a deep magenta/rose).

| Use | Value |
|-----|-------|
| Accent (`--brand`) | `173 30 107` (space-separated RGB channels, for `rgb(var(--brand) / <alpha>)`) |
| Accent, darker (`--brand-dark`, hover/active) | `138 24 86` (`#8A1856`) |

The brand color is the **identity accent**, used sparingly (nav highlights, small badges). It is
kept separate from the UI's **primary** action color:

| Token | Role | Default |
|-------|------|---------|
| `--primary` / `--primary-dark` | Functional actions — buttons, focus rings, selection | `37 99 235` / `29 78 216` (a serious blue, `#2563EB`) |
| `--brand` / `--brand-dark` | Identity accent, used sparingly | `173 30 107` / `138 24 86` (`#AD1E6B`) |

Both are defaulted in `clients/ui/index.html` and overridable per deployment via config
`branding.customCss` (`:root{ --primary: <r> <g> <b>; --brand: <r> <g> <b>; … }`).

## Typography

**Wordmark font: [Aclonica](https://fonts.google.com/specimen/Aclonica)** — a Google Font (single
weight, 400). The wordmark SVGs ship as outlined vector paths, so the font is baked into the shapes;
no font file is needed to render the logo.

Google Fonts import (if the running app should reuse Aclonica for headings, etc.):

```
https://fonts.googleapis.com/css2?family=Aclonica&display=swap
```

The app UI otherwise renders in the system UI stack (`system-ui, sans-serif`, via Tailwind's
defaults).

## Assets

| File | Purpose | Notes |
|------|---------|-------|
| `logo_light.svg` | Wordmark for **light** backgrounds | wordmark in `rgb(90, 90, 90)`, symbol `#000000`, accent `#AD1E6B` |
| `logo_dark.svg`  | Wordmark for **dark** backgrounds  | wordmark in `rgb(240, 240, 240)`, symbol `#000000`, accent `#AD1E6B` |
| `favicon.svg`    | Browser tab / favicon              | symbol `#000000` + accent `#AD1E6B` |

> Note: the symbol in both logo variants is `#000000`, so on a dark background the symbol part of
> `logo_dark.svg` will be near-invisible. Recolor the symbol (e.g. to white or the accent) if it
> should read on dark. The wordmark text already switches (dark-gray ↔ light-gray).

Served by umami at `/app/logo/light`, `/app/logo/dark`, `/app/favicon`.
