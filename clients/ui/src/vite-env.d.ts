/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the umami API (empty = same origin). */
  readonly VITE_UMAMI_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
