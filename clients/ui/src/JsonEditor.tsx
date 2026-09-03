import { json, jsonParseLinter } from "@codemirror/lang-json";
import { linter, lintGutter } from "@codemirror/lint";
import { oneDark } from "@codemirror/theme-one-dark";
import CodeMirror from "@uiw/react-codemirror";
import { useEffect, useState } from "react";
import { resolvedDark, subscribeTheme } from "./theme";

// JSON grammar + a linter that turns a parse error into an inline marker at the offending offset,
// and a gutter to hang it in. Static: the set never changes, so it is built once rather than per
// render (a fresh array would make CodeMirror reconfigure the editor on every keystroke).
const EXTENSIONS = [json(), linter(jsonParseLinter()), lintGutter()];

/** A JSON source editor: syntax highlighting, line numbers, bracket matching and inline parse
 * errors, themed to follow the app's light/dark choice.
 *
 * Default-exported for `React.lazy`: CodeMirror is a heavy dependency, and this is the only screen
 * that needs it, so it rides in its own chunk fetched when the config editor opens. */
export default function JsonEditor({
  value,
  onChange,
  readOnly,
}: {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
}) {
  // The editor's own theme is an extension, not a CSS class, so it cannot ride Tailwind's `dark`
  // class — it has to be swapped in JS when the resolved theme changes (explicit switch or an OS
  // change while on "auto").
  const [dark, setDark] = useState(resolvedDark);
  useEffect(() => subscribeTheme(() => setDark(resolvedDark())), []);

  return (
    <CodeMirror
      value={value}
      onChange={onChange}
      extensions={EXTENSIONS}
      theme={dark ? oneDark : "light"}
      height="70vh"
      readOnly={readOnly}
      className="overflow-hidden rounded-lg border border-slate-300 text-sm focus-within:ring-2 focus-within:ring-primary dark:border-slate-600"
    />
  );
}
