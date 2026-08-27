import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import de from "./de.json";
import en from "./en.json";

// The browser is only the opening guess — before anyone signs in there is no preference to
// honour. Once the profile is loaded, `UmamiProvider` switches to the user's own `locale`, which
// is the same source the server mints into the token. Two catalogues, one decision.
const lng = (navigator.language || "en").slice(0, 2) === "de" ? "de" : "en";

void i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, de: { translation: de } },
  lng,
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});

export default i18n;
