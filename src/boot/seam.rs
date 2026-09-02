//! How umami picks the implementation behind a seam, and how it says so at boot.
//!
//! Four seams are configurable — storage, the config catalog, signing keys, outbound mail. Each
//! reads one variable, and all of them follow the same three rules. The rules live here because
//! four copies of them would drift, and an operator has to be able to reason about the next seam
//! from the one they already learned:
//!
//! - **Explicit wins, and is strict.** `UMAMI_CONFIG_STORE=s3` with no bucket configured fails the
//!   boot rather than falling back. Naming a backend states what the deployment needs; running on a
//!   different one anyway produces a service that looks healthy and loses every config edit on
//!   restart.
//! - **Unset means auto-detect.** What umami did before this existed, kept for local dev: probe
//!   what the environment offers, take it, say which one won.
//! - **An unknown value never falls back.** A typo fails the boot with the list of valid names.
//!   The alternative is a deployment quietly running on a backend nobody chose.
//!
//! Strictness is derived from *explicitness*, not from a separate "production mode" switch.
//! There is nothing to remember to turn on, and no way for a deployment to be strict about one
//! seam and lax about the next.

use std::env;

/// Why a provider ended up being the one in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The seam's variable named it.
    Explicit,
    /// Nothing was configured, and probing the environment found this one.
    Detected,
    /// Nothing was configured and there is nothing to probe — the only provider this build has.
    Default,
}

/// One resolved seam, for the boot report.
pub struct Selection {
    /// Human-readable seam name (`"config store"`).
    pub seam: &'static str,
    /// The variable that selects it (`"UMAMI_CONFIG_STORE"`).
    pub variable: &'static str,
    /// The provider in use (`"s3"`).
    pub provider: &'static str,
    /// How it was chosen.
    pub reason: Reason,
    /// What this choice costs, when it costs something. Short — the full explanation belongs in a
    /// `WARN` of its own, next to the code that knows the details.
    pub note: Option<String>,
}

impl Selection {
    /// The seam's variable named this provider.
    pub fn explicit(seam: &'static str, variable: &'static str, provider: &'static str) -> Self {
        Selection {
            seam,
            variable,
            provider,
            reason: Reason::Explicit,
            note: None,
        }
    }

    /// Nothing was configured; probing found this provider.
    pub fn detected(seam: &'static str, variable: &'static str, provider: &'static str) -> Self {
        Selection {
            seam,
            variable,
            provider,
            reason: Reason::Detected,
            note: None,
        }
    }

    /// Nothing was configured and this build has only one provider for the seam.
    pub fn default_for(seam: &'static str, variable: &'static str, provider: &'static str) -> Self {
        Selection {
            seam,
            variable,
            provider,
            reason: Reason::Default,
            note: None,
        }
    }

    /// Adds the one-line cost of this choice to the report.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// The provider a seam's variable asks for, trimmed and lowercased.
///
/// `None` means unset or empty, which is "auto-detect" — never "off". A seam that can be switched
/// off has a provider name for that (`none`), so turning it off is a decision in the environment
/// rather than the absence of one.
pub fn requested(variable: &str) -> Option<String> {
    env::var(variable).ok().as_deref().and_then(normalize)
}

/// Trims and lowercases a raw variable value; `None` when nothing is left.
fn normalize(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_lowercase())
}

/// The boot error for a provider name this build does not implement.
pub fn unknown_provider(variable: &str, value: &str, valid: &[&str]) -> anyhow::Error {
    anyhow::anyhow!(
        "{variable}='{value}' names a backend umami does not implement. Valid values: {}. Leave \
         {variable} unset to auto-detect.",
        valid.join(", ")
    )
}

/// Logs one block naming every seam, its provider, and why it won.
///
/// One block rather than a line per seam as it is resolved: what an operator needs to check after a
/// deployment is the whole set at once, and interleaved with table provisioning it is unreadable.
pub fn report(selections: &[Selection]) {
    tracing::info!("{}", report_lines(selections).join("\n"));
}

/// The report as lines. Split from the logging so the format is testable.
fn report_lines(selections: &[Selection]) -> Vec<String> {
    let mut lines = vec!["Resolved backends:".to_owned()];
    for selection in selections {
        let why = match selection.reason {
            Reason::Explicit => {
                format!("configured ({}={})", selection.variable, selection.provider)
            }
            Reason::Detected => format!("auto-detected ({} unset)", selection.variable),
            Reason::Default => format!("default ({} unset)", selection.variable),
        };
        lines.push(format!(
            "  {:<14} {:<9} — {why}",
            selection.seam, selection.provider
        ));
        if let Some(note) = &selection.note {
            lines.push(format!("  {:<14} ↳ {note}", ""));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `UMAMI_STORAGE=" DynamoDB "` has to mean the same as `dynamodb`; an operator should not lose
    /// an afternoon to a trailing space in a deployment manifest.
    #[test]
    fn provider_names_are_case_and_whitespace_insensitive() {
        assert_eq!(normalize(" DynamoDB "), Some("dynamodb".to_owned()));
        assert_eq!(normalize("S3"), Some("s3".to_owned()));
    }

    /// An empty value is indistinguishable from unset, and both mean auto-detect. A deployment that
    /// templates `UMAMI_MAIL_TRANSPORT=` from an unset variable must not fail the boot on a name
    /// that is the empty string.
    #[test]
    fn empty_is_the_same_as_unset() {
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("   "), None);
    }

    /// The error has to carry the valid names — the whole point of failing instead of falling
    /// back is that the operator can fix it from the message alone.
    #[test]
    fn unknown_provider_lists_what_is_valid() {
        let err = unknown_provider("UMAMI_CONFIG_STORE", "s4", &["s3", "memory"]).to_string();
        assert!(err.contains("UMAMI_CONFIG_STORE='s4'"), "{err}");
        assert!(err.contains("s3, memory"), "{err}");
    }

    #[test]
    fn the_report_names_the_provider_and_the_reason() {
        let lines = report_lines(&[
            Selection::explicit("storage", "UMAMI_STORAGE", "dynamodb"),
            Selection::detected("mail transport", "UMAMI_MAIL_TRANSPORT", "none")
                .with_note("outbound mail is disabled"),
        ]);

        assert_eq!(lines.len(), 4);
        assert!(lines[1].contains("storage"), "{:?}", lines[1]);
        assert!(
            lines[1].contains("configured (UMAMI_STORAGE=dynamodb)"),
            "{:?}",
            lines[1]
        );
        assert!(
            lines[2].contains("auto-detected (UMAMI_MAIL_TRANSPORT unset)"),
            "{:?}",
            lines[2]
        );
        assert!(
            lines[3].contains("outbound mail is disabled"),
            "{:?}",
            lines[3]
        );
    }
}
