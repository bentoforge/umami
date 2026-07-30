//! Authentication: token issuance (JWKS), sessions, password + MFA, and the login/refresh flows.
//!
//! This module is built up across phases. Phase 1 provides the public JWKS endpoint stub so
//! product services can already discover it; later phases add password login, session rotation,
//! `/auth/me`, tenant switching and MFA.

pub mod tokens;
