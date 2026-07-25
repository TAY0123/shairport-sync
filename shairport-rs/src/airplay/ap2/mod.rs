//! AirPlay 2 API conformance contract module.
//!
//! This module provides:
//! - A static contract registry describing every AP2 endpoint.
//! - Lightweight request classification and validation.
//! - Response validation helpers.
//! - Session-phase transition validation.
//!
//! It is intentionally **free of side-effects** — no production behaviour is
//! changed by calling these functions.  The module only depends on `plist` and
//! the standard library so it cannot create circular dependencies with the
//! rest of the `airplay` crate.
//!
//! # Usage
//!
//! ```ignore
//! use shairport_rs::airplay::ap2::contract::{classify, AP2_CONTRACTS};
//! use shairport_rs::airplay::ap2::request::Ap2RequestView;
//!
//! let view = Ap2RequestView { method: "GET", uri: "/info", content_type: None, plist_dict: None };
//! let contract = classify(&view).unwrap();
//! assert_eq!(contract.operation, "GET /info");
//! ```

pub mod contract;
pub mod request;
pub mod response;
pub mod session;
