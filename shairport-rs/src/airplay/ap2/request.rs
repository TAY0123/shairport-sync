//! Lightweight request view for AP2 contract classification.
//!
//! [`Ap2RequestView`] borrows the method, URI, optional content-type, and an
//! optional parsed binary-plist [`plist::Dictionary`].  It is intentionally
//! **zero-copy** — no owned fields — so it can be constructed cheaply from an
//! incoming RTSP request without cloning the body.
//!
//! The caller is responsible for parsing the binary plist and supplying the
//! dictionary reference.  If the body is not valid binary plist the caller
//! should pass `plist_dict: None`.

/// A borrowed, lightweight view of an incoming AirPlay 2 request.
///
/// All fields are borrowed references.  The `plist_dict` is `None` when the
/// body is empty or could not be parsed as an Apple binary plist dictionary.
#[derive(Clone, Debug)]
pub struct Ap2RequestView<'a> {
    /// RTSP method, e.g. `"SETUP"`, `"POST"`, `"TEARDOWN"`.
    pub method: &'a str,
    /// Request URI path, e.g. `"/info"`, `"/pair-verify"`, or `"*"` for
    /// methods where the URI is free-form.
    pub uri: &'a str,
    /// Value of the `Content-Type` header, if present.
    pub content_type: Option<&'a str>,
    /// Parsed binary-plist dictionary, if the body was valid.
    pub plist_dict: Option<&'a plist::Dictionary>,
}

impl<'a> Ap2RequestView<'a> {
    /// Try to classify this request against the static [`super::contract::AP2_CONTRACTS`].
    pub fn classify(&self) -> Option<&'static super::contract::Ap2Contract> {
        super::contract::classify(self)
    }

    /// Classify and then validate against the matched contract.
    ///
    /// Returns a list of errors, or an empty list if the request matches
    /// the contract for all statically-checkable fields.
    pub fn classify_and_validate(&self) -> Vec<super::contract::ContractError> {
        match self.classify() {
            Some(c) => super::contract::validate_request(c, self),
            None => {
                let method = Ap2Method::from_str(self.method);
                if method.is_none() {
                    vec![super::contract::ContractError::UnknownMethod(
                        self.method.to_string(),
                    )]
                } else {
                    vec![super::contract::ContractError::UnsupportedOperation {
                        method: self.method.to_string(),
                        uri: self.uri.to_string(),
                        content_type: self.content_type.map(|s| s.to_string()),
                    }]
                }
            }
        }
    }
}

use super::contract::Ap2Method;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_classify_valid() {
        let v = Ap2RequestView {
            method: "GET",
            uri: "/info",
            content_type: None,
            plist_dict: None,
        };
        let c = v.classify().expect("should classify");
        assert_eq!(c.operation, "GET /info");
    }

    #[test]
    fn view_classify_and_validate_empty_errors_for_good_request() {
        let mut stream = plist::Dictionary::new();
        stream.insert("type".into(), plist::Value::Integer(103.into()));
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        dict.insert("timingProtocol".into(), plist::Value::String("PTP".into()));

        let v = Ap2RequestView {
            method: "SETUP",
            uri: "*",
            content_type: Some("application/x-apple-binary-plist"),
            plist_dict: Some(&dict),
        };
        let errs = v.classify_and_validate();
        assert!(errs.is_empty(), "expected no errors, got {errs:?}");
    }

    #[test]
    fn view_classify_and_validate_unknown_method() {
        let v = Ap2RequestView {
            method: "OPTIONS",
            uri: "*",
            content_type: None,
            plist_dict: None,
        };
        let errs = v.classify_and_validate();
        assert_eq!(errs.len(), 1);
        assert!(matches!(errs[0], ContractError::UnknownMethod(_)));
    }

    #[test]
    fn view_classify_and_validate_unsupported() {
        let v = Ap2RequestView {
            method: "POST",
            uri: "/no-such-path",
            content_type: None,
            plist_dict: None,
        };
        let errs = v.classify_and_validate();
        assert_eq!(errs.len(), 1);
        assert!(matches!(
            errs[0],
            ContractError::UnsupportedOperation { .. }
        ));
    }

    use super::super::contract::ContractError;
}
