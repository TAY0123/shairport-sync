//! Normalised response validation helpers.
//!
//! [`Ap2ResponseView`] mirrors [`super::request::Ap2RequestView`] for the
//! response side: a borrowed status code, optional `Content-Type`, and an
//! optional parsed binary-plist dictionary.
//!
//! The caller constructs one from the real RTSP response fields and passes it
//! to [`super::contract::validate_response`].

/// A borrowed, lightweight view of an AirPlay 2 response.
#[derive(Clone, Debug)]
pub struct Ap2ResponseView<'a> {
    /// RTSP / HTTP status code, e.g. 200, 400, 503.
    pub status: u16,
    /// Value of the `Content-Type` header, if present.
    pub content_type: Option<&'a str>,
    /// Parsed binary-plist dictionary, if the body was valid.
    pub plist_dict: Option<&'a plist::Dictionary>,
}

impl<'a> Ap2ResponseView<'a> {
    /// Validate against the given contract entry.
    pub fn validate(
        &self,
        contract: &super::contract::Ap2Contract,
    ) -> Vec<super::contract::ContractError> {
        super::contract::validate_response(contract, self)
    }

    /// Classify and validate using a request-view and the contract
    /// registry.  This is a convenience for end-to-end test helpers:
    /// classify the request to find the contract, then validate the
    /// response against it.
    pub fn classify_and_validate(
        &self,
        request: &super::request::Ap2RequestView<'_>,
    ) -> Vec<super::contract::ContractError> {
        match super::contract::classify(request) {
            Some(c) => super::contract::validate_response(c, self),
            None => vec![super::contract::ContractError::UnsupportedOperation {
                method: request.method.to_string(),
                uri: request.uri.to_string(),
                content_type: request.content_type.map(|s| s.to_string()),
            }],
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airplay::ap2::contract::AP2_CONTRACTS;
    use crate::airplay::ap2::contract::ContractError;

    #[test]
    fn response_view_validates_200() {
        let rv = Ap2ResponseView {
            status: 200,
            content_type: None,
            plist_dict: None,
        };
        let c = AP2_CONTRACTS
            .iter()
            .find(|c| c.operation == "PAUSE")
            .unwrap();
        let errs = rv.validate(c);
        assert!(errs.is_empty());
    }

    #[test]
    fn response_view_detects_wrong_status() {
        let rv = Ap2ResponseView {
            status: 500,
            content_type: None,
            plist_dict: None,
        };
        let c = AP2_CONTRACTS
            .iter()
            .find(|c| c.operation == "PAUSE")
            .unwrap();
        let errs = rv.validate(c);
        assert!(!errs.is_empty());
        assert!(matches!(
            errs[0],
            ContractError::WrongResponseStatus {
                expected: 200,
                actual: 500
            }
        ));
    }

    #[test]
    fn classify_and_validate_integration() {
        let req = crate::airplay::ap2::request::Ap2RequestView {
            method: "GET",
            uri: "/info",
            content_type: None,
            plist_dict: None,
        };

        let mut dict = plist::Dictionary::new();
        dict.insert("vv".into(), plist::Value::Integer(2.into()));
        dict.insert("deviceID".into(), plist::Value::String("id".into()));
        dict.insert("features".into(), plist::Value::Integer(0.into()));
        dict.insert("statusFlags".into(), plist::Value::Integer(0.into()));
        dict.insert("name".into(), plist::Value::String("n".into()));
        dict.insert("model".into(), plist::Value::String("m".into()));
        dict.insert("pi".into(), plist::Value::String("p".into()));
        dict.insert("pk".into(), plist::Value::Data(vec![]));
        dict.insert("srcvers".into(), plist::Value::String("1".into()));
        let mut fmt = plist::Dictionary::new();
        fmt.insert("audioStream".into(), plist::Value::Integer(0.into()));
        fmt.insert("bufferStream".into(), plist::Value::Integer(0.into()));
        dict.insert("supportedFormats".into(), plist::Value::Dictionary(fmt));

        let resp = Ap2ResponseView {
            status: 200,
            content_type: Some("application/x-apple-binary-plist"),
            plist_dict: Some(&dict),
        };
        let errs = resp.classify_and_validate(&req);
        assert!(errs.is_empty(), "unexpected errors: {errs:?}");
    }

    #[test]
    fn classify_and_validate_unsupported_request() {
        let req = crate::airplay::ap2::request::Ap2RequestView {
            method: "OPTIONS",
            uri: "*",
            content_type: None,
            plist_dict: None,
        };
        let resp = Ap2ResponseView {
            status: 200,
            content_type: None,
            plist_dict: None,
        };
        let errs = resp.classify_and_validate(&req);
        assert_eq!(errs.len(), 1);
        assert!(matches!(
            errs[0],
            ContractError::UnsupportedOperation { .. }
        ));
    }
}
