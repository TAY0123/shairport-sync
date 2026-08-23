//! Privacy-safe AirPlay 2 interoperability transcript recording.
//!
//! The schema is intentionally closed: it records protocol shape and a small
//! allow-list of non-secret stream parameters, never arbitrary headers or
//! plist values.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::rtsp::{RtspRequest, RtspResponse};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TranscriptRecord {
    Exchange {
        sequence: u64,
        connection: u64,
        method: String,
        path: String,
        content_type: Option<String>,
        request_plist: BTreeMap<String, String>,
        streams: Vec<StreamSummary>,
        response_status: u16,
        response_content_type: Option<String>,
        response_plist: BTreeMap<String, String>,
    },
    EventChannelConnected {
        sequence: u64,
        connection: u64,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_type: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_format: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_size: Option<u64>,
}

#[derive(Debug)]
pub struct TranscriptRecorder {
    writer: Mutex<BufWriter<File>>,
    next_sequence: AtomicU64,
    next_connection: AtomicU64,
}

impl TranscriptRecorder {
    /// Create a fresh JSONL transcript. Explicit configuration errors fail
    /// server startup rather than silently losing the interoperability trace.
    pub fn create(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
            next_sequence: AtomicU64::new(1),
            next_connection: AtomicU64::new(1),
        })
    }

    pub fn allocate_connection(&self) -> u64 {
        self.next_connection.fetch_add(1, Ordering::Relaxed)
    }

    pub fn record_exchange(
        &self,
        connection: u64,
        request: &RtspRequest,
        response: &RtspResponse,
    ) -> std::io::Result<()> {
        let request_dict = parse_plist_dictionary(&request.body);
        let response_dict = parse_plist_dictionary(&response.body);
        let record = TranscriptRecord::Exchange {
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
            connection,
            method: safe_token(&request.method),
            path: sanitize_path(&request.uri),
            content_type: request_header(request, "Content-Type").map(safe_content_type),
            request_plist: request_dict.as_ref().map(plist_shape).unwrap_or_default(),
            streams: request_dict
                .as_ref()
                .map(stream_summaries)
                .unwrap_or_default(),
            response_status: response.code,
            response_content_type: response_header(response, "Content-Type").map(safe_content_type),
            response_plist: response_dict.as_ref().map(plist_shape).unwrap_or_default(),
        };
        self.write_record(&record)
    }

    pub fn record_event_channel_connected(&self, connection: u64) -> std::io::Result<()> {
        self.write_record(&TranscriptRecord::EventChannelConnected {
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
            connection,
        })
    }

    fn write_record(&self, record: &TranscriptRecord) -> std::io::Result<()> {
        let mut writer = self.writer.lock();
        serde_json::to_writer(&mut *writer, record).map_err(std::io::Error::other)?;
        writer.write_all(b"\n")?;
        writer.flush()
    }
}

fn request_header<'a>(request: &'a RtspRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn response_header<'a>(response: &'a RtspResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn parse_plist_dictionary(body: &[u8]) -> Option<plist::Dictionary> {
    if body.is_empty() {
        return None;
    }
    plist::from_bytes(body).ok()
}

fn plist_shape(dict: &plist::Dictionary) -> BTreeMap<String, String> {
    let mut shape = BTreeMap::new();
    collect_dictionary_shape("", dict, &mut shape);
    shape
}

fn collect_dictionary_shape(
    prefix: &str,
    dict: &plist::Dictionary,
    shape: &mut BTreeMap<String, String>,
) {
    for (key, value) in dict {
        let safe_key = safe_plist_key(key);
        let path = if prefix.is_empty() {
            safe_key
        } else {
            format!("{prefix}.{safe_key}")
        };
        shape.insert(path.clone(), plist_type(value).to_string());
        match value {
            plist::Value::Dictionary(child) => collect_dictionary_shape(&path, child, shape),
            plist::Value::Array(values) => {
                for value in values {
                    let item_path = format!("{path}[]");
                    shape
                        .entry(item_path.clone())
                        .or_insert_with(|| plist_type(value).to_string());
                    if let plist::Value::Dictionary(child) = value {
                        collect_dictionary_shape(&item_path, child, shape);
                    }
                }
            }
            _ => {}
        }
    }
}

fn plist_type(value: &plist::Value) -> &'static str {
    match value {
        plist::Value::Array(_) => "array",
        plist::Value::Dictionary(_) => "dictionary",
        plist::Value::Boolean(_) => "boolean",
        plist::Value::Data(_) => "data",
        plist::Value::Date(_) => "date",
        plist::Value::Real(_) => "real",
        plist::Value::Integer(_) => "integer",
        plist::Value::String(_) => "string",
        plist::Value::Uid(_) => "uid",
        _ => "unknown",
    }
}

fn stream_summaries(dict: &plist::Dictionary) -> Vec<StreamSummary> {
    let Some(plist::Value::Array(streams)) = dict.get("streams") else {
        return Vec::new();
    };
    streams
        .iter()
        .filter_map(plist::Value::as_dictionary)
        .map(|stream| StreamSummary {
            stream_type: integer(stream.get("type")),
            audio_format: integer(stream.get("audioFormat")),
            sample_rate: integer(stream.get("sr")),
            packet_size: integer(stream.get("spf")).or_else(|| integer(stream.get("packetSize"))),
        })
        .collect()
}

fn integer(value: Option<&plist::Value>) -> Option<u64> {
    value.and_then(plist::Value::as_unsigned_integer)
}

fn safe_token(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '/'))
        .take(64)
        .collect()
}

fn safe_content_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .map(str::trim)
        .map(safe_token)
        .unwrap_or_default()
}

fn safe_plist_key(value: &str) -> String {
    if uuid::Uuid::parse_str(value).is_ok() {
        return "{uuid-key}".to_string();
    }
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        .take(80)
        .collect()
}

fn sanitize_path(uri: &str) -> String {
    let without_query = uri.split(['?', '#']).next().unwrap_or(uri);
    if without_query == "*" {
        return "*".to_string();
    }
    let path = if let Some(scheme) = without_query.find("://") {
        without_query[scheme + 3..]
            .find('/')
            .map(|slash| &without_query[scheme + 3 + slash..])
            .unwrap_or("/")
    } else {
        without_query
    };
    let mut out = String::new();
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            out.push('/');
        }
        if uuid::Uuid::parse_str(segment).is_ok() {
            out.push_str("{uuid}");
        } else {
            out.push_str(&safe_token(segment));
        }
    }
    if out.is_empty() { "/".to_string() } else { out }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_sender_post_pairing_prefix_fixture_preserves_observed_order_and_shape() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "fixtures/real_sender_post_pairing_prefix.json"
        ))
        .unwrap();
        assert_eq!(fixture["complete"], false);
        let exchanges = fixture["exchanges"].as_array().unwrap();
        let operations: Vec<String> = exchanges
            .iter()
            .map(|exchange| {
                exchange["method"]
                    .as_str()
                    .map(|method| format!("{method} {}", exchange["path"].as_str().unwrap_or("")))
                    .unwrap_or_else(|| exchange["kind"].as_str().unwrap().to_string())
            })
            .collect();
        assert_eq!(
            operations,
            [
                "POST /fp-setup",
                "POST /fp-setup",
                "SETUP /session",
                "event-channel-connected",
                "GET /info",
                "RECORD /session",
                "SETPEERS /session",
                "POST /command",
                "POST /command",
                "POST /command",
                "SET_PARAMETER /session",
                "POST /feedback",
                "SETUP /session",
            ]
        );

        let stream_setup = exchanges.last().unwrap();
        assert_eq!(stream_setup["stream"]["type"], 103);
        assert_eq!(stream_setup["stream"]["audioFormat"], 0x0080_0000u64);
        assert_eq!(stream_setup["stream"]["spf"], 1024);
        assert_eq!(stream_setup["stream"]["sr_present"], false);
        assert_eq!(stream_setup["captured_response_status"], 400);
        assert_eq!(stream_setup["required_response_status"], 200);

        let rendered = serde_json::to_string(&fixture).unwrap();
        for forbidden in [
            "signature",
            "public_key",
            "private_key",
            "payload_bytes",
            "uuid_value",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }
    use std::{collections::BTreeMap, fs};

    fn request(body: Vec<u8>) -> RtspRequest {
        RtspRequest {
            method: "SETUP".into(),
            uri: "rtsp://receiver/550e8400-e29b-41d4-a716-446655440000?token=secret".into(),
            version: "RTSP/1.0".into(),
            headers: BTreeMap::from([
                (
                    "Content-Type".into(),
                    "application/x-apple-binary-plist".into(),
                ),
                ("Authorization".into(), "secret-header".into()),
            ]),
            body,
        }
    }

    #[test]
    fn shape_and_stream_summary_contain_only_allowlisted_values() {
        let mut stream = plist::Dictionary::new();
        stream.insert("type".into(), plist::Value::Integer(103u64.into()));
        stream.insert(
            "audioFormat".into(),
            plist::Value::Integer(0x40000u64.into()),
        );
        stream.insert("sr".into(), plist::Value::Integer(44_100u64.into()));
        stream.insert("spf".into(), plist::Value::Integer(352u64.into()));
        stream.insert("shk".into(), plist::Value::Data(vec![0xAB; 32]));
        stream.insert(
            "streamConnectionID".into(),
            plist::Value::Integer(123_456u64.into()),
        );
        let mut root = plist::Dictionary::new();
        root.insert(
            "groupUUID".into(),
            plist::Value::String("550e8400-e29b-41d4-a716-446655440000".into()),
        );
        root.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let shape = plist_shape(&root);
        assert_eq!(shape.get("streams[].shk").map(String::as_str), Some("data"));
        assert_eq!(shape.get("groupUUID").map(String::as_str), Some("string"));
        let streams = stream_summaries(&root);
        assert_eq!(
            streams,
            vec![StreamSummary {
                stream_type: Some(103),
                audio_format: Some(0x40000),
                sample_rate: Some(44_100),
                packet_size: Some(352),
            }]
        );
        let json = serde_json::to_string(&(shape, streams)).unwrap();
        assert!(!json.contains("550e8400"));
        assert!(!json.contains("123456"));
        assert!(!json.contains("abab"));
    }

    #[test]
    fn recorder_redacts_paths_and_never_serializes_headers_or_values() {
        let dir =
            std::env::temp_dir().join(format!("shairport-transcript-{}", uuid::Uuid::new_v4()));
        let path = dir.join("capture.jsonl");
        let recorder = TranscriptRecorder::create(&path).unwrap();

        let mut dict = plist::Dictionary::new();
        dict.insert(
            "groupUUID".into(),
            plist::Value::String("550e8400-e29b-41d4-a716-446655440000".into()),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        let response = RtspResponse {
            code: 200,
            reason: "OK",
            headers: vec![(
                "Content-Type".into(),
                "application/x-apple-binary-plist".into(),
            )],
            body: Vec::new(),
        };
        recorder
            .record_exchange(1, &request(body), &response)
            .unwrap();
        recorder.record_event_channel_connected(1).unwrap();

        let output = fs::read_to_string(&path).unwrap();
        assert!(output.contains("\"path\":\"/{uuid}\""));
        assert!(output.contains("\"groupUUID\":\"string\""));
        for forbidden in [
            "550e8400",
            "token",
            "secret",
            "Authorization",
            "secret-header",
        ] {
            assert!(
                !output.contains(forbidden),
                "transcript leaked {forbidden}: {output}"
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
