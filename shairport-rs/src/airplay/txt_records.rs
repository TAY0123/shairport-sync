use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    airplay::{ap2::capability::Ap2CapabilityPolicy, crypto::accessory_public_key_for_device_id},
    config::Config,
};

const SRCVERS: &str = "366.0";
const OSVERS: &str = "15.0";
const FIRMWARE_VERSION: &str = "5.0-shairport-rs";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AirplayService {
    pub service_type: String,
    pub instance_name: String,
    pub port: u16,
    pub txt: Vec<String>,
}

/// Build the list of mDNS services to publish.
///
/// `ptp_running` should be `true` when the PTP service is confirmed to be
/// running. External nqptp is not considered available until its shared-
/// memory adapter is implemented. When AP2 is enabled but PTP is not running the `_airplay`
/// service is suppressed.
pub fn airplay_services(config: &Config, ptp_running: bool) -> Vec<AirplayService> {
    let policy = Ap2CapabilityPolicy::from_config(config, ptp_running);

    let airplay_port = config
        .airplay
        .bind
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(7000);

    let raop = AirplayService {
        service_type: "_raop._tcp.local.".to_string(),
        instance_name: format!(
            "{}@{}",
            config.airplay.device_id.replace(':', "").to_uppercase(),
            config.mdns.service_name
        ),
        port: airplay_port,
        txt: if policy.publish_airplay {
            raop_ap2_txt(config, &policy)
        } else {
            raop_ap1_txt(config)
        },
    };

    if policy.publish_airplay {
        let airplay = AirplayService {
            service_type: "_airplay._tcp.local.".to_string(),
            instance_name: config.mdns.service_name.clone(),
            port: airplay_port,
            txt: airplay_txt(config, &policy),
        };
        vec![raop, airplay]
    } else {
        vec![raop]
    }
}

pub fn raop_ap1_txt(config: &Config) -> Vec<String> {
    vec![
        "sf=0x4".to_string(),
        format!("fv={FIRMWARE_VERSION}"),
        "am=ShairportSync".to_string(),
        "vs=105.1".to_string(),
        "tp=TCP,UDP".to_string(),
        "vn=65537".to_string(),
        "md=0,1,2".to_string(),
        "ss=16".to_string(),
        "sr=44100".to_string(),
        "da=true".to_string(),
        "sv=false".to_string(),
        "et=0,1".to_string(),
        "ek=1".to_string(),
        "cn=0,1".to_string(),
        "ch=2".to_string(),
        "txtvers=1".to_string(),
        "pw=false".to_string(),
        format!("pk={}", public_key_hex(&config.airplay.device_id)),
    ]
}

pub fn raop_ap2_txt(config: &Config, policy: &Ap2CapabilityPolicy) -> Vec<String> {
    let (features_lo, features_hi) = policy.feature_words();
    vec![
        "cn=0,1".to_string(),
        "da=true".to_string(),
        "et=0,1".to_string(),
        format!("pw={}", config.airplay.password_required()),
        format!("ft=0x{features_lo:X},0x{features_hi:X}"),
        format!("fv={FIRMWARE_VERSION}"),
        format!("sf=0x{:X}", policy.status_flags),
        "md=0,1".to_string(),
        "am=ShairportSync".to_string(),
        format!("pk={}", public_key_hex(&config.airplay.device_id)),
        "tp=UDP".to_string(),
        "vn=65537".to_string(),
        format!("vs={SRCVERS}"),
        format!("ov={OSVERS}"),
    ]
}

pub fn airplay_txt(config: &Config, policy: &Ap2CapabilityPolicy) -> Vec<String> {
    let (features_lo, features_hi) = policy.feature_words();
    let pi = stable_uuid("pi", &config.airplay.device_id);
    let psi = stable_uuid("psi", &config.airplay.device_id);
    let fex = policy.features_ex();
    vec![
        "acl=0".to_string(),
        "btaddr=00:00:00:00:00:00".to_string(),
        format!("deviceid={}", config.airplay.device_id),
        format!("fex={fex}"),
        format!("features=0x{features_lo:X},0x{features_hi:X}"),
        format!("flags=0x{:X}", policy.status_flags),
        format!("gid={pi}"),
        "igl=0".to_string(),
        "gcgl=0".to_string(),
        "model=ShairportSync".to_string(),
        "protovers=1.1".to_string(),
        format!("pi={pi}"),
        format!("psi={psi}"),
        format!("pk={}", public_key_hex(&config.airplay.device_id)),
        format!("pw={}", config.airplay.password_required()),
        format!("srcvers={SRCVERS}"),
        format!("osvers={OSVERS}"),
        "vv=2".to_string(),
        format!("fv={FIRMWARE_VERSION}"),
    ]
}

pub(crate) fn stable_uuid(label: &str, device_id: &str) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        format!("shairport-rs:{label}:{device_id}").as_bytes(),
    )
}

fn public_key_hex(device_id: &str) -> String {
    accessory_public_key_for_device_id(device_id)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config_ap2() -> Config {
        let mut c = Config::default();
        c.airplay.airplay2_enabled = true;
        c.ptp.enabled = true;
        c.ptp.backend = crate::config::PtpBackendName::Embedded;
        c
    }

    #[test]
    fn ap1_mode_only_publishes_raop() {
        let config = Config::default();
        assert!(!config.airplay.airplay2_enabled);
        let services = airplay_services(&config, false);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service_type, "_raop._tcp.local.");
        assert!(services[0].txt.iter().any(|e| e.starts_with("sr=44100")));
        assert!(services[0].txt.iter().any(|e| e.starts_with("txtvers=1")));
    }

    #[test]
    fn default_ap2_discovery_does_not_advertise_user_password() {
        let config = base_config_ap2();
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        assert!(
            raop_ap2_txt(&config, &policy)
                .iter()
                .any(|entry| entry == "pw=false")
        );
        assert!(
            airplay_txt(&config, &policy)
                .iter()
                .any(|entry| entry == "pw=false")
        );
    }

    #[test]
    fn ap2_mode_publishes_both_services() {
        let config = base_config_ap2();
        let services = airplay_services(&config, true);
        assert_eq!(services.len(), 2);
        assert!(
            services
                .iter()
                .any(|s| s.service_type == "_raop._tcp.local.")
        );
        assert!(
            services
                .iter()
                .any(|s| s.service_type == "_airplay._tcp.local.")
        );
    }

    #[test]
    fn ap2_without_ptp_suppresses_airplay_service() {
        let mut config = base_config_ap2();
        config.ptp.backend = crate::config::PtpBackendName::Off;
        let services = airplay_services(&config, false);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service_type, "_raop._tcp.local.");
        assert!(
            !services
                .iter()
                .any(|s| s.service_type == "_airplay._tcp.local.")
        );
        // _raop must fall back to classic (AP1) TXT when PTP is not available.
        assert!(
            services[0].txt.iter().any(|e| e == "txtvers=1"),
            "classic RAOP TXT must have txtvers=1"
        );
        assert!(
            services[0].txt.iter().any(|e| e.starts_with("sr=44100")),
            "classic RAOP TXT must have sr field"
        );
        assert!(
            !services[0].txt.iter().any(|e| e.starts_with("ft=0x")),
            "classic RAOP TXT must NOT have AP2 ft field"
        );
        assert!(
            !services[0].txt.iter().any(|e| e.starts_with("fex=")),
            "classic RAOP TXT must NOT have AP2 fex field"
        );
    }

    #[test]
    fn ap2_ptp_configured_but_not_running_falls_back_to_classic_raop_txt() {
        // AP2 is enabled and PTP backend is configured (e.g. Embedded),
        // but the PTP daemon has not started yet.  The _airplay service is
        // suppressed and _raop must publish classic (AP1) TXT — not AP2
        // TXT with zeroed/unusable PTP features.
        let config = base_config_ap2();
        let services = airplay_services(&config, false);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service_type, "_raop._tcp.local.");
        assert!(
            !services
                .iter()
                .any(|s| s.service_type == "_airplay._tcp.local.")
        );
        // Classic TXT markers
        assert!(services[0].txt.iter().any(|e| e == "txtvers=1"));
        assert!(services[0].txt.iter().any(|e| e.starts_with("sr=44100")));
        assert!(services[0].txt.iter().any(|e| e.starts_with("ss=16")));
        assert!(services[0].txt.iter().any(|e| e.starts_with("ch=2")));
        assert!(services[0].txt.iter().any(|e| e.starts_with("tp=TCP,UDP")));
        // AP2 markers must be absent
        assert!(!services[0].txt.iter().any(|e| e.starts_with("ft=0x")));
        assert!(!services[0].txt.iter().any(|e| e.starts_with("fex=")));
    }

    #[test]
    fn airplay_txt_contains_required_discovery_fields() {
        let config = base_config_ap2();
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        let txt = airplay_txt(&config, &policy);
        assert!(txt.iter().any(|entry| entry.starts_with("deviceid=")));
        assert!(txt.iter().any(|entry| entry.starts_with("pk=")));
        assert!(txt.iter().any(|entry| entry == "vv=2"));
        assert!(txt.iter().any(|entry| entry.starts_with("fex=")));
        assert!(
            !txt.iter()
                .any(|entry| entry.contains("00000000-0000-0000-0000-000000000000"))
        );
    }

    #[test]
    fn raop_ap2_txt_has_ft_field() {
        let config = base_config_ap2();
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        let txt = raop_ap2_txt(&config, &policy);
        assert!(txt.iter().any(|e| e.starts_with("ft=0x")));
    }

    #[test]
    fn raop_ap2_txt_has_status_flags() {
        let config = base_config_ap2();
        let policy = Ap2CapabilityPolicy::from_config(&config, true);
        let txt = raop_ap2_txt(&config, &policy);
        assert!(txt.iter().any(|e| e.starts_with("sf=0x")));
        // status flags should include audio cable attached (bit 2)
        let sf_entry = txt.iter().find(|e| e.starts_with("sf=0x")).unwrap();
        let sf_val = u32::from_str_radix(sf_entry.strip_prefix("sf=0x").unwrap(), 16).unwrap();
        assert!(
            sf_val & (1 << 2) != 0,
            "audio cable attached flag must be set"
        );
    }

    #[test]
    fn raop_ap1_txt_has_classic_fields() {
        let config = Config::default();
        let txt = raop_ap1_txt(&config);
        assert!(txt.iter().any(|e| e == "txtvers=1"));
        assert!(txt.iter().any(|e| e.starts_with("sr=44100")));
        assert!(txt.iter().any(|e| e.starts_with("ss=16")));
        assert!(txt.iter().any(|e| e.starts_with("ch=2")));
        assert!(txt.iter().any(|e| e.starts_with("tp=TCP,UDP")));
        assert!(txt.iter().any(|e| e.starts_with("pk=")));
        assert!(!txt.iter().any(|e| e.starts_with("ft=0x")));
    }

    #[test]
    fn mdns_txt_matches_info_fields_via_policy() {
        // The same policy feeds both mDNS TXT and /info plist.
        let config = base_config_ap2();
        let policy = Ap2CapabilityPolicy::from_config(&config, true);

        // From mDNS
        let raop_txt = raop_ap2_txt(&config, &policy);
        let airplay_txt = airplay_txt(&config, &policy);

        // Extract features from mDNS TXT
        let ft_entry = raop_txt.iter().find(|e| e.starts_with("ft=0x")).unwrap();
        let features_entry = airplay_txt
            .iter()
            .find(|e| e.starts_with("features=0x"))
            .unwrap();

        // Both should encode the same features
        let ft_clean = ft_entry.strip_prefix("ft=0x").unwrap();
        let features_clean = features_entry.strip_prefix("features=0x").unwrap();

        // ft is lo,hi for _raop; features is lo,hi for _airplay
        // They should match the policy
        let (policy_lo, policy_hi) = policy.feature_words();
        assert!(ft_clean.starts_with(&format!("{policy_lo:X}")));
        assert!(features_clean.starts_with(&format!("{policy_lo:X}")));
        // Both TXT records should encode the same upper word
        assert!(ft_clean.contains(&format!("{policy_hi:X}")));
    }
}
