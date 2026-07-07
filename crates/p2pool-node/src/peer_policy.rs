use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicyConfig {
    pub max_envelopes_per_window: u32,
    pub max_read_requests_per_window: u32,
    pub rate_window_seconds: i64,
    pub max_invalid_envelopes: u32,
    pub ban_seconds: i64,
    pub max_peers_per_ip_group: usize,
}

impl Default for PeerPolicyConfig {
    fn default() -> Self {
        Self {
            max_envelopes_per_window: 120,
            max_read_requests_per_window: 600,
            rate_window_seconds: 60,
            max_invalid_envelopes: 10,
            ban_seconds: 3_600,
            max_peers_per_ip_group: 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub peer_id: String,
    pub ip_group: Option<String>,
    pub invalid_envelopes: u32,
    pub banned_until_unix: Option<i64>,
    rate_window_started_unix: i64,
    accepted_in_window: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRecord {
    pub ip: String,
    pub invalid_envelopes: u32,
    pub banned_until_unix: Option<i64>,
    rate_window_started_unix: i64,
    accepted_in_window: u32,
    read_window_started_unix: i64,
    read_requests_in_window: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerDecision {
    Allowed,
    RateLimited {
        retry_after_seconds: i64,
    },
    Banned {
        banned_until_unix: i64,
    },
    IpGroupFull {
        ip_group: String,
        max_peers_per_ip_group: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerPolicyError {
    #[error("invalid peer id")]
    InvalidPeerId,
    #[error("invalid policy config: {0}")]
    InvalidConfig(String),
}

#[derive(Debug, Clone)]
pub struct PeerPolicy {
    config: PeerPolicyConfig,
    peers: BTreeMap<String, PeerRecord>,
    ips: BTreeMap<String, IpRecord>,
    peers_by_ip_group: BTreeMap<String, BTreeSet<String>>,
}

impl PeerPolicy {
    pub fn new(config: PeerPolicyConfig) -> Result<Self, PeerPolicyError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            peers: BTreeMap::new(),
            ips: BTreeMap::new(),
            peers_by_ip_group: BTreeMap::new(),
        })
    }

    pub fn check_ip_envelope_allowed(
        &mut self,
        ip: IpAddr,
        now_unix: i64,
    ) -> Result<PeerDecision, PeerPolicyError> {
        let max_envelopes_per_ip_window = self.max_envelopes_per_ip_window();
        let rate_window_seconds = self.config.rate_window_seconds;
        let record = self.ip_record(ip, now_unix);

        if let Some(banned_until_unix) = record.banned_until_unix {
            if now_unix < banned_until_unix {
                return Ok(PeerDecision::Banned { banned_until_unix });
            }
            record.banned_until_unix = None;
            record.invalid_envelopes = 0;
        }

        if now_unix.saturating_sub(record.rate_window_started_unix) >= rate_window_seconds {
            record.rate_window_started_unix = now_unix;
            record.accepted_in_window = 0;
        }

        if record.accepted_in_window >= max_envelopes_per_ip_window {
            let retry_after_seconds = rate_window_seconds
                .saturating_sub(now_unix.saturating_sub(record.rate_window_started_unix))
                .max(1);
            return Ok(PeerDecision::RateLimited {
                retry_after_seconds,
            });
        }

        record.accepted_in_window += 1;
        Ok(PeerDecision::Allowed)
    }

    pub fn check_ip_read_request_allowed(
        &mut self,
        ip: IpAddr,
        now_unix: i64,
    ) -> Result<PeerDecision, PeerPolicyError> {
        let max_read_requests_per_window = self.config.max_read_requests_per_window;
        let rate_window_seconds = self.config.rate_window_seconds;
        let record = self.ip_record(ip, now_unix);

        if let Some(banned_until_unix) = record.banned_until_unix {
            if now_unix < banned_until_unix {
                return Ok(PeerDecision::Banned { banned_until_unix });
            }
            record.banned_until_unix = None;
            record.invalid_envelopes = 0;
        }

        if now_unix.saturating_sub(record.read_window_started_unix) >= rate_window_seconds {
            record.read_window_started_unix = now_unix;
            record.read_requests_in_window = 0;
        }

        if record.read_requests_in_window >= max_read_requests_per_window {
            let retry_after_seconds = rate_window_seconds
                .saturating_sub(now_unix.saturating_sub(record.read_window_started_unix))
                .max(1);
            return Ok(PeerDecision::RateLimited {
                retry_after_seconds,
            });
        }

        record.read_requests_in_window += 1;
        Ok(PeerDecision::Allowed)
    }

    pub fn check_ip_not_banned(
        &mut self,
        ip: IpAddr,
        now_unix: i64,
    ) -> Result<PeerDecision, PeerPolicyError> {
        let record = self.ip_record(ip, now_unix);
        if let Some(banned_until_unix) = record.banned_until_unix {
            if now_unix < banned_until_unix {
                return Ok(PeerDecision::Banned { banned_until_unix });
            }
            record.banned_until_unix = None;
            record.invalid_envelopes = 0;
        }
        Ok(PeerDecision::Allowed)
    }

    pub fn record_invalid_ip_envelope(
        &mut self,
        ip: IpAddr,
        now_unix: i64,
    ) -> Result<PeerDecision, PeerPolicyError> {
        let max_invalid_envelopes = self.config.max_invalid_envelopes;
        let ban_seconds = self.config.ban_seconds;
        let record = self.ip_record(ip, now_unix);
        record.invalid_envelopes = record.invalid_envelopes.saturating_add(1);
        if record.invalid_envelopes >= max_invalid_envelopes {
            let banned_until_unix = now_unix.saturating_add(ban_seconds);
            record.banned_until_unix = Some(banned_until_unix);
            return Ok(PeerDecision::Banned { banned_until_unix });
        }
        Ok(PeerDecision::Allowed)
    }

    pub fn record_valid_ip_envelope(&mut self, ip: IpAddr) -> Result<(), PeerPolicyError> {
        if let Some(record) = self.ips.get_mut(&ip_record_key(ip)) {
            record.invalid_envelopes = record.invalid_envelopes.saturating_sub(1);
        }
        Ok(())
    }

    pub fn admit_peer(
        &mut self,
        peer_id: &str,
        ip: Option<IpAddr>,
        now_unix: i64,
    ) -> Result<PeerDecision, PeerPolicyError> {
        validate_peer_id(peer_id)?;
        let peer_id = peer_id.to_ascii_lowercase();
        let ip_group = ip.map(ip_group_key);
        let previous_ip_group = self
            .peers
            .get(&peer_id)
            .and_then(|record| record.ip_group.clone());

        if let Some(group) = &ip_group {
            let existing = self.peers_by_ip_group.entry(group.clone()).or_default();
            if !existing.contains(&peer_id) && existing.len() >= self.config.max_peers_per_ip_group
            {
                return Ok(PeerDecision::IpGroupFull {
                    ip_group: group.clone(),
                    max_peers_per_ip_group: self.config.max_peers_per_ip_group,
                });
            }
        }

        if previous_ip_group != ip_group {
            if let Some(old_group) = previous_ip_group {
                let mut remove_group = false;
                if let Some(peers) = self.peers_by_ip_group.get_mut(&old_group) {
                    peers.remove(&peer_id);
                    remove_group = peers.is_empty();
                }
                if remove_group {
                    self.peers_by_ip_group.remove(&old_group);
                }
            }
        }

        if let Some(group) = &ip_group {
            self.peers_by_ip_group
                .entry(group.clone())
                .or_default()
                .insert(peer_id.clone());
        }

        let record = self
            .peers
            .entry(peer_id.clone())
            .or_insert_with(|| PeerRecord {
                peer_id: peer_id.clone(),
                ip_group: ip_group.clone(),
                invalid_envelopes: 0,
                banned_until_unix: None,
                rate_window_started_unix: now_unix,
                accepted_in_window: 0,
            });
        record.ip_group = ip_group;
        Ok(PeerDecision::Allowed)
    }

    pub fn check_envelope_allowed(
        &mut self,
        peer_id: &str,
        now_unix: i64,
    ) -> Result<PeerDecision, PeerPolicyError> {
        validate_peer_id(peer_id)?;
        let peer_id = peer_id.to_ascii_lowercase();
        let record = self
            .peers
            .entry(peer_id.clone())
            .or_insert_with(|| PeerRecord {
                peer_id,
                ip_group: None,
                invalid_envelopes: 0,
                banned_until_unix: None,
                rate_window_started_unix: now_unix,
                accepted_in_window: 0,
            });

        if let Some(banned_until_unix) = record.banned_until_unix {
            if now_unix < banned_until_unix {
                return Ok(PeerDecision::Banned { banned_until_unix });
            }
            record.banned_until_unix = None;
            record.invalid_envelopes = 0;
        }

        if now_unix.saturating_sub(record.rate_window_started_unix)
            >= self.config.rate_window_seconds
        {
            record.rate_window_started_unix = now_unix;
            record.accepted_in_window = 0;
        }

        if record.accepted_in_window >= self.config.max_envelopes_per_window {
            let retry_after_seconds = self
                .config
                .rate_window_seconds
                .saturating_sub(now_unix.saturating_sub(record.rate_window_started_unix))
                .max(1);
            return Ok(PeerDecision::RateLimited {
                retry_after_seconds,
            });
        }

        record.accepted_in_window += 1;
        Ok(PeerDecision::Allowed)
    }

    pub fn record_invalid_envelope(
        &mut self,
        peer_id: &str,
        now_unix: i64,
    ) -> Result<PeerDecision, PeerPolicyError> {
        validate_peer_id(peer_id)?;
        let peer_id = peer_id.to_ascii_lowercase();
        let record = self
            .peers
            .entry(peer_id.clone())
            .or_insert_with(|| PeerRecord {
                peer_id,
                ip_group: None,
                invalid_envelopes: 0,
                banned_until_unix: None,
                rate_window_started_unix: now_unix,
                accepted_in_window: 0,
            });
        record.invalid_envelopes = record.invalid_envelopes.saturating_add(1);
        if record.invalid_envelopes >= self.config.max_invalid_envelopes {
            let banned_until_unix = now_unix.saturating_add(self.config.ban_seconds);
            record.banned_until_unix = Some(banned_until_unix);
            return Ok(PeerDecision::Banned { banned_until_unix });
        }
        Ok(PeerDecision::Allowed)
    }

    pub fn record_valid_envelope(&mut self, peer_id: &str) -> Result<(), PeerPolicyError> {
        validate_peer_id(peer_id)?;
        let peer_id = peer_id.to_ascii_lowercase();
        if let Some(record) = self.peers.get_mut(&peer_id) {
            record.invalid_envelopes = record.invalid_envelopes.saturating_sub(1);
        }
        Ok(())
    }

    fn ip_record(&mut self, ip: IpAddr, now_unix: i64) -> &mut IpRecord {
        let ip = ip_record_key(ip);
        self.ips.entry(ip.clone()).or_insert_with(|| IpRecord {
            ip,
            invalid_envelopes: 0,
            banned_until_unix: None,
            rate_window_started_unix: now_unix,
            accepted_in_window: 0,
            read_window_started_unix: now_unix,
            read_requests_in_window: 0,
        })
    }

    fn max_envelopes_per_ip_window(&self) -> u32 {
        self.config
            .max_envelopes_per_window
            .saturating_mul(u32::try_from(self.config.max_peers_per_ip_group).unwrap_or(u32::MAX))
            .max(self.config.max_envelopes_per_window)
    }
}

fn validate_config(config: &PeerPolicyConfig) -> Result<(), PeerPolicyError> {
    if config.max_envelopes_per_window == 0 {
        return Err(PeerPolicyError::InvalidConfig(
            "max_envelopes_per_window must be greater than zero".to_string(),
        ));
    }
    if config.max_read_requests_per_window == 0 {
        return Err(PeerPolicyError::InvalidConfig(
            "max_read_requests_per_window must be greater than zero".to_string(),
        ));
    }
    if config.rate_window_seconds <= 0 {
        return Err(PeerPolicyError::InvalidConfig(
            "rate_window_seconds must be greater than zero".to_string(),
        ));
    }
    if config.max_invalid_envelopes == 0 {
        return Err(PeerPolicyError::InvalidConfig(
            "max_invalid_envelopes must be greater than zero".to_string(),
        ));
    }
    if config.ban_seconds <= 0 {
        return Err(PeerPolicyError::InvalidConfig(
            "ban_seconds must be greater than zero".to_string(),
        ));
    }
    if config.max_peers_per_ip_group == 0 {
        return Err(PeerPolicyError::InvalidConfig(
            "max_peers_per_ip_group must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_peer_id(peer_id: &str) -> Result<(), PeerPolicyError> {
    if peer_id.len() != 64
        || !peer_id
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(PeerPolicyError::InvalidPeerId);
    }
    Ok(())
}

fn ip_group_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            format!("v4:{:02x}{:02x}", octets[0], octets[1])
        }
        IpAddr::V6(addr) => {
            let octets = addr.octets();
            format!(
                "v6:{:02x}{:02x}{:02x}{:02x}",
                octets[0], octets[1], octets[2], octets[3]
            )
        }
    }
}

fn ip_record_key(ip: IpAddr) -> String {
    ip.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn config() -> PeerPolicyConfig {
        PeerPolicyConfig {
            max_envelopes_per_window: 2,
            max_read_requests_per_window: 4,
            rate_window_seconds: 10,
            max_invalid_envelopes: 2,
            ban_seconds: 60,
            max_peers_per_ip_group: 1,
        }
    }

    fn peer(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn rate_limits_envelopes_per_peer_window() {
        let mut policy = PeerPolicy::new(config()).unwrap();
        let peer = peer(1);

        assert_eq!(
            policy.check_envelope_allowed(&peer, 100).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.check_envelope_allowed(&peer, 101).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.check_envelope_allowed(&peer, 102).unwrap(),
            PeerDecision::RateLimited {
                retry_after_seconds: 8
            }
        );
        assert_eq!(
            policy.check_envelope_allowed(&peer, 110).unwrap(),
            PeerDecision::Allowed
        );
    }

    #[test]
    fn bans_peer_after_repeated_invalid_envelopes() {
        let mut policy = PeerPolicy::new(config()).unwrap();
        let peer = peer(2);

        assert_eq!(
            policy.record_invalid_envelope(&peer, 100).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.record_invalid_envelope(&peer, 101).unwrap(),
            PeerDecision::Banned {
                banned_until_unix: 161
            }
        );
        assert_eq!(
            policy.check_envelope_allowed(&peer, 102).unwrap(),
            PeerDecision::Banned {
                banned_until_unix: 161
            }
        );
    }

    #[test]
    fn valid_envelopes_reduce_invalid_strike_count() {
        let mut policy = PeerPolicy::new(config()).unwrap();
        let peer = peer(2);

        assert_eq!(
            policy.record_invalid_envelope(&peer, 100).unwrap(),
            PeerDecision::Allowed
        );
        policy.record_valid_envelope(&peer).unwrap();
        assert_eq!(
            policy.record_invalid_envelope(&peer, 101).unwrap(),
            PeerDecision::Allowed
        );
    }

    #[test]
    fn limits_peers_per_ip_group() {
        let mut policy = PeerPolicy::new(config()).unwrap();
        let first = peer(1);
        let second = peer(2);
        let first_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let second_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 9, 9));

        assert_eq!(
            policy.admit_peer(&first, Some(first_ip), 100).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.admit_peer(&second, Some(second_ip), 100).unwrap(),
            PeerDecision::IpGroupFull {
                ip_group: "v4:0a01".to_string(),
                max_peers_per_ip_group: 1
            }
        );
    }

    #[test]
    fn moving_peer_between_ip_groups_releases_old_group_slot() {
        let mut policy = PeerPolicy::new(config()).unwrap();
        let first = peer(1);
        let second = peer(2);
        let first_group_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let second_group_ip = IpAddr::V4(Ipv4Addr::new(10, 2, 2, 3));
        let replacement_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 9, 9));

        assert_eq!(
            policy
                .admit_peer(&first, Some(first_group_ip), 100)
                .unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy
                .admit_peer(&first, Some(second_group_ip), 101)
                .unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy
                .admit_peer(&second, Some(replacement_ip), 102)
                .unwrap(),
            PeerDecision::Allowed
        );
    }

    #[test]
    fn rate_limits_envelopes_per_ip_window() {
        let mut policy = PeerPolicy::new(config()).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

        assert_eq!(
            policy.check_ip_envelope_allowed(ip, 100).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.check_ip_envelope_allowed(ip, 101).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.check_ip_envelope_allowed(ip, 102).unwrap(),
            PeerDecision::RateLimited {
                retry_after_seconds: 8
            }
        );
    }

    #[test]
    fn rate_limits_read_requests_per_ip_window_without_spending_envelope_budget() {
        let mut config = config();
        config.max_read_requests_per_window = 2;
        let mut policy = PeerPolicy::new(config).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

        assert_eq!(
            policy.check_ip_read_request_allowed(ip, 100).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.check_ip_read_request_allowed(ip, 101).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.check_ip_read_request_allowed(ip, 102).unwrap(),
            PeerDecision::RateLimited {
                retry_after_seconds: 8
            }
        );
        assert_eq!(
            policy.check_ip_envelope_allowed(ip, 103).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.check_ip_read_request_allowed(ip, 110).unwrap(),
            PeerDecision::Allowed
        );
    }

    #[test]
    fn bans_ip_after_repeated_invalid_envelopes() {
        let mut policy = PeerPolicy::new(config()).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

        assert_eq!(
            policy.record_invalid_ip_envelope(ip, 100).unwrap(),
            PeerDecision::Allowed
        );
        assert_eq!(
            policy.record_invalid_ip_envelope(ip, 101).unwrap(),
            PeerDecision::Banned {
                banned_until_unix: 161
            }
        );
        assert_eq!(
            policy.check_ip_envelope_allowed(ip, 102).unwrap(),
            PeerDecision::Banned {
                banned_until_unix: 161
            }
        );
    }
}
