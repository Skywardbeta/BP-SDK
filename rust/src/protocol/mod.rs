use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

pub use crate::error::{BpError, BpResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Priority {
    Bulk = 0,
    Standard = 1,
    Expedited = 2,
}

impl Default for Priority {
    fn default() -> Self {
        Self::Standard
    }
}

impl Priority {
    pub fn as_int(self) -> i32 {
        self as i32
    }
    
    pub fn from_int(value: i32) -> Self {
        match value {
            0 => Self::Bulk,
            2 => Self::Expedited,
            _ => Self::Standard,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Custody {
    None = 0,
    Optional = 1,
    Required = 2,
}

impl Default for Custody {
    fn default() -> Self {
        Self::None
    }
}

impl Custody {
    pub fn as_int(self) -> i32 {
        self as i32
    }
    
    pub fn from_int(value: i32) -> Self {
        match value {
            1 => Self::Optional,
            2 => Self::Required,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpTimestamp {
    pub msec: u64,
    pub count: u32,
}

impl BpTimestamp {
    pub fn now() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        
        Self {
            msec: now.as_millis() as u64,
            count: 0,
        }
    }
    
    pub fn to_datetime(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.msec as i64 / 1000, 0)
            .unwrap_or_else(|| Utc::now())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Eid(String);

impl Eid {
    pub fn new(eid: impl Into<String>) -> BpResult<Self> {
        let eid = eid.into();
        
        if eid.starts_with("ipn:") && eid.contains('.') {
            Ok(Self(eid))
        } else if eid.starts_with("dtn:") {
            Ok(Self(eid))
        } else {
            Err(BpError::InvalidArgs)
        }
    }
    
    pub fn ipn(node: u64, service: u64) -> Self {
        Self(format!("ipn:{}.{}", node, service))
    }
    
    pub fn dtn(endpoint: &str) -> Self {
        Self(format!("dtn:{}", endpoint))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
    
    pub fn node_number(&self) -> Option<u64> {
        self.0.strip_prefix("ipn:")?.split('.').next()?.parse().ok()
    }
    
    pub fn service_number(&self) -> Option<u64> {
        self.0.strip_prefix("ipn:")?.split('.').nth(1)?.parse().ok()
    }
}

impl std::fmt::Display for Eid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for Eid {
    type Err = BpError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub id: Uuid,
    pub source_eid: Eid,
    pub dest_eid: Eid,
    pub creation_time: BpTimestamp,
    pub ttl: Duration,
    pub priority: Priority,
    pub custody: Custody,
    pub payload: Bytes,
    pub metadata: HashMap<String, String>,
}

impl Bundle {
    pub fn new(source_eid: Eid, dest_eid: Eid, payload: impl Into<Bytes>) -> Self {
        Self {
            id: Uuid::new_v4(),
            source_eid,
            dest_eid,
            creation_time: BpTimestamp::now(),
            ttl: Duration::from_secs(3600),
            priority: Priority::default(),
            custody: Custody::default(),
            payload: payload.into(),
            metadata: HashMap::new(),
        }
    }
    
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }
    
    pub fn with_custody(mut self, custody: Custody) -> Self {
        self.custody = custody;
        self
    }
    
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
    
    pub fn add_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
    
    pub fn payload_size(&self) -> usize {
        self.payload.len()
    }
    
    pub fn is_expired(&self) -> bool {
        let elapsed = BpTimestamp::now().msec.saturating_sub(self.creation_time.msec);
        elapsed > self.ttl.as_millis() as u64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub dest_eid: Eid,
    pub next_hop: Eid,
    pub cost: u32,
    pub confidence: f32,
    pub valid_until: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

impl Route {
    pub fn new(dest_eid: Eid, next_hop: Eid, cost: u32) -> Self {
        Self {
            dest_eid,
            next_hop,
            cost,
            confidence: 1.0,
            valid_until: Utc::now() + chrono::Duration::hours(1),
            metadata: HashMap::new(),
        }
    }
    
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
    
    pub fn with_validity(mut self, valid_until: DateTime<Utc>) -> Self {
        self.valid_until = valid_until;
        self
    }
    
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.valid_until
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub neighbor_eid: Eid,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub data_rate: u32,
    pub confidence: f32,
}

impl Contact {
    pub fn new(
        neighbor_eid: Eid,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        data_rate: u32,
    ) -> Self {
        Self {
            neighbor_eid,
            start_time,
            end_time,
            data_rate,
            confidence: 1.0,
        }
    }
    
    pub fn duration(&self) -> chrono::Duration {
        self.end_time - self.start_time
    }
    
    pub fn is_active(&self) -> bool {
        let now = Utc::now();
        now >= self.start_time && now <= self.end_time
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    pub neighbor_eid: Eid,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub owlt: Duration,
}

impl Range {
    pub fn new(
        neighbor_eid: Eid,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        owlt: Duration,
    ) -> Self {
        Self {
            neighbor_eid,
            start_time,
            end_time,
            owlt,
        }
    }
    
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.start_time && now <= self.end_time
    }
} 