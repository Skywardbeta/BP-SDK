use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::protocol::{Bundle, Eid, BpResult, BpError};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Statistics {
    pub bundles_sent: u64,
    pub bundles_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub errors: u64,
    pub last_reset: DateTime<Utc>,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            last_reset: Utc::now(),
            ..Default::default()
        }
    }
    
    pub fn reset(&mut self) {
        *self = Self::new();
    }
    
    pub fn bundle_sent(&mut self, size: usize) {
        self.bundles_sent += 1;
        self.bytes_sent += size as u64;
    }
    
    pub fn bundle_received(&mut self, size: usize) {
        self.bundles_received += 1;
        self.bytes_received += size as u64;
    }
    
    pub fn error_occurred(&mut self) {
        self.errors += 1;
    }
    
    pub fn uptime(&self) -> chrono::Duration {
        Utc::now() - self.last_reset
    }
    
    pub fn send_rate(&self) -> f64 {
        let secs = self.uptime().num_seconds() as f64;
        if secs > 0.0 {
            self.bundles_sent as f64 / secs
        } else {
            0.0
        }
    }
    
    pub fn receive_rate(&self) -> f64 {
        let secs = self.uptime().num_seconds() as f64;
        if secs > 0.0 {
            self.bundles_received as f64 / secs
        } else {
            0.0
        }
    }
}

#[derive(Debug)]
pub struct AtomicStatistics {
    bundles_sent: AtomicU64,
    bundles_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    errors: AtomicU64,
    start_time: DateTime<Utc>,
}

impl AtomicStatistics {
    pub fn new() -> Self {
        Self {
            bundles_sent: AtomicU64::new(0),
            bundles_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            start_time: Utc::now(),
        }
    }
    
    pub fn bundle_sent(&self, size: usize) {
        self.bundles_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(size as u64, Ordering::Relaxed);
    }
    
    pub fn bundle_received(&self, size: usize) {
        self.bundles_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(size as u64, Ordering::Relaxed);
    }
    
    pub fn error_occurred(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn get_stats(&self) -> Statistics {
        Statistics {
            bundles_sent: self.bundles_sent.load(Ordering::Relaxed),
            bundles_received: self.bundles_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            last_reset: self.start_time,
        }
    }
}

pub struct Validation;

impl Validation {
    pub fn validate_eid(eid: &str) -> BpResult<()> {
        if eid.is_empty() {
            return Err(BpError::InvalidArgs);
        }
        
        if eid.starts_with("ipn:") {
            if let Some(rest) = eid.strip_prefix("ipn:") {
                let parts: Vec<&str> = rest.split('.').collect();
                if parts.len() != 2 {
                    return Err(BpError::InvalidArgs);
                }
                
                parts[0].parse::<u64>()
                    .map_err(|_| BpError::InvalidArgs)?;
                parts[1].parse::<u64>()
                    .map_err(|_| BpError::InvalidArgs)?;
                
                Ok(())
            } else {
                Err(BpError::InvalidArgs)
            }
        } else if eid.starts_with("dtn:") {
            if eid.len() > 4 {
                Ok(())
            } else {
                Err(BpError::InvalidArgs)
            }
        } else {
            Err(BpError::InvalidArgs)
        }
    }
    
    pub fn validate_bundle(bundle: &Bundle) -> BpResult<()> {
        Self::validate_eid(bundle.source_eid.as_str())?;
        Self::validate_eid(bundle.dest_eid.as_str())?;
        
        if bundle.payload.is_empty() {
            return Err(BpError::InvalidArgs);
        }
        
        if bundle.payload.len() > 1_000_000_000 {
            return Err(BpError::InvalidArgs);
        }
        
        if bundle.ttl.as_secs() == 0 {
            return Err(BpError::InvalidArgs);
        }
        
        Ok(())
    }
    
    pub fn validate_socket_addr(addr: &str) -> BpResult<SocketAddr> {
        addr.parse::<SocketAddr>()
            .map_err(|_| BpError::InvalidArgs)
    }
    
    pub fn validate_port(port: u16) -> BpResult<()> {
        if port == 0 {
            return Err(BpError::InvalidArgs);
        }
        
        if port < 1024 && port != 80 && port != 443 {
            return Err(BpError::InvalidArgs);
        }
        
        Ok(())
    }
    
    pub fn sanitize_string(input: &str) -> String {
        input.chars()
            .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_' || *c == ':')
            .collect()
    }
    
    pub fn validate_node_config(local_eid: &Eid, bind_addr: &str) -> BpResult<()> {
        Self::validate_eid(local_eid.as_str())?;
        Self::validate_socket_addr(bind_addr)?;
        Ok(())
    }
}

pub struct StatsCollector {
    stats: Arc<AtomicStatistics>,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(AtomicStatistics::new()),
        }
    }
    
    pub fn record_bundle_sent(&self, bundle: &Bundle) {
        self.stats.bundle_sent(bundle.payload_size());
    }
    
    pub fn record_bundle_received(&self, bundle: &Bundle) {
        self.stats.bundle_received(bundle.payload_size());
    }
    
    pub fn record_error(&self) {
        self.stats.error_occurred();
    }
    
    pub fn get_statistics(&self) -> Statistics {
        self.stats.get_stats()
    }
    
    pub fn clone_stats(&self) -> Arc<AtomicStatistics> {
        Arc::clone(&self.stats)
    }
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

pub fn validate_eid_format(eid: &str) -> bool {
    Validation::validate_eid(eid).is_ok()
}

pub fn validate_bundle_integrity(bundle: &Bundle) -> bool {
    Validation::validate_bundle(bundle).is_ok()
}

pub fn sanitize_node_id(node_id: &str) -> String {
    Validation::sanitize_string(node_id)
} 