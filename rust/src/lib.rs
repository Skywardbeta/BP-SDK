//! Bundle Protocol SDK (Rust)
//! 
//! Modern Rust wrapper for NASA's ION-DTN Bundle Protocol implementation.

pub mod error;
pub mod types;
pub mod ffi;
pub mod core;
pub mod cla;
pub mod bpsec;
pub mod routing;
pub mod metrics;
pub mod testing;

pub use error::{BpError, BpResult};
pub use types::{Bundle, Custody, Eid, Priority, Statistics, Route, Contact, Range, TransportConfig, BpTimestamp};
pub use core::{BpSdk, Endpoint};
pub use cla::{Cla, ClaManager, TcpCla, UdpCla};
pub use bpsec::{BpsecManager, SecurityBlock, SecurityPolicy};
pub use routing::{RoutingEngine, EpidemicRouting, SprayAndWaitRouting};
pub use metrics::{MetricsCollector, PerformanceMetrics};

pub mod prelude {
    pub use crate::{
        BpSdk, Endpoint, Bundle, Eid, Priority, Custody, 
        BpError, BpResult, Cla, ClaManager, BpsecManager,
        RoutingEngine, MetricsCollector, Route, Contact
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_eid_validation_and_parsing() {
        assert!(Eid::new("ipn:1.1").is_ok());
        assert!(Eid::new("ipn:123.456").is_ok());
        assert!(Eid::new("invalid").is_err());
        assert!(Eid::new("ipn:1").is_err());
        
        let eid = Eid::new("ipn:123.456").unwrap();
        assert_eq!(eid.node_number(), Some(123));
        assert_eq!(eid.service_number(), Some(456));
        assert_eq!(eid.as_str(), "ipn:123.456");
        
        let parsed: Eid = "ipn:789.012".parse().unwrap();
        assert_eq!(parsed.node_number(), Some(789));
        assert_eq!(parsed.service_number(), Some(12));
    }

    #[test]
    fn test_bundle_creation_and_expiration() {
        let source = Eid::new("ipn:1.1").unwrap();
        let dest = Eid::new("ipn:2.1").unwrap();
        let payload = "Hello, DTN!";
        
        let bundle = Bundle::new(source.clone(), dest.clone(), payload)
            .with_priority(Priority::Expedited)
            .with_custody(Custody::Required)
            .with_ttl(Duration::from_secs(7200));
        
        assert_eq!(bundle.source_eid, source);
        assert_eq!(bundle.dest_eid, dest);
        assert_eq!(bundle.priority, Priority::Expedited);
        assert_eq!(bundle.custody, Custody::Required);
        assert_eq!(bundle.ttl, Duration::from_secs(7200));
        assert_eq!(bundle.payload, payload.as_bytes());
        assert!(!bundle.is_expired());

        let short_bundle = Bundle::new(source, dest, "test").with_ttl(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));
        assert!(short_bundle.is_expired());
    }

    #[test]
    fn test_route_and_contact_validity() {
        let dest = Eid::new("ipn:2.1").unwrap();
        let next_hop = Eid::new("ipn:3.1").unwrap();
        
        let route = Route::new(dest, next_hop, 100)
            .with_confidence(0.9)
            .with_validity(chrono::Utc::now() + chrono::Duration::seconds(60));
        
        assert!(route.is_valid());
        assert_eq!(route.confidence, 0.9);
        assert_eq!(route.cost, 100);

        let neighbor = Eid::new("ipn:2.1").unwrap();
        let start = chrono::Utc::now();
        let end = start + chrono::Duration::hours(2);
        
        let contact = Contact::new(neighbor, start, end, 1_000_000);
        assert_eq!(contact.duration(), chrono::Duration::hours(2));
    }

    #[tokio::test]
    async fn test_cla_manager_operations() {
        let manager = ClaManager::new();
        assert!(manager.list_protocols().is_empty());
        
        let _udp_cla = manager.create_udp_cla("127.0.0.1:0").await.unwrap();
        let _tcp_cla = manager.create_tcp_cla("127.0.0.1:0").await.unwrap();
        
        let protocols = manager.list_protocols();
        assert_eq!(protocols.len(), 2);
        assert!(protocols.contains(&"udp".to_string()));
        assert!(protocols.contains(&"tcp".to_string()));
        
        manager.unregister("udp").unwrap();
        manager.unregister("tcp").unwrap();
        assert!(manager.list_protocols().is_empty());
    }

    #[test]
    fn test_transport_config_creation() {
        let tcp_config = TransportConfig::tcp("192.168.1.100:8080");
        assert_eq!(tcp_config.protocol, "tcp");
        assert_eq!(tcp_config.local_address, "192.168.1.100:8080");
        assert_eq!(tcp_config.max_payload_size, 65536);

        let udp_config = TransportConfig::udp("10.0.0.1:9090");
        assert_eq!(udp_config.protocol, "udp");
        assert_eq!(udp_config.local_address, "10.0.0.1:9090");
        assert_eq!(udp_config.max_payload_size, 1472);
    }

    #[test]
    fn test_error_conversion() {
        let error = BpError::from(-1);
        assert_eq!(error, BpError::InvalidArgs);
        
        let error = BpError::from(-3);
        assert_eq!(error, BpError::Memory);
        
        let proto_error = BpError::Protocol("Test error".to_string());
        assert!(matches!(proto_error, BpError::Protocol(_)));
    }

    #[test]
    fn test_statistics() {
        let mut stats = Statistics::new();
        assert_eq!(stats.bundles_sent, 0);
        
        stats.bundles_sent += 1;
        stats.bytes_sent += 100;
        
        assert_eq!(stats.bundles_sent, 1);
        assert_eq!(stats.bytes_sent, 100);
        
        stats.reset();
        assert_eq!(stats.bundles_sent, 0);
    }

    #[test]
    fn test_timestamp_operations() {
        let timestamp = BpTimestamp::now();
        assert!(timestamp.msec > 0);
        let datetime = timestamp.to_datetime();
        assert!(datetime.timestamp() > 0);
    }

    #[tokio::test]
    async fn test_bpsec_operations() {
        let manager = BpsecManager::new();
        
        let key = bytes::Bytes::from_static(b"test_key_32_bytes_long_example__");
        assert!(manager.add_key("default", key).is_ok());
        
        let policy = SecurityPolicy::new("test_policy", crate::bpsec::SecurityOperation::Encrypt);
        
        assert!(manager.add_policy(policy).is_ok());
        assert!(manager.get_policy("test_policy").is_some());
        
        let bundle = Bundle::new(
            Eid::new("ipn:1.1").unwrap(),
            Eid::new("ipn:2.1").unwrap(),
            "test data"
        );
        
        let secured_bundle = manager.apply_security(&bundle).unwrap();
        assert!(secured_bundle.payload.len() >= bundle.payload.len());
    }

    #[test]
    fn test_routing_engines() {
        let epidemic = EpidemicRouting::new();
        let spray_wait = SprayAndWaitRouting::new(10);
        
        assert_eq!(epidemic.name(), "epidemic");
        assert_eq!(spray_wait.name(), "spray_and_wait");
        
        let dest = Eid::new("ipn:2.1").unwrap();
        let routes = epidemic.compute_routes(&dest, &vec![]);
        assert!(!routes.is_empty());
    }

    #[test]
    fn test_metrics_collection() {
        let collector = MetricsCollector::new();
        collector.record_bundle_sent(1024);
        collector.record_bundle_received(512);
        
        let metrics = collector.get_metrics();
        assert_eq!(metrics.bundles_sent, 1);
        assert_eq!(metrics.bytes_sent, 1024);
        assert_eq!(metrics.bundles_received, 1);
        assert_eq!(metrics.bytes_received, 512);
    }
} 