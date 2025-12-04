use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub bundles_sent: u64,
    pub bundles_received: u64,
    pub bundles_forwarded: u64,
    pub bundles_delivered: u64,
    pub bundles_expired: u64,
    pub bundles_dropped: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_avg_ms: f64,
    pub latency_min_ms: f64,
    pub latency_max_ms: f64,
    pub throughput_bps: f64,
    pub delivery_ratio: f64,
    pub buffer_utilization: f64,
    pub active_connections: u32,
    pub timestamp: DateTime<Utc>,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            bundles_sent: 0,
            bundles_received: 0,
            bundles_forwarded: 0,
            bundles_delivered: 0,
            bundles_expired: 0,
            bundles_dropped: 0,
            bytes_sent: 0,
            bytes_received: 0,
            latency_avg_ms: 0.0,
            latency_min_ms: f64::MAX,
            latency_max_ms: 0.0,
            throughput_bps: 0.0,
            delivery_ratio: 0.0,
            buffer_utilization: 0.0,
            active_connections: 0,
            timestamp: Utc::now(),
        }
    }

    pub fn compute_delivery_ratio(&mut self) {
        let total_sent = self.bundles_sent + self.bundles_forwarded;
        if total_sent > 0 {
            self.delivery_ratio = self.bundles_delivered as f64 / total_sent as f64;
        }
    }

    pub fn compute_throughput(&mut self, duration: Duration) {
        if duration.as_secs() > 0 {
            self.throughput_bps = (self.bytes_sent + self.bytes_received) as f64 / duration.as_secs_f64();
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyMeasurement {
    pub bundle_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub latency_ms: f64,
    pub hop_count: u32,
}

impl LatencyMeasurement {
    pub fn new(bundle_id: String, start_time: DateTime<Utc>) -> Self {
        let end_time = Utc::now();
        let latency_ms = end_time.signed_duration_since(start_time).num_milliseconds() as f64;
        
        Self {
            bundle_id,
            start_time,
            end_time,
            latency_ms,
            hop_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connection_time: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub is_active: bool,
}

impl ConnectionMetrics {
    pub fn new(protocol: String, local_address: String, remote_address: String) -> Self {
        let now = Utc::now();
        Self {
            protocol,
            local_address,
            remote_address,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            connection_time: now,
            last_activity: now,
            is_active: true,
        }
    }

    pub fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.packets_sent += 1;
        self.last_activity = Utc::now();
    }

    pub fn record_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.packets_received += 1;
        self.last_activity = Utc::now();
    }

    pub fn connection_duration(&self) -> Duration {
        let now = Utc::now();
        Duration::from_secs((now.signed_duration_since(self.connection_time).num_seconds()).max(0) as u64)
    }
}

#[derive(Debug)]
pub struct MetricsCollector {
    bundles_sent: AtomicU64,
    bundles_received: AtomicU64,
    bundles_forwarded: AtomicU64,
    bundles_delivered: AtomicU64,
    bundles_expired: AtomicU64,
    bundles_dropped: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    
    latency_measurements: RwLock<VecDeque<LatencyMeasurement>>,
    connection_metrics: RwLock<HashMap<String, ConnectionMetrics>>,
    historical_metrics: RwLock<VecDeque<PerformanceMetrics>>,
    
    start_time: Instant,
    max_history_size: usize,
    max_latency_samples: usize,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            bundles_sent: AtomicU64::new(0),
            bundles_received: AtomicU64::new(0),
            bundles_forwarded: AtomicU64::new(0),
            bundles_delivered: AtomicU64::new(0),
            bundles_expired: AtomicU64::new(0),
            bundles_dropped: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            
            latency_measurements: RwLock::new(VecDeque::new()),
            connection_metrics: RwLock::new(HashMap::new()),
            historical_metrics: RwLock::new(VecDeque::new()),
            
            start_time: Instant::now(),
            max_history_size: 1000,
            max_latency_samples: 10000,
        }
    }

    pub fn with_history_size(mut self, size: usize) -> Self {
        self.max_history_size = size;
        self
    }

    pub fn with_latency_samples(mut self, samples: usize) -> Self {
        self.max_latency_samples = samples;
        self
    }

    pub fn record_bundle_sent(&self, bytes: u64) {
        self.bundles_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_bundle_received(&self, bytes: u64) {
        self.bundles_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_bundle_forwarded(&self, bytes: u64) {
        self.bundles_forwarded.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_bundle_delivered(&self) {
        self.bundles_delivered.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bundle_expired(&self) {
        self.bundles_expired.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bundle_dropped(&self) {
        self.bundles_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_latency(&self, measurement: LatencyMeasurement) {
        let mut latencies = self.latency_measurements.write();
        latencies.push_back(measurement);
        
        if latencies.len() > self.max_latency_samples {
            latencies.pop_front();
        }
    }

    pub fn record_connection_activity(&self, connection_id: &str, sent_bytes: u64, received_bytes: u64) {
        let mut connections = self.connection_metrics.write();
        if let Some(metrics) = connections.get_mut(connection_id) {
            if sent_bytes > 0 {
                metrics.record_sent(sent_bytes);
            }
            if received_bytes > 0 {
                metrics.record_received(received_bytes);
            }
        }
    }

    pub fn add_connection(&self, connection_id: String, metrics: ConnectionMetrics) {
        let mut connections = self.connection_metrics.write();
        connections.insert(connection_id, metrics);
    }

    pub fn remove_connection(&self, connection_id: &str) {
        let mut connections = self.connection_metrics.write();
        if let Some(mut metrics) = connections.remove(connection_id) {
            metrics.is_active = false;
        }
    }

    pub fn get_metrics(&self) -> PerformanceMetrics {
        let mut metrics = PerformanceMetrics::new();
        
        metrics.bundles_sent = self.bundles_sent.load(Ordering::Relaxed);
        metrics.bundles_received = self.bundles_received.load(Ordering::Relaxed);
        metrics.bundles_forwarded = self.bundles_forwarded.load(Ordering::Relaxed);
        metrics.bundles_delivered = self.bundles_delivered.load(Ordering::Relaxed);
        metrics.bundles_expired = self.bundles_expired.load(Ordering::Relaxed);
        metrics.bundles_dropped = self.bundles_dropped.load(Ordering::Relaxed);
        metrics.bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        metrics.bytes_received = self.bytes_received.load(Ordering::Relaxed);
        
        let latencies = self.latency_measurements.read();
        if !latencies.is_empty() {
            let latency_values: Vec<f64> = latencies.iter().map(|m| m.latency_ms).collect();
            metrics.latency_avg_ms = latency_values.iter().sum::<f64>() / latency_values.len() as f64;
            metrics.latency_min_ms = latency_values.iter().cloned().fold(f64::INFINITY, f64::min);
            metrics.latency_max_ms = latency_values.iter().cloned().fold(0.0, f64::max);
        }
        
        let connections = self.connection_metrics.read();
        metrics.active_connections = connections.values().filter(|c| c.is_active).count() as u32;
        
        metrics.compute_delivery_ratio();
        metrics.compute_throughput(self.start_time.elapsed());
        
        metrics
    }

    pub fn get_connection_metrics(&self) -> Vec<ConnectionMetrics> {
        self.connection_metrics.read().values().cloned().collect()
    }

    pub fn get_latency_distribution(&self) -> HashMap<String, u64> {
        let latencies = self.latency_measurements.read();
        let mut distribution = HashMap::new();
        
        for measurement in latencies.iter() {
            let bucket = match measurement.latency_ms {
                0.0..=10.0 => "0-10ms",
                10.0..=50.0 => "10-50ms",
                50.0..=100.0 => "50-100ms",
                100.0..=500.0 => "100-500ms",
                500.0..=1000.0 => "500ms-1s",
                1000.0..=5000.0 => "1s-5s",
                _ => "5s+",
            };
            *distribution.entry(bucket.to_string()).or_insert(0) += 1;
        }
        
        distribution
    }

    pub fn snapshot(&self) -> PerformanceMetrics {
        let metrics = self.get_metrics();
        
        let mut historical = self.historical_metrics.write();
        historical.push_back(metrics.clone());
        
        if historical.len() > self.max_history_size {
            historical.pop_front();
        }
        
        metrics
    }

    pub fn get_historical_metrics(&self) -> Vec<PerformanceMetrics> {
        self.historical_metrics.read().iter().cloned().collect()
    }

    pub fn reset(&self) {
        self.bundles_sent.store(0, Ordering::Relaxed);
        self.bundles_received.store(0, Ordering::Relaxed);
        self.bundles_forwarded.store(0, Ordering::Relaxed);
        self.bundles_delivered.store(0, Ordering::Relaxed);
        self.bundles_expired.store(0, Ordering::Relaxed);
        self.bundles_dropped.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        
        self.latency_measurements.write().clear();
        self.connection_metrics.write().clear();
        self.historical_metrics.write().clear();
    }

    pub fn export_json(&self) -> String {
        let metrics = self.get_metrics();
        serde_json::to_string_pretty(&metrics).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn export_csv(&self) -> String {
        let metrics = self.get_metrics();
        format!(
            "timestamp,bundles_sent,bundles_received,bundles_delivered,delivery_ratio,throughput_bps,latency_avg_ms\n{},{},{},{},{:.3},{:.2},{:.2}",
            metrics.timestamp.format("%Y-%m-%d %H:%M:%S"),
            metrics.bundles_sent,
            metrics.bundles_received,
            metrics.bundles_delivered,
            metrics.delivery_ratio,
            metrics.throughput_bps,
            metrics.latency_avg_ms
        )
    }

    pub fn get_summary(&self) -> String {
        let metrics = self.get_metrics();
        format!(
            "Bundle Protocol SDK Metrics Summary:\n\
            =====================================\n\
            Bundles Sent: {}\n\
            Bundles Received: {}\n\
            Bundles Delivered: {}\n\
            Delivery Ratio: {:.2}%\n\
            Throughput: {:.2} bytes/sec\n\
            Average Latency: {:.2} ms\n\
            Active Connections: {}\n\
            Uptime: {:.2} seconds",
            metrics.bundles_sent,
            metrics.bundles_received,
            metrics.bundles_delivered,
            metrics.delivery_ratio * 100.0,
            metrics.throughput_bps,
            metrics.latency_avg_ms,
            metrics.active_connections,
            self.start_time.elapsed().as_secs_f64()
        )
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MetricsAggregator {
    collectors: RwLock<Vec<MetricsCollector>>,
}

impl MetricsAggregator {
    pub fn new() -> Self {
        Self {
            collectors: RwLock::new(Vec::new()),
        }
    }

    pub fn add_collector(&self, collector: MetricsCollector) {
        self.collectors.write().push(collector);
    }

    pub fn aggregate_metrics(&self) -> PerformanceMetrics {
        let collectors = self.collectors.read();
        if collectors.is_empty() {
            return PerformanceMetrics::new();
        }

        let mut aggregated = PerformanceMetrics::new();
        let mut total_latency = 0.0;
        let mut latency_count = 0;
        let mut min_latency = f64::MAX;
        let mut max_latency = 0.0;

        for collector in collectors.iter() {
            let metrics = collector.get_metrics();
            
            aggregated.bundles_sent += metrics.bundles_sent;
            aggregated.bundles_received += metrics.bundles_received;
            aggregated.bundles_forwarded += metrics.bundles_forwarded;
            aggregated.bundles_delivered += metrics.bundles_delivered;
            aggregated.bundles_expired += metrics.bundles_expired;
            aggregated.bundles_dropped += metrics.bundles_dropped;
            aggregated.bytes_sent += metrics.bytes_sent;
            aggregated.bytes_received += metrics.bytes_received;
            aggregated.throughput_bps += metrics.throughput_bps;
            aggregated.active_connections += metrics.active_connections;
            
            if metrics.latency_avg_ms > 0.0 {
                total_latency += metrics.latency_avg_ms;
                latency_count += 1;
                
                if metrics.latency_min_ms < min_latency {
                    min_latency = metrics.latency_min_ms;
                }
                if metrics.latency_max_ms > max_latency {
                    max_latency = metrics.latency_max_ms;
                }
            }
        }

        if latency_count > 0 {
            aggregated.latency_avg_ms = total_latency / latency_count as f64;
            aggregated.latency_min_ms = min_latency;
            aggregated.latency_max_ms = max_latency;
        }

        aggregated.compute_delivery_ratio();
        aggregated.timestamp = Utc::now();
        
        aggregated
    }
}

impl Default for MetricsAggregator {
    fn default() -> Self {
        Self::new()
    }
} 