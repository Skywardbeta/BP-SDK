use crate::{
    BpSdk, Bundle, Eid, Endpoint, Priority, Custody,
    metrics::{MetricsCollector, LatencyMeasurement},
    error::{BpError, BpResult},
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

pub struct TestScenario {
    pub name: String,
    pub description: String,
    pub nodes: Vec<TestNode>,
    pub topology: TestTopology,
    pub traffic_pattern: TrafficPattern,
    pub expected_results: TestResults,
}

#[derive(Clone)]
pub struct TestNode {
    pub eid: Eid,
    pub sdk: Option<Arc<BpSdk>>,
    pub endpoint: Option<Arc<Endpoint>>,
    pub metrics: Option<Arc<MetricsCollector>>,
    pub position: (f64, f64),
    pub mobility: Option<MobilityModel>,
}

impl TestNode {
    pub fn new(eid: Eid) -> Self {
        Self {
            eid,
            sdk: None,
            endpoint: None,
            metrics: None,
            position: (0.0, 0.0),
            mobility: None,
        }
    }

    pub fn with_position(mut self, x: f64, y: f64) -> Self {
        self.position = (x, y);
        self
    }

    pub fn with_mobility(mut self, mobility: MobilityModel) -> Self {
        self.mobility = Some(mobility);
        self
    }

    pub async fn initialize(&mut self) -> BpResult<()> {
        let sdk = BpSdk::new(self.eid.clone(), None)?;
        sdk.init().await?;
        
        let endpoint = sdk.create_endpoint(self.eid.clone()).await?;
        let metrics = Arc::new(MetricsCollector::new());
        
        self.sdk = Some(Arc::new(sdk));
        self.endpoint = Some(endpoint);
        self.metrics = Some(metrics);
        
        Ok(())
    }

    pub async fn send_bundle(&self, dest: &Eid, payload: &str) -> BpResult<()> {
        if let Some(sdk) = &self.sdk {
            let bundle = Bundle::new(self.eid.clone(), dest.clone(), payload.to_string());
            sdk.send(bundle).await?;
            
            if let Some(metrics) = &self.metrics {
                metrics.record_bundle_sent(payload.len() as u64);
            }
        }
        Ok(())
    }

    pub async fn receive_bundle(&self, timeout_duration: Duration) -> BpResult<Bundle> {
        if let Some(endpoint) = &self.endpoint {
            let bundle = endpoint.receive(Some(timeout_duration)).await?;
            
            if let Some(metrics) = &self.metrics {
                metrics.record_bundle_received(bundle.payload.len() as u64);
            }
            
            Ok(bundle)
        } else {
            Err(BpError::NotInitialized)
        }
    }

    pub fn distance_to(&self, other: &TestNode) -> f64 {
        let dx = self.position.0 - other.position.0;
        let dy = self.position.1 - other.position.1;
        (dx * dx + dy * dy).sqrt()
    }
}

#[derive(Debug, Clone)]
pub enum MobilityModel {
    Static,
    RandomWalk { speed: f64, bounds: (f64, f64, f64, f64) },
    LinearMovement { velocity: (f64, f64) },
    CircularMovement { center: (f64, f64), radius: f64, angular_velocity: f64 },
}

impl MobilityModel {
    pub fn update_position(&self, current: (f64, f64), time_delta: f64) -> (f64, f64) {
        match self {
            MobilityModel::Static => current,
            MobilityModel::RandomWalk { speed, bounds } => {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                
                let mut hasher = DefaultHasher::new();
                current.0.to_bits().hash(&mut hasher);
                current.1.to_bits().hash(&mut hasher);
                let hash = hasher.finish();
                
                let angle = (hash as f64 / u64::MAX as f64) * 2.0 * std::f64::consts::PI;
                let distance = speed * time_delta;
                let new_x = (current.0 + distance * angle.cos()).clamp(bounds.0, bounds.2);
                let new_y = (current.1 + distance * angle.sin()).clamp(bounds.1, bounds.3);
                (new_x, new_y)
            }
            MobilityModel::LinearMovement { velocity } => {
                (current.0 + velocity.0 * time_delta, current.1 + velocity.1 * time_delta)
            }
            MobilityModel::CircularMovement { center, radius, angular_velocity } => {
                let current_angle = ((current.0 - center.0) / radius).atan2((current.1 - center.1) / radius);
                let new_angle = current_angle + angular_velocity * time_delta;
                (
                    center.0 + radius * new_angle.cos(),
                    center.1 + radius * new_angle.sin(),
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TestTopology {
    pub topology_type: TopologyType,
    pub communication_range: f64,
    pub link_reliability: f64,
    pub latency_ms: f64,
    pub bandwidth_bps: u64,
}

#[derive(Debug, Clone)]
pub enum TopologyType {
    FullyConnected,
    Linear,
    Ring,
    Star { hub_node: usize },
    Grid { width: usize, height: usize },
    Random { connection_probability: f64 },
}

impl TestTopology {
    pub fn can_communicate(&self, node1: &TestNode, node2: &TestNode) -> bool {
        match self.topology_type {
            TopologyType::FullyConnected => true,
            TopologyType::Linear => {
                let distance = node1.distance_to(node2);
                distance <= self.communication_range
            }
            TopologyType::Ring => {
                let distance = node1.distance_to(node2);
                distance <= self.communication_range
            }
            TopologyType::Star { .. } => {
                let distance = node1.distance_to(node2);
                distance <= self.communication_range
            }
            TopologyType::Grid { .. } => {
                let distance = node1.distance_to(node2);
                distance <= self.communication_range
            }
            TopologyType::Random { connection_probability } => {
                let distance = node1.distance_to(node2);
                let deterministic_value = ((node1.position.0 + node2.position.0) * 1000.0) % 1.0;
                distance <= self.communication_range && deterministic_value <= connection_probability
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrafficPattern {
    pub pattern_type: TrafficType,
    pub message_size: usize,
    pub message_interval: Duration,
    pub total_messages: usize,
    pub priority: Priority,
    pub custody: Custody,
}

#[derive(Debug, Clone)]
pub enum TrafficType {
    OneToOne { source: usize, destination: usize },
    OneToAll { source: usize },
    AllToOne { destination: usize },
    AllToAll,
    Random,
}

#[derive(Debug, Clone)]
pub struct TestResults {
    pub expected_delivery_ratio: f64,
    pub max_latency_ms: f64,
    pub min_throughput_bps: f64,
    pub max_overhead_ratio: f64,
}

pub struct TestHarness {
    pub scenarios: Vec<TestScenario>,
    pub current_scenario: Option<usize>,
    pub results: HashMap<String, TestExecutionResult>,
}

impl TestHarness {
    pub fn new() -> Self {
        Self {
            scenarios: Vec::new(),
            current_scenario: None,
            results: HashMap::new(),
        }
    }

    pub fn add_scenario(&mut self, scenario: TestScenario) {
        self.scenarios.push(scenario);
    }

    pub fn create_basic_scenarios(&mut self) -> BpResult<()> {
        self.add_scenario(TestScenario {
            name: "Basic P2P Communication".to_string(),
            description: "Two nodes exchanging messages".to_string(),
            nodes: vec![
                TestNode::new(Eid::new("ipn:1.1")?).with_position(0.0, 0.0),
                TestNode::new(Eid::new("ipn:2.1")?).with_position(100.0, 0.0),
            ],
            topology: TestTopology {
                topology_type: TopologyType::FullyConnected,
                communication_range: 200.0,
                link_reliability: 0.95,
                latency_ms: 50.0,
                bandwidth_bps: 1_000_000,
            },
            traffic_pattern: TrafficPattern {
                pattern_type: TrafficType::OneToOne { source: 0, destination: 1 },
                message_size: 1024,
                message_interval: Duration::from_millis(100),
                total_messages: 100,
                priority: Priority::Standard,
                custody: Custody::None,
            },
            expected_results: TestResults {
                expected_delivery_ratio: 0.95,
                max_latency_ms: 100.0,
                min_throughput_bps: 100_000.0,
                max_overhead_ratio: 0.1,
            },
        });

        self.add_scenario(TestScenario {
            name: "Mobile Network".to_string(),
            description: "Nodes with mobility patterns".to_string(),
            nodes: vec![
                TestNode::new(Eid::new("ipn:1.1")?).with_mobility(MobilityModel::RandomWalk {
                    speed: 10.0,
                    bounds: (0.0, 0.0, 1000.0, 1000.0),
                }),
                TestNode::new(Eid::new("ipn:2.1")?).with_mobility(MobilityModel::LinearMovement {
                    velocity: (5.0, 0.0),
                }),
                TestNode::new(Eid::new("ipn:3.1")?).with_mobility(MobilityModel::CircularMovement {
                    center: (500.0, 500.0),
                    radius: 200.0,
                    angular_velocity: 0.1,
                }),
            ],
            topology: TestTopology {
                topology_type: TopologyType::Random { connection_probability: 0.3 },
                communication_range: 150.0,
                link_reliability: 0.8,
                latency_ms: 100.0,
                bandwidth_bps: 500_000,
            },
            traffic_pattern: TrafficPattern {
                pattern_type: TrafficType::AllToAll,
                message_size: 512,
                message_interval: Duration::from_secs(1),
                total_messages: 50,
                priority: Priority::Standard,
                custody: Custody::Optional,
            },
            expected_results: TestResults {
                expected_delivery_ratio: 0.7,
                max_latency_ms: 5000.0,
                min_throughput_bps: 10_000.0,
                max_overhead_ratio: 0.5,
            },
        });

        Ok(())
    }

    pub async fn run_scenario(&mut self, scenario_index: usize) -> BpResult<TestExecutionResult> {
        if scenario_index >= self.scenarios.len() {
            return Err(BpError::InvalidArgs);
        }

        self.current_scenario = Some(scenario_index);
        
        println!("Running scenario: {}", self.scenarios[scenario_index].name);
        println!("Description: {}", self.scenarios[scenario_index].description);

        for node in &mut self.scenarios[scenario_index].nodes {
            node.initialize().await?;
        }

        let start_time = Utc::now();
        let mut sent_messages = 0;
        let mut received_messages = 0;
        let mut latency_measurements = Vec::new();

        let execution_duration = Duration::from_secs(30);
        let end_time = start_time + chrono::Duration::from_std(execution_duration).unwrap();

        while Utc::now() < end_time {
            execute_traffic_pattern(&mut self.scenarios[scenario_index], &mut sent_messages, &mut received_messages).await?;
            update_node_positions(&mut self.scenarios[scenario_index]).await;
            collect_latency_measurements(&self.scenarios[scenario_index], &mut latency_measurements).await;
            
            sleep(Duration::from_millis(100)).await;
        }

        let scenario = &self.scenarios[scenario_index];
        let result = analyze_results(scenario, sent_messages, received_messages, latency_measurements).await;
        self.results.insert(scenario.name.clone(), result.clone());

        Ok(result)
    }

    pub async fn run_all_scenarios(&mut self) -> BpResult<TestSummary> {
        let mut summary = TestSummary::new();
        
        for i in 0..self.scenarios.len() {
            let result = self.run_scenario(i).await?;
            summary.add_result(result);
        }

        Ok(summary)
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("Bundle Protocol SDK Test Report\n");
        report.push_str("===============================\n\n");

        for (name, result) in &self.results {
            report.push_str(&format!("Scenario: {}\n", name));
            report.push_str(&format!("Status: {}\n", if result.passed { "PASSED" } else { "FAILED" }));
            report.push_str(&format!("Delivery Ratio: {:.2}%\n", result.delivery_ratio * 100.0));
            report.push_str(&format!("Average Latency: {:.2} ms\n", result.avg_latency_ms));
            report.push_str(&format!("Throughput: {:.2} bps\n", result.throughput_bps));
            report.push_str(&format!("Messages Sent: {}\n", result.total_sent));
            report.push_str(&format!("Messages Received: {}\n", result.total_received));
            report.push_str("\n");
        }

        report
    }
}

// Standalone helper functions to avoid borrowing conflicts
async fn execute_traffic_pattern(scenario: &mut TestScenario, sent: &mut usize, _received: &mut usize) -> BpResult<()> {
    match scenario.traffic_pattern.pattern_type {
        TrafficType::OneToOne { source, destination } => {
            if source < scenario.nodes.len() && destination < scenario.nodes.len() {
                let payload = format!("Message {}", *sent);
                scenario.nodes[source].send_bundle(&scenario.nodes[destination].eid, &payload).await?;
                *sent += 1;
            }
        }
        TrafficType::OneToAll { source } => {
            if source < scenario.nodes.len() {
                let payload = format!("Broadcast {}", *sent);
                for (i, node) in scenario.nodes.iter().enumerate() {
                    if i != source {
                        scenario.nodes[source].send_bundle(&node.eid, &payload).await?;
                    }
                }
                *sent += 1;
            }
        }
        TrafficType::AllToOne { destination } => {
            if destination < scenario.nodes.len() {
                let payload = format!("Message {}", *sent);
                for (i, node) in scenario.nodes.iter().enumerate() {
                    if i != destination {
                        node.send_bundle(&scenario.nodes[destination].eid, &payload).await?;
                    }
                }
                *sent += 1;
            }
        }
        TrafficType::AllToAll => {
            let payload = format!("AllToAll {}", *sent);
            for (i, sender) in scenario.nodes.iter().enumerate() {
                for (j, receiver) in scenario.nodes.iter().enumerate() {
                    if i != j {
                        sender.send_bundle(&receiver.eid, &payload).await?;
                    }
                }
            }
            *sent += 1;
        }
        TrafficType::Random => {
            if scenario.nodes.len() >= 2 {
                let source = (*sent * 7) % scenario.nodes.len();
                let mut destination = (*sent * 13) % scenario.nodes.len();
                while destination == source {
                    destination = (destination + 1) % scenario.nodes.len();
                }
                let payload = format!("Random {}", *sent);
                scenario.nodes[source].send_bundle(&scenario.nodes[destination].eid, &payload).await?;
                *sent += 1;
            }
        }
    }
    Ok(())
}

async fn update_node_positions(scenario: &mut TestScenario) {
    for node in &mut scenario.nodes {
        if let Some(mobility) = &node.mobility {
            node.position = mobility.update_position(node.position, 0.1);
        }
    }
}

async fn collect_latency_measurements(scenario: &TestScenario, measurements: &mut Vec<LatencyMeasurement>) {
    for node in &scenario.nodes {
        if let Some(endpoint) = &node.endpoint {
            if let Ok(bundle) = timeout(Duration::from_millis(1), endpoint.receive(Some(Duration::from_millis(1)))).await {
                if let Ok(bundle) = bundle {
                    let measurement = LatencyMeasurement::new(
                        bundle.id.to_string(),
                        bundle.creation_time.to_datetime(),
                    );
                    measurements.push(measurement);
                }
            }
        }
    }
}

async fn analyze_results(scenario: &TestScenario, sent: usize, received: usize, measurements: Vec<LatencyMeasurement>) -> TestExecutionResult {
    let delivery_ratio = if sent > 0 { received as f64 / sent as f64 } else { 0.0 };
    
    let avg_latency = if !measurements.is_empty() {
        measurements.iter().map(|m| m.latency_ms).sum::<f64>() / measurements.len() as f64
    } else {
        0.0
    };

    let max_latency = measurements.iter().map(|m| m.latency_ms).fold(0.0, f64::max);
    let min_latency = measurements.iter().map(|m| m.latency_ms).fold(f64::MAX, f64::min);

    let total_metrics = scenario.nodes.iter()
        .filter_map(|n| n.metrics.as_ref())
        .map(|m| m.get_metrics())
        .fold(crate::metrics::PerformanceMetrics::new(), |mut acc, m| {
            acc.bundles_sent += m.bundles_sent;
            acc.bundles_received += m.bundles_received;
            acc.bytes_sent += m.bytes_sent;
            acc.bytes_received += m.bytes_received;
            acc
        });

    let passed = delivery_ratio >= scenario.expected_results.expected_delivery_ratio &&
                max_latency <= scenario.expected_results.max_latency_ms;

    TestExecutionResult {
        scenario_name: scenario.name.clone(),
        passed,
        delivery_ratio,
        avg_latency_ms: avg_latency,
        max_latency_ms: max_latency,
        min_latency_ms: if min_latency == f64::MAX { 0.0 } else { min_latency },
        total_sent: sent,
        total_received: received,
        throughput_bps: total_metrics.throughput_bps,
        overhead_ratio: if total_metrics.bytes_sent > 0 {
            (total_metrics.bytes_sent - total_metrics.bytes_received) as f64 / total_metrics.bytes_sent as f64
        } else {
            0.0
        },
        execution_time: Duration::from_secs(30),
    }
}

#[derive(Debug, Clone)]
pub struct TestExecutionResult {
    pub scenario_name: String,
    pub passed: bool,
    pub delivery_ratio: f64,
    pub avg_latency_ms: f64,
    pub max_latency_ms: f64,
    pub min_latency_ms: f64,
    pub total_sent: usize,
    pub total_received: usize,
    pub throughput_bps: f64,
    pub overhead_ratio: f64,
    pub execution_time: Duration,
}

#[derive(Debug, Clone)]
pub struct TestSummary {
    pub results: Vec<TestExecutionResult>,
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub avg_delivery_ratio: f64,
    pub avg_latency_ms: f64,
}

impl TestSummary {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            total_tests: 0,
            passed_tests: 0,
            failed_tests: 0,
            avg_delivery_ratio: 0.0,
            avg_latency_ms: 0.0,
        }
    }

    pub fn add_result(&mut self, result: TestExecutionResult) {
        self.total_tests += 1;
        if result.passed {
            self.passed_tests += 1;
        } else {
            self.failed_tests += 1;
        }
        
        self.results.push(result);
        self.update_averages();
    }

    fn update_averages(&mut self) {
        if !self.results.is_empty() {
            self.avg_delivery_ratio = self.results.iter().map(|r| r.delivery_ratio).sum::<f64>() / self.results.len() as f64;
            self.avg_latency_ms = self.results.iter().map(|r| r.avg_latency_ms).sum::<f64>() / self.results.len() as f64;
        }
    }
}

impl Default for TestHarness {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn run_integration_tests() -> BpResult<()> {
    println!("Running Bundle Protocol SDK Integration Tests...");
    
    let mut harness = TestHarness::new();
    harness.create_basic_scenarios()?;
    
    let summary = harness.run_all_scenarios().await?;
    
    println!("\n=== Test Summary ===");
    println!("Total Tests: {}", summary.total_tests);
    println!("Passed: {}", summary.passed_tests);
    println!("Failed: {}", summary.failed_tests);
    println!("Average Delivery Ratio: {:.2}%", summary.avg_delivery_ratio * 100.0);
    println!("Average Latency: {:.2} ms", summary.avg_latency_ms);
    
    println!("\n{}", harness.generate_report());
    
    Ok(())
} 