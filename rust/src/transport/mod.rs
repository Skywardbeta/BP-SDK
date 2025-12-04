use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;

use crate::protocol::{Bundle, Eid, BpResult, BpError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: Option<String>,
    pub max_payload_size: usize,
    pub timeout: Duration,
    pub parameters: HashMap<String, String>,
}

impl TransportConfig {
    pub fn tcp(local_address: impl Into<String>) -> Self {
        Self {
            protocol: "tcp".to_string(),
            local_address: local_address.into(),
            remote_address: None,
            max_payload_size: 65536,
            timeout: Duration::from_secs(30),
            parameters: HashMap::new(),
        }
    }
    
    pub fn udp(local_address: impl Into<String>) -> Self {
        Self {
            protocol: "udp".to_string(),
            local_address: local_address.into(),
            remote_address: None,
            max_payload_size: 1472,
            timeout: Duration::from_secs(10),
            parameters: HashMap::new(),
        }
    }
    
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    pub fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }
}

#[async_trait]
pub trait Cla: Send + Sync {
    async fn start(&self, config: &TransportConfig) -> BpResult<()>;
    async fn stop(&self) -> BpResult<()>;
    async fn send(&self, bundle: &Bundle, dest_eid: &Eid) -> BpResult<()>;
    async fn receive(&self) -> BpResult<Bundle>;
    fn is_running(&self) -> bool;
    fn protocol(&self) -> &str;
}

pub struct TcpCla {
    listener: Arc<RwLock<Option<TcpListener>>>,
    connections: Arc<RwLock<HashMap<String, TcpStream>>>,
    running: Arc<RwLock<bool>>,
}

impl TcpCla {
    pub fn new() -> Self {
        Self {
            listener: Arc::new(RwLock::new(None)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }
    
    async fn serialize_bundle(bundle: &Bundle) -> BpResult<Bytes> {
        let json = serde_json::to_string(bundle)
            .map_err(|_| BpError::Protocol("Failed to serialize bundle".to_string()))?;
        let data = json.into_bytes();
        let mut result = Vec::with_capacity(4 + data.len());
        result.extend_from_slice(&(data.len() as u32).to_be_bytes());
        result.extend_from_slice(&data);
        Ok(result.into())
    }
    
    async fn deserialize_bundle(data: &[u8]) -> BpResult<Bundle> {
        let json = std::str::from_utf8(data)
            .map_err(|_| BpError::Protocol("Invalid UTF-8 in bundle data".to_string()))?;
        serde_json::from_str(json)
            .map_err(|_| BpError::Protocol("Failed to deserialize bundle".to_string()))
    }
    
    async fn connect_to_peer(&self, address: &str) -> BpResult<TcpStream> {
        TcpStream::connect(address).await
            .map_err(|_| BpError::Protocol(format!("Failed to connect to {}", address)))
    }
}

#[async_trait]
impl Cla for TcpCla {
    async fn start(&self, config: &TransportConfig) -> BpResult<()> {
        let listener = TcpListener::bind(&config.local_address).await
            .map_err(|_| BpError::Protocol(format!("Failed to bind to {}", config.local_address)))?;
        
        *self.listener.write().await = Some(listener);
        *self.running.write().await = true;
        
        Ok(())
    }
    
    async fn stop(&self) -> BpResult<()> {
        *self.running.write().await = false;
        *self.listener.write().await = None;
        self.connections.write().await.clear();
        Ok(())
    }
    
    async fn send(&self, bundle: &Bundle, dest_eid: &Eid) -> BpResult<()> {
        let address = dest_eid.as_str().replace("ipn:", "127.0.0.1:");
        
        let mut stream = if let Some(stream) = self.connections.read().await.get(&address) {
            stream.try_clone().await
                .map_err(|_| BpError::Protocol("Failed to clone connection".to_string()))?
        } else {
            let stream = self.connect_to_peer(&address).await?;
            self.connections.write().await.insert(address.clone(), stream.try_clone().await.unwrap());
            stream
        };
        
        let data = Self::serialize_bundle(bundle).await?;
        stream.write_all(&data).await
            .map_err(|_| BpError::Protocol("Failed to send bundle".to_string()))?;
        
        Ok(())
    }
    
    async fn receive(&self) -> BpResult<Bundle> {
        let listener = self.listener.read().await;
        let listener = listener.as_ref()
            .ok_or_else(|| BpError::NotInitialized)?;
        
        let (mut stream, _) = listener.accept().await
            .map_err(|_| BpError::Protocol("Failed to accept connection".to_string()))?;
        
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await
            .map_err(|_| BpError::Protocol("Failed to read bundle length".to_string()))?;
        
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 10_000_000 {
            return Err(BpError::Protocol("Bundle too large".to_string()));
        }
        
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await
            .map_err(|_| BpError::Protocol("Failed to read bundle data".to_string()))?;
        
        Self::deserialize_bundle(&data).await
    }
    
    fn is_running(&self) -> bool {
        *self.running.try_read().unwrap_or_else(|_| std::sync::RwLockReadGuard::leak(
            std::sync::RwLock::new(false).read().unwrap()
        ))
    }
    
    fn protocol(&self) -> &str {
        "tcp"
    }
}

pub struct UdpCla {
    socket: Arc<RwLock<Option<UdpSocket>>>,
    running: Arc<RwLock<bool>>,
}

impl UdpCla {
    pub fn new() -> Self {
        Self {
            socket: Arc::new(RwLock::new(None)),
            running: Arc::new(RwLock::new(false)),
        }
    }
    
    async fn serialize_bundle(bundle: &Bundle) -> BpResult<Bytes> {
        let json = serde_json::to_string(bundle)
            .map_err(|_| BpError::Protocol("Failed to serialize bundle".to_string()))?;
        Ok(json.into_bytes().into())
    }
    
    async fn deserialize_bundle(data: &[u8]) -> BpResult<Bundle> {
        let json = std::str::from_utf8(data)
            .map_err(|_| BpError::Protocol("Invalid UTF-8 in bundle data".to_string()))?;
        serde_json::from_str(json)
            .map_err(|_| BpError::Protocol("Failed to deserialize bundle".to_string()))
    }
}

#[async_trait]
impl Cla for UdpCla {
    async fn start(&self, config: &TransportConfig) -> BpResult<()> {
        let socket = UdpSocket::bind(&config.local_address).await
            .map_err(|_| BpError::Protocol(format!("Failed to bind to {}", config.local_address)))?;
        
        *self.socket.write().await = Some(socket);
        *self.running.write().await = true;
        
        Ok(())
    }
    
    async fn stop(&self) -> BpResult<()> {
        *self.running.write().await = false;
        *self.socket.write().await = None;
        Ok(())
    }
    
    async fn send(&self, bundle: &Bundle, dest_eid: &Eid) -> BpResult<()> {
        let socket = self.socket.read().await;
        let socket = socket.as_ref()
            .ok_or_else(|| BpError::NotInitialized)?;
        
        let address = dest_eid.as_str().replace("ipn:", "127.0.0.1:");
        let data = Self::serialize_bundle(bundle).await?;
        
        socket.send_to(&data, &address).await
            .map_err(|_| BpError::Protocol("Failed to send bundle".to_string()))?;
        
        Ok(())
    }
    
    async fn receive(&self) -> BpResult<Bundle> {
        let socket = self.socket.read().await;
        let socket = socket.as_ref()
            .ok_or_else(|| BpError::NotInitialized)?;
        
        let mut buf = vec![0u8; 65536];
        let (len, _) = socket.recv_from(&mut buf).await
            .map_err(|_| BpError::Protocol("Failed to receive bundle".to_string()))?;
        
        buf.truncate(len);
        Self::deserialize_bundle(&buf).await
    }
    
    fn is_running(&self) -> bool {
        *self.running.try_read().unwrap_or_else(|_| std::sync::RwLockReadGuard::leak(
            std::sync::RwLock::new(false).read().unwrap()
        ))
    }
    
    fn protocol(&self) -> &str {
        "udp"
    }
}

pub struct ClaManager {
    clas: Arc<RwLock<HashMap<String, Box<dyn Cla>>>>,
}

impl ClaManager {
    pub fn new() -> Self {
        Self {
            clas: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn register_cla(&self, name: String, cla: Box<dyn Cla>) -> BpResult<()> {
        self.clas.write().await.insert(name, cla);
        Ok(())
    }
    
    pub async fn start_cla(&self, name: &str, config: &TransportConfig) -> BpResult<()> {
        let clas = self.clas.read().await;
        let cla = clas.get(name)
            .ok_or_else(|| BpError::NotFound)?;
        
        cla.start(config).await
    }
    
    pub async fn stop_cla(&self, name: &str) -> BpResult<()> {
        let clas = self.clas.read().await;
        let cla = clas.get(name)
            .ok_or_else(|| BpError::NotFound)?;
        
        cla.stop().await
    }
    
    pub async fn send_bundle(&self, bundle: &Bundle, dest_eid: &Eid) -> BpResult<()> {
        let protocol = if dest_eid.as_str().contains("tcp") { "tcp" } else { "udp" };
        
        let clas = self.clas.read().await;
        let cla = clas.values()
            .find(|c| c.protocol() == protocol)
            .ok_or_else(|| BpError::NotFound)?;
        
        cla.send(bundle, dest_eid).await
    }
    
    pub async fn receive_bundle(&self, protocol: &str) -> BpResult<Bundle> {
        let clas = self.clas.read().await;
        let cla = clas.values()
            .find(|c| c.protocol() == protocol)
            .ok_or_else(|| BpError::NotFound)?;
        
        cla.receive().await
    }
    
    pub async fn shutdown(&self) -> BpResult<()> {
        let clas = self.clas.read().await;
        for cla in clas.values() {
            cla.stop().await?;
        }
        Ok(())
    }
} 