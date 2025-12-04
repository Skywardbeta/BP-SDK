use crate::{
    error::{BpError, BpResult},
    types::TransportConfig,
};
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    fmt::Debug,
    net::SocketAddr,
    sync::Arc,
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};

/// Convergence Layer Adapter trait for implementing transport protocols
#[async_trait]
pub trait Cla: Send + Sync + Debug {
    /// Get the protocol name
    fn protocol(&self) -> &str;
    
    /// Get the local address
    fn local_address(&self) -> &str;
    
    /// Get maximum payload size
    fn max_payload_size(&self) -> usize;
    
    /// Start the CLA
    async fn start(&self) -> BpResult<()>;
    
    /// Stop the CLA
    async fn stop(&self) -> BpResult<()>;
    
    /// Send data to a remote address
    async fn send(&self, dest_addr: &str, data: Bytes) -> BpResult<()>;
    
    /// Set up bundle reception callback
    fn set_receive_callback(&self, callback: Arc<dyn Fn(Bytes, String) + Send + Sync>);
}

/// CLA manager for registering and managing transport protocols
#[derive(Debug)]
pub struct ClaManager {
    clas: RwLock<HashMap<String, Arc<dyn Cla>>>,
}

impl ClaManager {
    pub fn new() -> Self {
        Self {
            clas: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new CLA
    pub fn register(&self, cla: Arc<dyn Cla>) -> BpResult<()> {
        let mut clas = self.clas.write();
        let protocol = cla.protocol().to_string();
        
        if clas.contains_key(&protocol) {
            return Err(BpError::Duplicate);
        }
        
        clas.insert(protocol, cla);
        Ok(())
    }

    /// Unregister a CLA
    pub fn unregister(&self, protocol: &str) -> BpResult<()> {
        self.clas.write().remove(protocol).ok_or(BpError::NotFound)?;
        Ok(())
    }

    /// Get a CLA by protocol name
    pub fn get(&self, protocol: &str) -> Option<Arc<dyn Cla>> {
        self.clas.read().get(protocol).cloned()
    }

    /// List all registered protocols
    pub fn list_protocols(&self) -> Vec<String> {
        self.clas.read().keys().cloned().collect()
    }

    /// Send data using a specific protocol
    pub async fn send(&self, protocol: &str, dest_addr: &str, data: Bytes) -> BpResult<()> {
        let cla = self.get(protocol).ok_or(BpError::NotFound)?;
        cla.send(dest_addr, data).await
    }

    /// Start all CLAs
    pub async fn start_all(&self) -> BpResult<()> {
        let clas = self.clas.read().clone();
        for cla in clas.values() {
            cla.start().await?;
        }
        Ok(())
    }

    /// Stop all CLAs
    pub async fn stop_all(&self) -> BpResult<()> {
        let clas = self.clas.read().clone();
        for cla in clas.values() {
            cla.stop().await?;
        }
        Ok(())
    }

    /// Create and register a TCP CLA
    pub async fn create_tcp_cla(&self, local_address: &str) -> BpResult<Arc<dyn Cla>> {
        let config = TransportConfig::tcp(local_address);
        let cla = Arc::new(TcpCla::new(config)?) as Arc<dyn Cla>;
        self.register(cla.clone())?;
        Ok(cla)
    }

    /// Create and register a UDP CLA
    pub async fn create_udp_cla(&self, local_address: &str) -> BpResult<Arc<dyn Cla>> {
        let config = TransportConfig::udp(local_address);
        let cla = Arc::new(UdpCla::new(config)?) as Arc<dyn Cla>;
        self.register(cla.clone())?;
        Ok(cla)
    }
}

impl Default for ClaManager {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP-based Convergence Layer Adapter
pub struct TcpCla {
    config: TransportConfig,
    listener: RwLock<Option<TcpListener>>,
    receive_callback: RwLock<Option<Arc<dyn Fn(Bytes, String) + Send + Sync>>>,
    shutdown_tx: RwLock<Option<mpsc::Sender<()>>>,
}

impl Debug for TcpCla {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpCla")
            .field("config", &self.config)
            .field("listener", &self.listener)
            .field("receive_callback", &"<callback>")
            .field("shutdown_tx", &self.shutdown_tx)
            .finish()
    }
}

impl TcpCla {
    pub fn new(config: TransportConfig) -> BpResult<Self> {
        if config.protocol != "tcp" {
            return Err(BpError::InvalidArgs);
        }

        Ok(Self {
            config,
            listener: RwLock::new(None),
            receive_callback: RwLock::new(None),
            shutdown_tx: RwLock::new(None),
        })
    }

    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        callback: Arc<dyn Fn(Bytes, String) + Send + Sync>,
    ) {
        use tokio::io::AsyncReadExt;
        
        let mut stream = stream;
        let mut buffer = vec![0u8; 65536];
        
        while let Ok(n) = stream.read(&mut buffer).await {
            if n == 0 { break; }
            let data = Bytes::from(buffer[..n].to_vec());
            callback(data, peer_addr.to_string());
        }
    }

    async fn accept_loop(
        listener: TcpListener,
        callback: Arc<dyn Fn(Bytes, String) + Send + Sync>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    if let Ok((stream, peer_addr)) = result {
                        let callback_clone = callback.clone();
                        tokio::spawn(Self::handle_connection(stream, peer_addr, callback_clone));
                    } else {
                        break;
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    }
}

#[async_trait]
impl Cla for TcpCla {
    fn protocol(&self) -> &str {
        &self.config.protocol
    }

    fn local_address(&self) -> &str {
        &self.config.local_address
    }

    fn max_payload_size(&self) -> usize {
        self.config.max_payload_size
    }

    async fn start(&self) -> BpResult<()> {
        let addr: SocketAddr = self.config.local_address
            .parse()
            .map_err(|_| BpError::InvalidArgs)?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|_| BpError::Protocol("Failed to bind TCP listener".to_string()))?;

        *self.listener.write() = Some(listener);

        let callback = self.receive_callback.read().as_ref().cloned();
        if let Some(callback) = callback {
            let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
            
            *self.shutdown_tx.write() = Some(shutdown_tx);
            
            let new_listener = TcpListener::bind(addr)
                .await
                .map_err(|_| BpError::Protocol("Failed to rebind listener".to_string()))?;
            
            tokio::spawn(Self::accept_loop(new_listener, callback, shutdown_rx));
        }

        Ok(())
    }

    async fn stop(&self) -> BpResult<()> {
        let shutdown_tx = self.shutdown_tx.write().take();
        if let Some(tx) = shutdown_tx {
            let _ = tx.send(()).await;
        }
        
        *self.listener.write() = None;
        Ok(())
    }

    async fn send(&self, dest_addr: &str, data: Bytes) -> BpResult<()> {
        use tokio::io::AsyncWriteExt;
        
        let addr: SocketAddr = dest_addr.parse().map_err(|_| BpError::InvalidArgs)?;

        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|_| BpError::Protocol("Failed to connect".to_string()))?;

        stream.write_all(&data)
            .await
            .map_err(|_| BpError::Protocol("Failed to send data".to_string()))?;

        Ok(())
    }

    fn set_receive_callback(&self, callback: Arc<dyn Fn(Bytes, String) + Send + Sync>) {
        *self.receive_callback.write() = Some(callback);
    }
}

/// UDP-based Convergence Layer Adapter
pub struct UdpCla {
    config: TransportConfig,
    socket: RwLock<Option<Arc<UdpSocket>>>,
    receive_callback: RwLock<Option<Arc<dyn Fn(Bytes, String) + Send + Sync>>>,
    shutdown_tx: RwLock<Option<mpsc::Sender<()>>>,
}

impl Debug for UdpCla {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpCla")
            .field("config", &self.config)
            .field("socket", &self.socket)
            .field("receive_callback", &"<callback>")
            .field("shutdown_tx", &self.shutdown_tx)
            .finish()
    }
}

impl UdpCla {
    pub fn new(config: TransportConfig) -> BpResult<Self> {
        if config.protocol != "udp" {
            return Err(BpError::InvalidArgs);
        }

        Ok(Self {
            config,
            socket: RwLock::new(None),
            receive_callback: RwLock::new(None),
            shutdown_tx: RwLock::new(None),
        })
    }

    async fn receive_loop(
        socket: Arc<UdpSocket>,
        callback: Arc<dyn Fn(Bytes, String) + Send + Sync>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let mut buffer = vec![0u8; 65536];
        
        loop {
            tokio::select! {
                result = socket.recv_from(&mut buffer) => {
                    if let Ok((len, peer_addr)) = result {
                        let data = Bytes::from(buffer[..len].to_vec());
                        callback(data, peer_addr.to_string());
                    } else {
                        break;
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    }
}

#[async_trait]
impl Cla for UdpCla {
    fn protocol(&self) -> &str {
        &self.config.protocol
    }

    fn local_address(&self) -> &str {
        &self.config.local_address
    }

    fn max_payload_size(&self) -> usize {
        self.config.max_payload_size
    }

    async fn start(&self) -> BpResult<()> {
        let addr: SocketAddr = self.config.local_address
            .parse()
            .map_err(|_| BpError::InvalidArgs)?;

        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|_| BpError::Protocol("Failed to bind UDP socket".to_string()))?;

        let socket = Arc::new(socket);
        *self.socket.write() = Some(socket.clone());

        let callback = self.receive_callback.read().as_ref().cloned();
        if let Some(callback) = callback {
            let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
            
            *self.shutdown_tx.write() = Some(shutdown_tx);
            
            tokio::spawn(Self::receive_loop(socket, callback, shutdown_rx));
        }

        Ok(())
    }

    async fn stop(&self) -> BpResult<()> {
        let shutdown_tx = self.shutdown_tx.write().take();
        if let Some(tx) = shutdown_tx {
            let _ = tx.send(()).await;
        }
        
        *self.socket.write() = None;
        Ok(())
    }

    async fn send(&self, dest_addr: &str, data: Bytes) -> BpResult<()> {
        let socket = self.socket.read()
            .as_ref()
            .ok_or(BpError::NotInitialized)?
            .clone();

        let addr: SocketAddr = dest_addr.parse().map_err(|_| BpError::InvalidArgs)?;

        socket.send_to(&data, addr)
            .await
            .map_err(|_| BpError::Protocol("Failed to send UDP packet".to_string()))?;

        Ok(())
    }

    fn set_receive_callback(&self, callback: Arc<dyn Fn(Bytes, String) + Send + Sync>) {
        *self.receive_callback.write() = Some(callback);
    }
} 