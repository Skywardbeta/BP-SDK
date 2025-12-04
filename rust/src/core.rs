use crate::{
    error::{BpError, BpResult},
    ffi,
    types::{Bundle, Custody, Eid, Statistics},
};
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use std::{
    collections::HashMap,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::timeout;

/// Thread-safe Bundle Protocol SDK context
#[derive(Debug)]
pub struct BpSdk {
    inner: Arc<BpSdkInner>,
}

#[derive(Debug)]
struct BpSdkInner {
    node_eid: Eid,
    config_file: Option<String>,
    initialized: AtomicBool,
    endpoints: RwLock<HashMap<Eid, Arc<Endpoint>>>,
    statistics: Mutex<Statistics>,
}

/// Bundle Protocol endpoint for sending/receiving
#[derive(Debug)]
pub struct Endpoint {
    eid: Eid,
    sap: Mutex<Option<*mut ffi::BpSAP>>,
}

impl BpSdk {
    /// Create a new Bundle Protocol SDK instance
    pub fn new(node_eid: Eid, config_file: Option<String>) -> BpResult<Self> {
        Ok(Self {
            inner: Arc::new(BpSdkInner {
                node_eid,
                config_file,
                initialized: AtomicBool::new(false),
                endpoints: RwLock::new(HashMap::new()),
                statistics: Mutex::new(Statistics::new()),
            })
        })
    }

    /// Initialize the Bundle Protocol SDK
    pub async fn init(&self) -> BpResult<()> {
        if self.inner.initialized.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let result = unsafe { ffi::bp_attach() };
        if result != 0 {
            self.inner.initialized.store(false, Ordering::Release);
            return Err(BpError::from(result));
        }
        Ok(())
    }

    /// Shutdown the Bundle Protocol SDK
    pub async fn shutdown(&self) -> BpResult<()> {
        if !self.inner.initialized.swap(false, Ordering::AcqRel) {
            return Err(BpError::NotInitialized);
        }

        let endpoints = self.inner.endpoints.read().clone();
        for endpoint in endpoints.values() {
            endpoint.close().await?;
        }
        self.inner.endpoints.write().clear();

        ffi::from_c_result(unsafe { ffi::bp_detach() })
    }

    /// Check if the SDK is initialized
    pub fn is_initialized(&self) -> bool {
        self.inner.initialized.load(Ordering::Acquire)
    }

    /// Create a new endpoint
    pub async fn create_endpoint(&self, eid: Eid) -> BpResult<Arc<Endpoint>> {
        if !self.is_initialized() {
            return Err(BpError::NotInitialized);
        }

        let endpoint = Arc::new(Endpoint::new(eid.clone())?);
        
        let mut endpoints = self.inner.endpoints.write();
        if endpoints.contains_key(&eid) {
            return Err(BpError::Duplicate);
        }
        
        endpoints.insert(eid, endpoint.clone());
        Ok(endpoint)
    }

    /// Get an existing endpoint
    pub fn get_endpoint(&self, eid: &Eid) -> Option<Arc<Endpoint>> {
        self.inner.endpoints.read().get(eid).cloned()
    }

    /// Remove an endpoint
    pub async fn remove_endpoint(&self, eid: &Eid) -> BpResult<()> {
        if let Some(endpoint) = self.inner.endpoints.write().remove(eid) {
            endpoint.close().await?;
        }
        Ok(())
    }

    /// Send a bundle
    pub async fn send(&self, bundle: Bundle) -> BpResult<()> {
        if !self.is_initialized() {
            return Err(BpError::NotInitialized);
        }

        let source_eid_c = ffi::to_c_string(bundle.source_eid.as_str())?;
        let dest_eid_c = ffi::to_c_string(bundle.dest_eid.as_str())?;
        let report_to_c = bundle.report_to_eid
            .as_ref()
            .map(|eid| ffi::to_c_string(eid.as_str()))
            .transpose()?;

        let mut sap: *mut ffi::BpSAP = ptr::null_mut();
        ffi::from_c_result(unsafe { ffi::bp_open(source_eid_c.as_ptr() as *mut _, &mut sap) })?;

        let _guard = SapGuard(sap);

        let sdr = unsafe { ffi::bp_get_sdr() };
        if sdr.is_null() {
            return Err(BpError::Protocol("Failed to get SDR".to_string()));
        }

        let payload_obj = unsafe { ffi::sdr_malloc(sdr, bundle.payload.len()) };
        if payload_obj == 0 {
            return Err(BpError::Memory);
        }

        unsafe {
            ffi::sdr_begin_xn(sdr);
            let result = ffi::sdr_write(sdr, payload_obj, bundle.payload.as_ptr() as *const _, bundle.payload.len());
            if result < 0 {
                ffi::sdr_cancel_xn(sdr);
                return Err(BpError::Protocol("Failed to write payload".to_string()));
            }
            ffi::sdr_end_xn(sdr);
        }

        let zco = unsafe {
            ffi::ion_create_zco(1, payload_obj, 0, bundle.payload.len(), bundle.priority as i32, 0, 1, ptr::null_mut())
        };

        if zco == 0 {
            return Err(BpError::Memory);
        }

        let custody_switch = match bundle.custody {
            Custody::None => ffi::BpCustodySwitch::NoCustodyRequested,
            Custody::Optional => ffi::BpCustodySwitch::SourceCustodyOptional,
            Custody::Required => ffi::BpCustodySwitch::SourceCustodyRequired,
        };

        let mut new_bundle: u32 = 0;
        let result = unsafe {
            ffi::bp_send(
                sap,
                dest_eid_c.as_ptr() as *mut _,
                report_to_c.as_ref().map(|c| c.as_ptr() as *mut _).unwrap_or(ptr::null_mut()),
                bundle.ttl.as_secs() as i32,
                bundle.priority as i32,
                custody_switch,
                0, 0,
                ptr::null_mut(),
                zco,
                &mut new_bundle,
            )
        };

        if result != 1 {
            return Err(BpError::Protocol("Bundle send failed".to_string()));
        }

        let mut stats = self.inner.statistics.lock();
        stats.bundles_sent += 1;
        stats.bytes_sent += bundle.payload.len() as u64;

        Ok(())
    }

    /// Get current statistics
    pub fn statistics(&self) -> Statistics {
        self.inner.statistics.lock().clone()
    }

    /// Reset statistics
    pub fn reset_statistics(&self) {
        self.inner.statistics.lock().reset();
    }
}

impl Endpoint {
    fn new(eid: Eid) -> BpResult<Self> {
        Ok(Self {
            eid,
            sap: Mutex::new(None),
        })
    }

    /// Get the endpoint identifier
    pub fn eid(&self) -> &Eid {
        &self.eid
    }

    /// Open the endpoint for communication
    async fn open(&self) -> BpResult<*mut ffi::BpSAP> {
        let mut sap_guard = self.sap.lock();
        
        if let Some(sap) = *sap_guard {
            return Ok(sap);
        }

        let eid_c = ffi::to_c_string(self.eid.as_str())?;
        let mut sap: *mut ffi::BpSAP = ptr::null_mut();
        
        ffi::from_c_result(unsafe { ffi::bp_open(eid_c.as_ptr() as *mut _, &mut sap) })?;
        
        *sap_guard = Some(sap);
        Ok(sap)
    }

    /// Close the endpoint
    async fn close(&self) -> BpResult<()> {
        if let Some(sap) = self.sap.lock().take() {
            ffi::from_c_result(unsafe { ffi::bp_close(sap) })?;
        }
        Ok(())
    }

    /// Receive a bundle with timeout
    pub async fn receive(&self, timeout_duration: Option<Duration>) -> BpResult<Bundle> {
        let sap = self.open().await?;

        let receive_future = async {
            let mut delivery = ffi::BpDelivery {
                result: 0,
                bundle_source_eid: ptr::null_mut(),
                bundle_creation_time: ffi::BpTimestamp { msec: 0, count: 0 },
                time_to_live: 0,
                adu: 0,
            };

            let timeout_secs = timeout_duration.map(|d| d.as_secs() as i32).unwrap_or(-1);

            ffi::from_c_result(unsafe { ffi::bp_receive(sap, &mut delivery, timeout_secs) })?;

            if delivery.result != 1 {
                return if delivery.result == 3 {
                    Err(BpError::Timeout)
                } else {
                    Err(BpError::Protocol("No payload present".to_string()))
                };
            }

            let source_eid = unsafe { ffi::from_c_string(delivery.bundle_source_eid) }
                .ok_or_else(|| BpError::Protocol("Invalid source EID".to_string()))?;
            let source_eid = Eid::new(source_eid)?;

            let sdr = unsafe { ffi::bp_get_sdr() };
            let payload_len = unsafe { ffi::zco_source_data_length(sdr, delivery.adu) };
            
            let mut payload = vec![0u8; payload_len];
            if payload_len > 0 {
                let mut reader = [0u8; 64];
                unsafe {
                    ffi::zco_start_receiving(delivery.adu, reader.as_mut_ptr() as *mut _);
                    ffi::zco_receive_source(sdr, reader.as_mut_ptr() as *mut _, payload_len, payload.as_mut_ptr() as *mut _);
                }
            }

            unsafe { ffi::bp_release_delivery(&mut delivery, 1); }

            Ok(Bundle::new(source_eid, self.eid.clone(), Bytes::from(payload)))
        };

        match timeout_duration {
            Some(duration) => timeout(duration, receive_future).await.map_err(|_| BpError::Timeout)?,
            None => receive_future.await,
        }
    }
}

/// RAII guard for closing SAP
struct SapGuard(*mut ffi::BpSAP);

impl Drop for SapGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ffi::bp_close(self.0); }
        }
    }
}

unsafe impl Send for Endpoint {}
unsafe impl Sync for Endpoint {} 