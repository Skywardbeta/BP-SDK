use libc::{c_char, c_int, c_uint, c_void, size_t};
use std::ffi::{CStr, CString};

/// FFI bindings to ION-DTN C library
#[repr(C)]
pub struct BpSAP {
    _private: [u8; 0],
}

#[repr(C)]
pub struct BpDelivery {
    pub result: c_int,
    pub bundle_source_eid: *mut c_char,
    pub bundle_creation_time: BpTimestamp,
    pub time_to_live: c_uint,
    pub adu: c_uint,
}

#[repr(C)]
pub struct BpTimestamp {
    pub msec: u64,
    pub count: u32,
}

#[repr(C)]
pub enum BpCustodySwitch {
    NoCustodyRequested = 0,
    SourceCustodyOptional = 1,
    SourceCustodyRequired = 2,
}

// ION-DTN Bundle Protocol functions
extern "C" {
    pub fn bp_attach() -> c_int;
    pub fn bp_detach() -> c_int;
    pub fn bp_open(eid: *mut c_char, sap: *mut *mut BpSAP) -> c_int;
    pub fn bp_close(sap: *mut BpSAP) -> c_int;
    
    pub fn bp_send(
        sap: *mut BpSAP,
        dest_eid: *mut c_char,
        report_to_eid: *mut c_char,
        ttl: c_int,
        priority: c_int,
        custody_switch: BpCustodySwitch,
        srr_flags: u8,
        ack_requested: c_int,
        ancillary_data: *mut c_void,
        adu: c_uint,
        new_bundle: *mut c_uint,
    ) -> c_int;
    
    pub fn bp_receive(
        sap: *mut BpSAP,
        delivery: *mut BpDelivery,
        timeout: c_int,
    ) -> c_int;
    
    pub fn bp_release_delivery(delivery: *mut BpDelivery, release_adu: c_int) -> c_int;
    
    // ION SDR functions
    pub fn bp_get_sdr() -> *mut c_void;
    pub fn sdr_malloc(sdr: *mut c_void, size: size_t) -> c_uint;
    pub fn sdr_write(sdr: *mut c_void, object: c_uint, data: *const c_void, size: size_t) -> c_int;
    pub fn sdr_begin_xn(sdr: *mut c_void) -> c_int;
    pub fn sdr_end_xn(sdr: *mut c_void) -> c_int;
    pub fn sdr_cancel_xn(sdr: *mut c_void) -> c_int;
    
    // ION ZCO functions
    pub fn ion_create_zco(
        source_type: c_int,
        source_data: c_uint,
        offset: size_t,
        length: size_t,
        priority: c_int,
        ordinal: c_int,
        direction: c_int,
        ancillary_data: *mut c_void,
    ) -> c_uint;
    
    pub fn zco_start_receiving(zco: c_uint, reader: *mut c_void) -> c_int;
    pub fn zco_receive_source(
        sdr: *mut c_void,
        reader: *mut c_void,
        length: size_t,
        buffer: *mut c_char,
    ) -> c_int;
    pub fn zco_source_data_length(sdr: *mut c_void, zco: c_uint) -> size_t;
    
    // ION Admin functions
    pub fn add_plan(dest_eid: *mut c_char, nominal_rate: c_uint) -> c_int;
    pub fn remove_plan(dest_eid: *mut c_char) -> c_int;
    pub fn add_scheme(
        scheme_name: *mut c_char,
        forwarder_cmd: *mut c_char,
        admin_cmd: *mut c_char,
    ) -> c_int;
    pub fn remove_scheme(scheme_name: *mut c_char) -> c_int;
}

/// Safe wrapper for creating C strings
pub fn to_c_string(s: &str) -> Result<CString, crate::error::BpError> {
    CString::new(s).map_err(|_| crate::error::BpError::Ffi("Invalid string contains null bytes".to_string()))
}

/// Safe wrapper for converting C strings to Rust strings
pub unsafe fn from_c_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_owned())
    }
}

/// Convert C result code to Rust Result
pub fn from_c_result(code: c_int) -> crate::error::BpResult<()> {
    if code == 0 { Ok(()) } else { Err(crate::error::BpError::from(code)) }
} 