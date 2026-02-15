#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::all, clippy::pedantic)]

#[cfg(any(feature = "alloc", feature = "std"))]
extern crate alloc;

#[cfg(not(any(feature = "alloc", feature = "std")))]
extern crate heapless;

use core::mem;
use ed25519_dalek::{Signature, VerifyingKey};
use ed25519_dalek::Verifier;
use zerocopy::byteorder::{I32, LE, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout, Ref, Unaligned};

const MAGIC: [u8; 4] = *b"QDP1";

const PREFIX_LEN: usize = mem::size_of::<QdpPrefix>();
const ALERT_FIXED_LEN: usize = mem::size_of::<QdpAlertFixed>();
const SIGNATURE_LEN: usize = 64;
const ORIGIN_KEY_ID_LEN: usize = 8;
const ALERT_FIXED_END: usize = PREFIX_LEN + ALERT_FIXED_LEN;
#[cfg(not(any(feature = "alloc", feature = "std")))]
const MAX_TLV_VALUE_LEN: usize = 255;

const TLV_HAZARD_NAME: u8 = 0x01;
const TLV_CAP_ID: u8 = 0x02;
const TLV_REGION_CODE: u8 = 0x03;
const TLV_TEXT_SUMMARY: u8 = 0x04;
const TLV_POLYGON: u8 = 0x05;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    BadMagic,
    BadVersion,
    BadHeaderLen,
    BadReserved,
    BadFlagsExt,
    BadSignedTlvLen,
    BadTlv,
    BadSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationError {
    LatitudeOutOfRange,
    LongitudeOutOfRange,
}

#[derive(FromBytes, Unaligned, KnownLayout, Immutable, Copy, Clone)]
#[repr(C, packed)]
struct QdpPrefix {
    magic: [u8; 4],
    version_major: u8,
    version_minor: u8,
    header_len: U16<LE>,
    flags: U16<LE>,
    flags_ext: U16<LE>,
    reserved0: [u8; 3],
    timestamp_s: U64<LE>,
    origin_id: U64<LE>,
    event_root_id: [u8; 16],
    seq: U16<LE>,
    ttl_s: U16<LE>,
    reserved1: U32<LE>,
}

#[derive(FromBytes, Unaligned, KnownLayout, Immutable, Copy, Clone)]
#[repr(C, packed)]
struct QdpAlertFixed {
    hazard_major: u8,
    hazard_minor: u8,
    alert_reserved0: U16<LE>,
    urgency: u8,
    severity: u8,
    certainty: u8,
    response: u8,
    onset_s: U64<LE>,
    expiry_s: U64<LE>,
    event_time_s: U64<LE>,
    epicenter_lat_udeg: I32<LE>,
    epicenter_lon_udeg: I32<LE>,
    radius_10m: U16<LE>,
    signed_tlv_len: U16<LE>,
    alert_reserved1: U16<LE>,
}

#[derive(FromBytes, Unaligned, KnownLayout, Immutable, Copy, Clone)]
#[repr(C, packed)]
struct QdpSignatureBlock {
    origin_key_id: U64<LE>,
    signature: [u8; SIGNATURE_LEN],
}

const _: [(); 55] = [(); mem::size_of::<QdpPrefix>()];
const _: [(); 46] = [(); mem::size_of::<QdpAlertFixed>()];
const _: [(); 72] = [(); mem::size_of::<QdpSignatureBlock>()];

#[derive(Clone, Copy, Debug)]
pub struct Alert<'a> {
    pub version_major: u8,
    pub version_minor: u8,
    pub header_len: u16,
    pub flags: u16,
    pub timestamp_s: u64,
    pub origin_id: u64,
    pub event_root_id: [u8; 16],
    pub seq: u16,
    pub ttl_s: u16,
    pub hazard_major: u8,
    pub hazard_minor: u8,
    pub urgency: u8,
    pub severity: u8,
    pub certainty: u8,
    pub response: u8,
    pub onset_s: u64,
    pub expiry_s: u64,
    pub event_time_s: u64,
    pub epicenter_lat_udeg: i32,
    pub epicenter_lon_udeg: i32,
    pub radius_10m: u16,
    pub signed_tlv: &'a [u8],
    pub origin_key_id: u64,
    pub signature: &'a [u8],
}

#[cfg(any(feature = "alloc", feature = "std"))]
pub type TlvBytes = alloc::vec::Vec<u8>;

#[cfg(not(any(feature = "alloc", feature = "std")))]
pub type TlvBytes = heapless::Vec<u8, MAX_TLV_VALUE_LEN>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tlv {
    HazardName(TlvBytes),
    CapId(TlvBytes),
    RegionCode(u32),
    TextSummary(TlvBytes),
    Polygon(TlvBytes),
    Unknown { tlv_type: u8, value: TlvBytes },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlvRef<'a> {
    pub tlv_type: u8,
    pub value: &'a [u8],
}

pub struct TlvIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Alert<'_> {
    pub const FLAG_PROPAGATE: u16 = 1 << 0;
    pub const FLAG_URGENT: u16 = 1 << 1;
    pub const FLAG_UPDATE: u16 = 1 << 2;
    pub const FLAG_CANCEL: u16 = 1 << 3;
    pub const FLAG_TEST: u16 = 1 << 4;

    #[must_use]
    pub fn get_tlv(&self, idx: usize) -> Option<Tlv> {
        let data = self.signed_tlv;
        let mut pos = 0usize;
        let mut cur = 0usize;

        while pos + 2 <= data.len() {
            let tlv_type = data[pos];
            let tlv_len = data[pos + 1] as usize;
            pos += 2;

            if pos + tlv_len > data.len() {
                return None;
            }

            if cur == idx {
                let value = &data[pos..pos + tlv_len];
                return tlv_from_bytes(tlv_type, value);
            }

            pos += tlv_len;
            cur += 1;
        }

        None
    }

    #[must_use]
    pub fn has_flag(&self, flag: u16) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub fn propagate(&self) -> bool {
        self.has_flag(Self::FLAG_PROPAGATE)
    }

    #[must_use]
    pub fn urgent(&self) -> bool {
        self.has_flag(Self::FLAG_URGENT)
    }

    #[must_use]
    pub fn update(&self) -> bool {
        self.has_flag(Self::FLAG_UPDATE)
    }

    #[must_use]
    pub fn cancel(&self) -> bool {
        self.has_flag(Self::FLAG_CANCEL)
    }

    #[must_use]
    pub fn test(&self) -> bool {
        self.has_flag(Self::FLAG_TEST)
    }

    #[must_use]
    pub fn tlv_iter(&self) -> TlvIter<'_> {
        TlvIter {
            data: self.signed_tlv,
            pos: 0,
        }
    }

    /// Validate TLV framing (type/len/value) for the signed TLV stream.
    ///
    /// # Errors
    /// Returns `ParseError::BadTlv` if the TLV stream is malformed.
    pub fn validate_tlv_framing(&self) -> Result<(), ParseError> {
        for item in self.tlv_iter() {
            item?;
        }
        Ok(())
    }

    /// Validate geographic bounds against the spec ranges.
    ///
    /// # Errors
    /// Returns `ValidationError` if any value falls outside its allowed range.
    pub fn validate_geo(&self) -> Result<(), ValidationError> {
        const LAT_MIN: i32 = -90_000_000;
        const LAT_MAX: i32 = 90_000_000;
        const LON_MIN: i32 = -180_000_000;
        const LON_MAX: i32 = 180_000_000;

        if self.epicenter_lat_udeg < LAT_MIN || self.epicenter_lat_udeg > LAT_MAX {
            return Err(ValidationError::LatitudeOutOfRange);
        }
        if self.epicenter_lon_udeg < LON_MIN || self.epicenter_lon_udeg > LON_MAX {
            return Err(ValidationError::LongitudeOutOfRange);
        }

        Ok(())
    }
}

#[cfg(feature = "std")]
impl Alert<'_> {
    #[must_use]
    pub fn collect_tlvs(&self) -> std::vec::Vec<Tlv> {
        let mut out = std::vec::Vec::new();
        let data = self.signed_tlv;
        let mut pos = 0usize;

        while pos + 2 <= data.len() {
            let tlv_type = data[pos];
            let tlv_len = data[pos + 1] as usize;
            pos += 2;

            if pos + tlv_len > data.len() {
                break;
            }

            if let Some(tlv) = tlv_from_bytes(tlv_type, &data[pos..pos + tlv_len]) {
                out.push(tlv);
            }

            pos += tlv_len;
        }

        out
    }

    #[must_use]
    pub fn get_tlv_utf8(&self, idx: usize) -> Option<std::string::String> {
        match self.get_tlv(idx)? {
            Tlv::HazardName(bytes)
            | Tlv::CapId(bytes)
            | Tlv::TextSummary(bytes)
            | Tlv::Polygon(bytes)
            | Tlv::Unknown { value: bytes, .. } => std::string::String::from_utf8(bytes).ok(),
            Tlv::RegionCode(_) => None,
        }
    }
}

impl<'a> TlvIter<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<TlvRef<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }
        if self.pos + 2 > self.data.len() {
            self.pos = self.data.len();
            return Some(Err(ParseError::BadTlv));
        }

        let tlv_type = self.data[self.pos];
        let tlv_len = self.data[self.pos + 1] as usize;
        self.pos += 2;

        if self.pos + tlv_len > self.data.len() {
            self.pos = self.data.len();
            return Some(Err(ParseError::BadTlv));
        }

        let value = &self.data[self.pos..self.pos + tlv_len];
        self.pos += tlv_len;

        Some(Ok(TlvRef { tlv_type, value }))
    }
}

impl TlvRef<'_> {
    #[must_use]
    pub fn to_tlv(&self) -> Option<Tlv> {
        tlv_from_bytes(self.tlv_type, self.value)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
pub struct TlvBuilder {
    data: alloc::vec::Vec<u8>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TlvBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self { data: alloc::vec::Vec::new() }
    }

    #[must_use]
    pub fn into_bytes(self) -> alloc::vec::Vec<u8> {
        self.data
    }

    #[must_use]
    pub fn push(&mut self, tlv_type: u8, value: &[u8]) -> bool {
        let Ok(len) = u8::try_from(value.len()) else {
            return false;
        };
        self.data.push(tlv_type);
        self.data.push(len);
        self.data.extend_from_slice(value);
        true
    }

    #[must_use]
    pub fn push_region_code(&mut self, code: u32) -> bool {
        self.push(TLV_REGION_CODE, &code.to_le_bytes())
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl Default for TlvBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an ALERT packet from the provided byte slice.
///
/// # Errors
/// Returns `ParseError` when the packet is malformed, truncated, or violates
/// required reserved-field or length rules.
pub fn parse_alert_unchecked(bytes: &[u8]) -> Result<Alert<'_>, ParseError> {
    if bytes.len() < PREFIX_LEN + ALERT_FIXED_LEN + ORIGIN_KEY_ID_LEN + SIGNATURE_LEN {
        return Err(ParseError::TooShort);
    }

    let (prefix, _) = Ref::<_, QdpPrefix>::from_prefix(bytes).map_err(|_| ParseError::TooShort)?;

    if prefix.magic != MAGIC {
        return Err(ParseError::BadMagic);
    }

    let version_major = prefix.version_major;
    let version_minor = prefix.version_minor;
    if version_major == 0 {
        return Err(ParseError::BadVersion);
    }

    let header_len = prefix.header_len.get();
    if header_len as usize > bytes.len() {
        return Err(ParseError::BadHeaderLen);
    }

    let flags = prefix.flags.get();
    if prefix.flags_ext.get() != 0 {
        return Err(ParseError::BadFlagsExt);
    }

    if prefix.reserved0 != [0, 0, 0] {
        return Err(ParseError::BadReserved);
    }

    let timestamp_s = prefix.timestamp_s.get();
    let origin_id = prefix.origin_id.get();
    let event_root_id = prefix.event_root_id;
    let seq = prefix.seq.get();
    let ttl_s = prefix.ttl_s.get();

    if prefix.reserved1.get() != 0 {
        return Err(ParseError::BadReserved);
    }

    let (fixed, _) = Ref::<_, QdpAlertFixed>::from_prefix(&bytes[PREFIX_LEN..])
        .map_err(|_| ParseError::TooShort)?;

    let hazard_major = fixed.hazard_major;
    let hazard_minor = fixed.hazard_minor;
    if fixed.alert_reserved0.get() != 0 {
        return Err(ParseError::BadReserved);
    }

    let urgency = fixed.urgency;
    let severity = fixed.severity;
    let certainty = fixed.certainty;
    let response = fixed.response;
    let onset_s = fixed.onset_s.get();
    let expiry_s = fixed.expiry_s.get();
    let event_time_s = fixed.event_time_s.get();
    let epicenter_lat_udeg = fixed.epicenter_lat_udeg.get();
    let epicenter_lon_udeg = fixed.epicenter_lon_udeg.get();
    let radius_10m = fixed.radius_10m.get();
    let signed_tlv_len = fixed.signed_tlv_len.get() as usize;
    if fixed.alert_reserved1.get() != 0 {
        return Err(ParseError::BadReserved);
    }

    let signed_tlv_start = ALERT_FIXED_END;
    let signed_tlv_end = signed_tlv_start + signed_tlv_len;
    let origin_key_id_start = signed_tlv_end;
    let signature_start = origin_key_id_start + ORIGIN_KEY_ID_LEN;
    let signature_end = signature_start + SIGNATURE_LEN;

    if signature_end > bytes.len() {
        return Err(ParseError::BadSignedTlvLen);
    }

    if header_len as usize != signature_end {
        return Err(ParseError::BadHeaderLen);
    }

    let (sig, _) = Ref::<_, QdpSignatureBlock>::from_prefix(&bytes[origin_key_id_start..])
        .map_err(|_| ParseError::BadSignedTlvLen)?;
    let origin_key_id = sig.origin_key_id.get();
    let signed_tlv = &bytes[signed_tlv_start..signed_tlv_end];
    let signature = &bytes[signature_start..signature_end];

    Ok(Alert {
        version_major,
        version_minor,
        header_len,
        flags,
        timestamp_s,
        origin_id,
        event_root_id,
        seq,
        ttl_s,
        hazard_major,
        hazard_minor,
        urgency,
        severity,
        certainty,
        response,
        onset_s,
        expiry_s,
        event_time_s,
        epicenter_lat_udeg,
        epicenter_lon_udeg,
        radius_10m,
        signed_tlv,
        origin_key_id,
        signature,
    })
}

/// Parse and verify an ALERT packet using Ed25519.
///
/// # Errors
/// Returns `ParseError` when parsing fails or the signature is invalid.
pub fn parse_alert_verified<'a>(
    bytes: &'a [u8],
    public_key: &[u8; 32],
) -> Result<Alert<'a>, ParseError> {
    let alert = parse_alert_unchecked(bytes)?;
    verify_alert_signature(bytes, &alert, public_key)?;
    Ok(alert)
}

#[cfg(any(feature = "alloc", feature = "std"))]
fn tlv_from_bytes(tlv_type: u8, value: &[u8]) -> Option<Tlv> {
    match tlv_type {
        TLV_HAZARD_NAME => Some(Tlv::HazardName(tlv_bytes(value))),
        TLV_CAP_ID => Some(Tlv::CapId(tlv_bytes(value))),
        TLV_TEXT_SUMMARY => Some(Tlv::TextSummary(tlv_bytes(value))),
        TLV_POLYGON => Some(Tlv::Polygon(tlv_bytes(value))),
        TLV_REGION_CODE => {
            if value.len() == 4 {
                Some(Tlv::RegionCode(u32::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                ])))
            } else {
                None
            }
        }
        _ => Some(Tlv::Unknown {
            tlv_type,
            value: tlv_bytes(value),
        }),
    }
}

#[cfg(not(any(feature = "alloc", feature = "std")))]
fn tlv_from_bytes(tlv_type: u8, value: &[u8]) -> Option<Tlv> {
    match tlv_type {
        TLV_HAZARD_NAME => tlv_bytes(value).map(Tlv::HazardName),
        TLV_CAP_ID => tlv_bytes(value).map(Tlv::CapId),
        TLV_TEXT_SUMMARY => tlv_bytes(value).map(Tlv::TextSummary),
        TLV_POLYGON => tlv_bytes(value).map(Tlv::Polygon),
        TLV_REGION_CODE => {
            if value.len() == 4 {
                Some(Tlv::RegionCode(u32::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                ])))
            } else {
                None
            }
        }
        _ => tlv_bytes(value).map(|bytes| Tlv::Unknown {
            tlv_type,
            value: bytes,
        }),
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
fn tlv_bytes(value: &[u8]) -> TlvBytes {
    value.to_vec()
}

#[cfg(not(any(feature = "alloc", feature = "std")))]
fn tlv_bytes(value: &[u8]) -> Option<TlvBytes> {
    if value.len() > MAX_TLV_VALUE_LEN {
        return None;
    }
    let mut out: TlvBytes = heapless::Vec::new();
    if out.extend_from_slice(value).is_err() {
        return None;
    }
    Some(out)
}

fn verify_alert_signature(
    bytes: &[u8],
    alert: &Alert<'_>,
    public_key: &[u8; 32],
) -> Result<(), ParseError> {
    let header_len = usize::from(alert.header_len);
    if header_len < SIGNATURE_LEN {
        return Err(ParseError::BadSignature);
    }
    if header_len > bytes.len() {
        return Err(ParseError::BadSignature);
    }

    let signature_start = header_len - SIGNATURE_LEN;
    let signed_region = &bytes[..signature_start];
    let signature_bytes = &bytes[signature_start..header_len];

    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| ParseError::BadSignature)?;
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| ParseError::BadSignature)?;

    verifying_key
        .verify(signed_region, &signature)
        .map_err(|_| ParseError::BadSignature)
}

#[cfg(feature = "c-interop")]
#[repr(C)]
pub struct QdpAlertRaw {
    pub buffer_ptr: *const u8,
    pub buffer_len: usize,
    pub header_len: u16,
    pub flags: u16,
    pub timestamp_s: u64,
    pub origin_id: u64,
    pub event_root_id: [u8; 16],
    pub seq: u16,
    pub ttl_s: u16,
    pub hazard_major: u8,
    pub hazard_minor: u8,
    pub urgency: u8,
    pub severity: u8,
    pub certainty: u8,
    pub response: u8,
    pub onset_s: u64,
    pub expiry_s: u64,
    pub event_time_s: u64,
    pub epicenter_lat_udeg: i32,
    pub epicenter_lon_udeg: i32,
    pub radius_10m: u16,
    pub signed_tlv_ptr: *const u8,
    pub signed_tlv_len: u16,
    pub origin_key_id: u64,
    pub signature_ptr: *const u8,
    pub signature_len: usize,
}

#[cfg(feature = "c-interop")]
#[unsafe(no_mangle)]
/// # Safety
/// Caller must pass valid pointers: `buf_ptr` must reference `buf_len` readable bytes
/// and `out_ptr` must be writable for `QdpAlertRaw`.
pub unsafe extern "C" fn qdp_parse_alert_raw(
    buf_ptr: *const u8,
    buf_len: usize,
    out_ptr: *mut QdpAlertRaw,
) -> bool {
    if buf_ptr.is_null() || out_ptr.is_null() {
        return false;
    }

    let bytes = unsafe { core::slice::from_raw_parts(buf_ptr, buf_len) };
    let Ok(alert) = parse_alert_unchecked(bytes) else {
        return false;
    };

    let signed_tlv_ptr = if alert.signed_tlv.is_empty() {
        core::ptr::null()
    } else {
        alert.signed_tlv.as_ptr()
    };

    let signature_ptr = if alert.signature.is_empty() {
        core::ptr::null()
    } else {
        alert.signature.as_ptr()
    };

    let Ok(signed_tlv_len) = u16::try_from(alert.signed_tlv.len()) else {
        return false;
    };

    let out = QdpAlertRaw {
        buffer_ptr: buf_ptr,
        buffer_len: buf_len,
        header_len: alert.header_len,
        flags: alert.flags,
        timestamp_s: alert.timestamp_s,
        origin_id: alert.origin_id,
        event_root_id: alert.event_root_id,
        seq: alert.seq,
        ttl_s: alert.ttl_s,
        hazard_major: alert.hazard_major,
        hazard_minor: alert.hazard_minor,
        urgency: alert.urgency,
        severity: alert.severity,
        certainty: alert.certainty,
        response: alert.response,
        onset_s: alert.onset_s,
        expiry_s: alert.expiry_s,
        event_time_s: alert.event_time_s,
        epicenter_lat_udeg: alert.epicenter_lat_udeg,
        epicenter_lon_udeg: alert.epicenter_lon_udeg,
        radius_10m: alert.radius_10m,
        signed_tlv_ptr,
        signed_tlv_len,
        origin_key_id: alert.origin_key_id,
        signature_ptr,
        signature_len: alert.signature.len(),
    };

    unsafe {
        core::ptr::write(out_ptr, out);
    }
    true
}

#[cfg(feature = "c-interop")]
#[unsafe(no_mangle)]
/// # Safety
/// This function is ABI-safe and has no side effects, but remains `unsafe`
/// to match FFI usage conventions.
pub unsafe extern "C" fn qdp_alert_raw_layout_ok() -> bool {
    core::mem::size_of::<QdpAlertRaw>() > 0
}
