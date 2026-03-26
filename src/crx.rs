use std::ops::Range;

use crate::types::OpenPackError;

pub(crate) fn crx_zip_payload_range(bytes: &[u8]) -> Result<Range<usize>, OpenPackError> {
    if bytes.len() < 12 {
        return Err(OpenPackError::InvalidArchive("CRX header too short".into()));
    }

    if &bytes[0..4] != b"Cr24" {
        return Err(OpenPackError::InvalidArchive("not a CRX file".into()));
    }

    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != 2 && version != 3 {
        return Err(OpenPackError::InvalidArchive(
            "unsupported CRX version".into(),
        ));
    }

    let start = match version {
        2 => {
            if bytes.len() < 16 {
                return Err(OpenPackError::InvalidArchive("CRX header too short".into()));
            }

            let pubkey_len = usize::try_from(u32::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
            ]))
            .map_err(|_| OpenPackError::InvalidArchive("CRX header overflows".into()))?;
            let sig_len = usize::try_from(u32::from_le_bytes([
                bytes[12], bytes[13], bytes[14], bytes[15],
            ]))
            .map_err(|_| OpenPackError::InvalidArchive("CRX header overflows".into()))?;

            16usize
                .checked_add(pubkey_len)
                .and_then(|value| value.checked_add(sig_len))
                .ok_or_else(|| OpenPackError::InvalidArchive("CRX header overflows".into()))?
        }
        3 => {
            let header_len = usize::try_from(u32::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
            ]))
            .map_err(|_| OpenPackError::InvalidArchive("CRX header overflows".into()))?;

            12usize
                .checked_add(header_len)
                .ok_or_else(|| OpenPackError::InvalidArchive("CRX header overflows".into()))?
        }
        _ => unreachable!("validated CRX version"),
    };

    if start >= bytes.len() {
        return Err(OpenPackError::InvalidArchive(
            "invalid CRX header lengths".into(),
        ));
    }

    Ok(start..bytes.len())
}
