//! Lector de bytes con comprobacion de limites.
//!
//! Todos los cargadores leen a traves de `Reader`: ninguna lectura puede
//! provocar un panic por indice fuera de rango ni por desbordamiento de
//! aritmetica, aunque el archivo sea malicioso (RNF-03, modelo de amenazas).

use crate::arch::Endian;
use crate::error::{Error, Result};

/// Vista de bytes de un binario con endianness fija y lecturas comprobadas.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    endian: Endian,
}

impl<'a> Reader<'a> {
    /// Crea un lector sobre `data` que interpreta los enteros con `endian`.
    pub fn new(data: &'a [u8], endian: Endian) -> Self {
        Reader { data, endian }
    }

    /// Tamano total del archivo en bytes.
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    /// Indica si el archivo esta vacio.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Devuelve `n` bytes desde `off`, o error si salen del archivo.
    pub fn bytes(&self, off: u64, n: u64) -> Result<&'a [u8]> {
        let end = off
            .checked_add(n)
            .ok_or_else(|| Error::malformed(format!("desbordamiento en 0x{off:x}+0x{n:x}")))?;
        if end > self.len() {
            return Err(Error::malformed(format!(
                "lectura fuera de rango: 0x{off:x}..0x{end:x} (archivo de 0x{:x} bytes)",
                self.len()
            )));
        }
        Ok(&self.data[off as usize..end as usize])
    }

    /// Comprueba que el rango `[off, off+n)` cabe en el archivo.
    pub fn check_range(&self, off: u64, n: u64, what: &str) -> Result<()> {
        self.bytes(off, n)
            .map(|_| ())
            .map_err(|_| Error::malformed(format!("{what} fuera del archivo")))
    }

    fn arr<const N: usize>(&self, off: u64) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(off, N as u64)?);
        Ok(out)
    }

    /// Lee un byte sin signo.
    pub fn u8(&self, off: u64) -> Result<u8> {
        Ok(self.arr::<1>(off)?[0])
    }

    /// Lee un entero de 16 bits con el endianness del lector.
    pub fn u16(&self, off: u64) -> Result<u16> {
        let b = self.arr::<2>(off)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
    }

    /// Lee un entero de 32 bits con el endianness del lector.
    pub fn u32(&self, off: u64) -> Result<u32> {
        let b = self.arr::<4>(off)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    }

    /// Lee un entero de 64 bits con el endianness del lector.
    pub fn u64(&self, off: u64) -> Result<u64> {
        let b = self.arr::<8>(off)?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        })
    }

    /// Lee una cadena C (terminada en 0) dentro de `[start, start+limit)`.
    pub fn cstr(&self, start: u64, limit: u64) -> String {
        let limit = limit.min(256);
        let n = limit.min(self.len().saturating_sub(start));
        match self.bytes(start, n) {
            Ok(b) => {
                let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                String::from_utf8_lossy(&b[..end]).into_owned()
            }
            Err(_) => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_endians() {
        let d = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(Reader::new(&d, Endian::Little).u32(0).unwrap(), 0x0403_0201);
        assert_eq!(Reader::new(&d, Endian::Big).u32(0).unwrap(), 0x0102_0304);
    }

    #[test]
    fn out_of_range_is_error_not_panic() {
        let d = [0u8; 4];
        let r = Reader::new(&d, Endian::Little);
        assert!(r.u32(1).is_err());
        assert!(r.u64(0).is_err());
        assert!(r.bytes(u64::MAX, 2).is_err()); // desbordamiento
    }

    #[test]
    fn cstr_stops_at_nul_and_is_bounded() {
        let d = b"abc\0def";
        let r = Reader::new(d, Endian::Little);
        assert_eq!(r.cstr(0, 100), "abc");
        assert_eq!(r.cstr(100, 10), ""); // inicio fuera de rango
    }
}
