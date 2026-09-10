// Denetim bütünlüğü. §9.3 şekli iki bağımsız ölçümle kapattı: olay başına
// hash zinciri insert bütçesinin çoğunu yiyor ve daha kötüsü kanıtı log
// boyutuyla doğrusal yapıyor. Düz append-only log + periyodik Merkle
// checkpoint olay başına neredeyse hiçbir şeye mal olmaz ve logaritmik
// kanıt verir. Crosby & Wallach (USENIX Security 2009): 80 milyon olaylı
// bir logda tek olayın kanıtı hash chain'de 800 MB, history tree'de 3 KB.

pub mod merkle;
pub mod record;

pub use record::{Attestation, CHAIN_UID_PREFIX, Checkpoint, fingerprint};
