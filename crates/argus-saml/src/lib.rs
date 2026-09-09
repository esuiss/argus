//! `argus-saml` — iskelet.

// `Cargo.toml` zaten `unsafe_code = "forbid"` uyguluyor. Attribute ayrıca
// yazılıyor çünkü kaynak dosyayı okuyan araçlar (cargo-geiger) lint tablosunu
// görmüyor — Faz 0 çıkış kriteri o araçla ifade edilmiş.
#![forbid(unsafe_code)]
