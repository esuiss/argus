//! `argus-http` — HTTP yüzeyi.
//!
//! # Bu katmanın işi
//!
//! Karar **vermez**, kararı uygular. Her endpoint şu üç adımı yapar:
//!
//! 1. İsteği ayrıştır ve kiracıyı **host'tan** çöz (gövdeden asla — §18).
//! 2. `argus-core`'un saf karar fonksiyonunu çağır.
//! 3. Dönen [`argus_core::effect::Effect`] listesini **sırayla ve tamamen** uygula.
//!
//! Üçüncü adımdaki "tamamen" bir üslup değil: uygulanmayan bir
//! `RevokeRefreshFamily`, çalınmış bir token zincirinin canlı kalması demektir.
//! Bu yüzden etki uygulayıcısı tek bir `match`'tir ve derleyici yeni bir etkiyi
//! ele almayı unutmaya izin vermez.

#![forbid(unsafe_code)]

pub mod effects;
pub mod endpoints;
pub mod memstore;
pub mod router;
pub mod state;
pub mod store;

pub use router::build;
pub use state::AppState;
