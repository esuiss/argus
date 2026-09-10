// Yönetim API'si. §24 beş satıcının incelemesini 38 karara çeviriyor; bu
// modül onları tele taşır, yargı argus-core'da durur (§1 #15, crate
// topolojisi: bir argus-http handler'ı karar veriyorsa yanlış yerdedir).
//
// Buradaki iki şey sözleşme değil YAPIDIR. Router izin manifestosundan
// üretilir, dolayısıyla kimsenin izin bildirmediği bir route hiç mount
// edilemez: §24 #10, Zitadel CVE-2025-27507 bir yanlış dizgeyle 12
// endpoint açtıktan sonra. Ve göremeyeceği bir kaynak için çağıran 403
// değil 404 alır: §24 #15, çünkü 403 kaynağın var olduğunu doğrular.

mod audit;
mod guard;
mod jobs;
mod openapi;
mod resources;
mod router;

pub use guard::{AdminState, Caller, PLATFORM_OBJECT, Refusal, Shared};
pub use router::{build, unimplemented};
