use std::collections::BTreeMap;

// §23 §5.1 ve §8 #18-19. Kiracı sayfanın KABUĞUNU yazabilir, giriş kutusunu
// yazamaz. Auth0'ın Universal Login'i de tam olarak böyle: Liquid şablonu
// prompt'un ETRAFINDAKİ içeriği kontrol eder, kutunun içini değil. Sebebi
// keyfi değil — alan adları, sıralama, neyin gönderildiği ve identifier
// adımının sabit biçimli cevabı güvenlik garantileridir.

/// Kabuğun kutuyu nereye koyacağını söyleyen yer tutucu. Şablonda geçmiyorsa
/// sayfa giriş kutusu olmadan render edilirdi, o yüzden doğrulama reddeder.
pub const LOGIN_BOX_PLACEHOLDER: &str = "argus_login_box";

pub const MAX_SHELL_BYTES: usize = 64 * 1024;
pub const MAX_STRINGS: usize = 128;
pub const MAX_STRING_BYTES: usize = 4 * 1024;
pub const MAX_LINKS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ThemeFault {
    #[error("a shell of {actual} bytes exceeds the {allowed} this server accepts")]
    ShellTooLarge { allowed: usize, actual: usize },

    #[error(
        "the shell never places {LOGIN_BOX_PLACEHOLDER}, so the page would carry no sign-in form"
    )]
    NoLoginBox,

    #[error("a theme carries {actual} strings and this server accepts {allowed}")]
    TooManyStrings { allowed: usize, actual: usize },

    #[error("the string {key} is longer than the {allowed} bytes this server accepts")]
    StringTooLong { key: String, allowed: usize },

    #[error("a theme carries {actual} links and this server accepts {allowed}")]
    TooManyLinks { allowed: usize, actual: usize },

    #[error("{field} must be an absolute https URL")]
    NotHttps { field: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub label: String,
    pub url: String,
}

/// Kiracının verdiği her şey. §23 §8 #18: bunların hiçbiri sunucuda kod
/// çalıştırmaz; `shell` bir Liquid şablonudur ve Liquid'in fonksiyon çağırma
/// sözdizimi yoktur.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Theme {
    pub name: String,
    pub logo_url: Option<String>,
    pub primary_colour: Option<String>,
    pub background_colour: Option<String>,

    /// Metin geçersiz kılmaları. §23 §8 #26'nın yerelleştirme zinciri bunun
    /// üstüne kurulur.
    pub strings: BTreeMap<String, String>,

    pub footer_links: Vec<Link>,

    /// Liquid kabuğu. `None` ise derlenmiş varsayılan kabuk kullanılır.
    pub shell: Option<String>,
}

fn is_https(url: &str) -> bool {
    url.starts_with("https://") && !url.contains(['"', '\'', '<', '>'])
}

impl Theme {
    /// Kabul edilmeden önce her tema buradan geçer. Reddedilen bir tema hiç
    /// saklanmaz, o yüzden bozuk bir tema bir kiracıyı giriş ekranından etmez.
    pub fn check(&self) -> Result<(), ThemeFault> {
        if let Some(shell) = &self.shell {
            if shell.len() > MAX_SHELL_BYTES {
                return Err(ThemeFault::ShellTooLarge {
                    allowed: MAX_SHELL_BYTES,
                    actual: shell.len(),
                });
            }
            if !shell.contains(LOGIN_BOX_PLACEHOLDER) {
                return Err(ThemeFault::NoLoginBox);
            }
        }

        if self.strings.len() > MAX_STRINGS {
            return Err(ThemeFault::TooManyStrings {
                allowed: MAX_STRINGS,
                actual: self.strings.len(),
            });
        }

        for (key, value) in &self.strings {
            if value.len() > MAX_STRING_BYTES {
                return Err(ThemeFault::StringTooLong {
                    key: key.clone(),
                    allowed: MAX_STRING_BYTES,
                });
            }
        }

        if self.footer_links.len() > MAX_LINKS {
            return Err(ThemeFault::TooManyLinks {
                allowed: MAX_LINKS,
                actual: self.footer_links.len(),
            });
        }

        // §11 F: kiracıdan gelen bir URL sayfaya girecekse şeması sabitlenir.
        // `javascript:` ve `data:` bir logo alanından geçerse XSS olur.
        if let Some(logo) = &self.logo_url
            && !is_https(logo)
        {
            return Err(ThemeFault::NotHttps {
                field: "logo_url".to_owned(),
            });
        }

        for link in &self.footer_links {
            if !is_https(&link.url) {
                return Err(ThemeFault::NotHttps {
                    field: format!("footer link {}", link.label),
                });
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn string(&self, key: &str, fallback: &str) -> String {
        self.strings
            .get(key)
            .cloned()
            .unwrap_or_else(|| fallback.to_owned())
    }
}
