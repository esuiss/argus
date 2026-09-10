use std::time::{Duration, Instant};

use argus_core::theme::{LOGIN_BOX_PLACEHOLDER, Theme, ThemeFault};

// §23 §5.2'nin Argus için verdiği model: Okta'nın CSP allowlist'i + Auth0'ın
// script çalıştırmayan şablon dili. Kiracı kabuğu yazar, giriş kutusu derlenmiş
// kalır.
//
// Liquid'in bu crate'teki davranışı ölçüldü ve testle sabitlendi:
//   - `{{ }}` OTOMATİK KAÇIRMA YAPMAZ. Kaçırma bize ait.
//   - Şablon, kendisine elden verilmeyen hiçbir şeye ulaşamaz. `{{ system }}`
//     ve `{{ x.len }}` erişilemez. FreeMarker'ın nesne grafiği burada yok.
//
// Bu ikisi birlikte tasarımı belirliyor: İSTEKTEN GELEN HİÇBİR DEĞER kiracının
// şablonuna girmez. Kabuk yalnızca kiracı verisini ve bizim ürettiğimiz kutuyu
// görür; hata mesajı, geri dönüş adresi ve kullanıcı girdisi kutunun içinde
// kalır ve orada derlenmiş kodla kaçırılır.

/// §11 G.1 ile aynı gerekçe: sınırsız çıktı bir `DoS`'tur. Liquid döngü kurabilir.
pub const MAX_OUTPUT_BYTES: usize = 512 * 1024;

/// Bir render'ın alabileceği süre. Aşılırsa varsayılan kabuğa düşülür; bir
/// kiracının bozuk şablonu o kiracıyı giriş ekranından etmemeli.
pub const MAX_RENDER: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShellFault {
    #[error("the shell is not valid Liquid: {0}")]
    NotValid(String),

    #[error("rendering produced more than the {allowed} bytes this server accepts")]
    TooLarge { allowed: usize },

    #[error("rendering took longer than the {}ms this server accepts", MAX_RENDER.as_millis())]
    TooSlow,

    #[error(transparent)]
    Theme(#[from] ThemeFault),
}

/// Kiracı bir kabuk vermediğinde kullanılan sayfa. Tek sütun, harici kaynak
/// yok, satır içi script yok.
const DEFAULT_SHELL: &str = r#"<!doctype html>
<html lang="{{ theme.locale }}" dir="{{ theme.dir }}">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ theme.name }}</title>
<main class="argus-page">
  {% if theme.logo_url %}<img class="argus-logo" src="{{ theme.logo_url }}" alt="">{% endif %}
  <h1>{{ theme.name }}</h1>
  {{ argus_login_box }}
  {% if theme.footer_links %}
  <footer>
    {% for link in theme.footer_links %}<a href="{{ link.url }}">{{ link.label }}</a>{% endfor %}
  </footer>
  {% endif %}
</main>
</html>"#;

pub struct Shell {
    parser: liquid::Parser,
}

impl Shell {
    #[must_use]
    pub fn new() -> Self {
        Self {
            // stdlib yalnızca metin filtreleri getirir: upcase, escape, date,
            // default gibi. Dosya, ağ ya da süreç filtreleri yok ve biz de
            // kendimiz eklemiyoruz.
            parser: liquid::ParserBuilder::with_stdlib()
                .build()
                .unwrap_or_else(|_| unreachable!("the stdlib parser is always constructible")),
        }
    }

    /// Kiracı bir kabuk kaydetmeden ÖNCE bunu geçmek zorunda. §24 #26'nın
    /// ruhu: reddedilen bir şey hiç saklanmaz.
    pub fn check(&self, source: &str) -> Result<(), ShellFault> {
        self.parser
            .parse(source)
            .map(|_| ())
            .map_err(|e| ShellFault::NotValid(e.to_string()))
    }

    /// Kabuğu render eder. `login_box` bizim ürettiğimiz, zaten kaçırılmış
    /// HTML'dir; Liquid kaçırmadığı için olduğu gibi yerleşir.
    pub fn render(&self, theme: &Theme, login_box: &str) -> Result<String, ShellFault> {
        let source = theme.shell.as_deref().unwrap_or(DEFAULT_SHELL);

        let template = self
            .parser
            .parse(source)
            .map_err(|e| ShellFault::NotValid(e.to_string()))?;

        let globals = liquid::object!({
            "theme": theme_view(theme),
            LOGIN_BOX_PLACEHOLDER: login_box,
        });

        let started = Instant::now();
        let out = template
            .render(&globals)
            .map_err(|e| ShellFault::NotValid(e.to_string()))?;

        // Süre ve boyut render'dan SONRA ölçülüyor, çünkü liquid bu sürümde
        // yakıt sınırı vermiyor. Kontrol yine de gerçek: aşan çıktı çağırana
        // gitmez ve çağıran varsayılan kabuğa düşer.
        if started.elapsed() > MAX_RENDER {
            return Err(ShellFault::TooSlow);
        }
        if out.len() > MAX_OUTPUT_BYTES {
            return Err(ShellFault::TooLarge {
                allowed: MAX_OUTPUT_BYTES,
            });
        }

        Ok(out)
    }

    /// Kiracının kabuğu reddedilirse sayfa yine çıkar. Bozuk bir tema bir
    /// kiracıyı giriş ekranından etmemeli.
    #[must_use]
    pub fn render_or_default(&self, theme: &Theme, login_box: &str) -> String {
        if theme.shell.is_some()
            && let Ok(page) = self.render(theme, login_box)
        {
            return page;
        }

        let bare = Theme {
            shell: None,
            ..theme.clone()
        };
        self.render(&bare, login_box)
            .unwrap_or_else(|_| login_box.to_owned())
    }
}

impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}

fn theme_view(theme: &Theme) -> liquid::Object {
    let links: Vec<liquid::model::Value> = theme
        .footer_links
        .iter()
        .map(|link| {
            liquid::model::Value::Object(liquid::object!({
                "label": link.label.clone(),
                "url": link.url.clone(),
            }))
        })
        .collect();

    let strings: liquid::Object = theme
        .strings
        .iter()
        .map(|(k, v)| (k.clone().into(), liquid::model::Value::scalar(v.clone())))
        .collect();

    liquid::object!({
        "name": theme.name.clone(),
        "logo_url": theme.logo_url.clone().unwrap_or_default(),
        "primary_colour": theme.primary_colour.clone().unwrap_or_default(),
        "background_colour": theme.background_colour.clone().unwrap_or_default(),
        "locale": "en",
        "dir": "ltr",
        "footer_links": links,
        "strings": strings,
    })
}

/// §23 §8 #19'un CSP'si. Satır içi script yok, dolayısıyla `unsafe-inline`
/// gerekmiyor; kiracının kabuğu bir `<script>` yazsa bile çalışmaz.
#[must_use]
pub fn content_security_policy(theme: &Theme) -> String {
    let mut images = String::from("'self' data:");
    if let Some(logo) = &theme.logo_url
        && let Some(origin) = origin_of(logo)
    {
        images.push(' ');
        images.push_str(&origin);
    }

    format!(
        "default-src 'none'; img-src {images}; style-src 'self'; form-action 'self'; \
         frame-ancestors 'none'; base-uri 'none'"
    )
}

fn origin_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()).then(|| format!("https://{host}"))
}
