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
/// Stil dosyasının yolu. Satır içi stil yok: CSP `style-src \'self\'` diyor ve
/// `unsafe-inline` açmamak için stil bir kaynak olarak sunuluyor.
pub const STYLESHEET_PATH: &str = "/assets/argus.css";

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
<link rel="stylesheet" href="{{ theme.stylesheet }}">
<title>{{ theme.name }}</title>
<main class="argus-page">
  {% if theme.has_logo %}<img class="argus-logo" src="{{ theme.logo_url }}" alt="">{% endif %}
  <h1>{{ theme.name }}</h1>
  {{ argus_login_box }}
  {% if theme.has_footer %}
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
    pub fn render(
        &self,
        theme: &Theme,
        client_id: Option<&str>,
        login_box: &str,
    ) -> Result<String, ShellFault> {
        let source = theme.shell.as_deref().unwrap_or(DEFAULT_SHELL);

        let template = self
            .parser
            .parse(source)
            .map_err(|e| ShellFault::NotValid(e.to_string()))?;

        let globals = liquid::object!({
            "theme": theme_view(theme, client_id),
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
    pub fn render_or_default(
        &self,
        theme: &Theme,
        client_id: Option<&str>,
        login_box: &str,
    ) -> String {
        if theme.shell.is_some()
            && let Ok(page) = self.render(theme, client_id, login_box)
        {
            return page;
        }

        let bare = Theme {
            shell: None,
            ..theme.clone()
        };
        self.render(&bare, client_id, login_box)
            .unwrap_or_else(|_| login_box.to_owned())
    }
}

impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}

/// Stil dosyası ayrı bir istek olduğu için hangi istemcinin sayfası olduğunu
/// sorgudan öğrenir; yoksa istemciye özel tema sayfada uygulanır ama stilde
/// uygulanmaz.
fn stylesheet_path(client_id: Option<&str>) -> String {
    client_id.map_or_else(
        || STYLESHEET_PATH.to_owned(),
        |id| format!("{STYLESHEET_PATH}?client_id={}", urlencode(id)),
    )
}

fn urlencode(value: &str) -> String {
    use core::fmt::Write as _;

    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn theme_view(theme: &Theme, client_id: Option<&str>) -> liquid::Object {
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
        // Ölçüldü: Liquid'de boş dizge ve boş dizi DOĞRU sayılır. Bunu
        // bilmeden yazılan bir `{% if theme.logo_url %}`, logosu olmayan
        // kiracıda boş bir img etiketi çizer.
        "has_logo": theme.logo_url.is_some(),
        "has_footer": !theme.footer_links.is_empty(),
        "stylesheet": stylesheet_path(client_id),
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

// Giriş kutusu. Kiracı bunu YAZMAZ, yalnızca yerleştirir. §23 §8'in kutuya
// dair kararları burada duruyor ve kiracının şablonuyla değiştirilemiyor.
pub struct LoginBox<'a> {
    pub theme: &'a Theme,
    /// §23 §8 #21: hata kullanıcıya gösterilir ama ham OAuth hatası değil.
    pub failed: bool,
    /// Giriş başarılıysa dönülecek yerel yol.
    pub return_to: Option<&'a str>,
}

/// §23 §8 #2: identifier adımının çıktısı sabit olmalı — aynı kod, aynı gövde,
/// aynı gecikme. Bu yüzden mesaj tek: hesap yok, parola yanlış, hesap kilitli
/// ve hesap devre dışı hepsi aynı cümleyi alır.
const REFUSED: &str = "Kimlik veya parola doğru değil.";

#[must_use]
pub fn login_box(spec: &LoginBox<'_>) -> String {
    let theme = spec.theme;

    let error = if spec.failed {
        format!(
            "<p class=\"argus-error\" role=\"alert\">{}</p>",
            escape(&theme.string("sign_in_refused", REFUSED))
        )
    } else {
        String::new()
    };

    let return_to = spec.return_to.map_or_else(String::new, |path| {
        format!(
            "<input type=\"hidden\" name=\"return_to\" value=\"{}\">",
            escape(path)
        )
    });

    // §23 §8 #23: paste engellenmiyor, autocomplete doğru kuruluyor, ve OTP
    // benzeri parçalı alan yok. WCAG 2.2 SC 3.3.8 bunu şart koşuyor.
    // §23 §8 #22: CAPTCHA yok.
    format!(
        "<form class=\"argus-box\" method=\"post\" action=\"/login\" autocomplete=\"on\">\
         {error}\
         <label for=\"identifier\">{identifier_label}</label>\
         <input id=\"identifier\" name=\"identifier\" type=\"text\" \
         autocomplete=\"username webauthn\" autocapitalize=\"none\" autocorrect=\"off\" \
         spellcheck=\"false\" required autofocus>\
         <label for=\"password\">{password_label}</label>\
         <input id=\"password\" name=\"password\" type=\"password\" \
         autocomplete=\"current-password\" required>\
         {return_to}\
         <button type=\"submit\">{submit_label}</button>\
         </form>",
        error = error,
        identifier_label = escape(&theme.string("identifier_label", "E-posta veya kullanıcı adı")),
        password_label = escape(&theme.string("password_label", "Parola")),
        submit_label = escape(&theme.string("sign_in", "Giriş yap")),
        return_to = return_to,
    )
}

/// §1 #24 ile aynı sınıf: dönüş adresi bir yönlendirmeye girecekse doğrulanır.
/// Yalnızca bu sunucudaki bir yol kabul edilir; şema, host ve protokole göreli
/// biçim reddedilir, yoksa açık yönlendirme olur.
#[must_use]
pub fn safe_return_to(candidate: &str) -> Option<&str> {
    if !candidate.starts_with('/') {
        return None;
    }
    // `//evil.test` protokole göreli bir mutlak URL'dir.
    if candidate.starts_with("//") {
        return None;
    }
    // Ters bölü bazı tarayıcılarda bölü gibi ele alınıyor.
    if candidate.contains('\\') || candidate.contains(['\r', '\n']) {
        return None;
    }
    Some(candidate)
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

// Stil, kiracının renkleriyle üretilip kendi origin'imizden sunuluyor. Satır
// içi `style` niteliği kullanmamanın sebebi CSP: `unsafe-inline` açmak, kiracı
// kabuğuna yazılmış bir stil enjeksiyonunu da meşrulaştırırdı.
//
// §23 §7: WCAG 2.2. Odak göstergesi görünür, kontrast yeterli, hedefler
// yeterince büyük, ve hiçbir yerde `user-select: none` ya da paste engeli yok.
#[must_use]
pub fn stylesheet(theme: &Theme) -> String {
    let primary = colour(theme.primary_colour.as_deref(), "#1f4ed8");
    let background = colour(theme.background_colour.as_deref(), "#f6f7f9");

    format!(
        ":root {{ --argus-primary: {primary}; --argus-bg: {background}; \
--argus-fg: #14161a; --argus-muted: #5b6472; --argus-line: #d6dae1; \
--argus-surface: #ffffff; --argus-danger: #b3261e; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; \
padding: 24px; background: var(--argus-bg); color: var(--argus-fg); \
font: 16px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }}
.argus-page {{ width: 100%; max-width: 400px; background: var(--argus-surface); \
border: 1px solid var(--argus-line); border-radius: 14px; padding: 32px; \
box-shadow: 0 1px 2px rgba(20, 22, 26, .06), 0 8px 24px rgba(20, 22, 26, .06); }}
.argus-logo {{ display: block; max-height: 40px; margin-bottom: 20px; }}
h1 {{ margin: 0 0 24px; font-size: 22px; line-height: 1.3; font-weight: 600; }}
.argus-box {{ display: grid; gap: 6px; }}
label {{ font-size: 14px; font-weight: 500; color: var(--argus-muted); }}
label + input {{ margin-bottom: 14px; }}
input {{ width: 100%; padding: 11px 13px; font-size: 16px; color: inherit; \
background: var(--argus-surface); border: 1px solid var(--argus-line); \
border-radius: 9px; }}
input:focus-visible, button:focus-visible, a:focus-visible {{ outline: 2px solid var(--argus-primary); \
outline-offset: 2px; }}
button {{ margin-top: 6px; padding: 12px 16px; min-height: 44px; font: inherit; \
font-weight: 600; color: #fff; background: var(--argus-primary); border: 0; \
border-radius: 9px; cursor: pointer; }}
button:hover {{ filter: brightness(.94); }}
.argus-error {{ margin: 0 0 16px; padding: 11px 13px; font-size: 14px; \
color: var(--argus-danger); background: #fdeceb; \
border: 1px solid #f5c6c2; border-radius: 9px; }}
footer {{ margin-top: 24px; padding-top: 16px; display: flex; gap: 16px; \
flex-wrap: wrap; border-top: 1px solid var(--argus-line); font-size: 14px; }}
footer a {{ color: var(--argus-muted); }}
@media (prefers-color-scheme: dark) {{
  :root {{ --argus-bg: #0f1115; --argus-fg: #e8eaed; --argus-muted: #9aa4b2; \
--argus-line: #2a2f38; --argus-surface: #171a20; --argus-danger: #f2b8b5; }}
  .argus-error {{ background: #2a1a19; border-color: #5c2b28; }}
  button {{ color: #0f1115; }}
}}
"
    )
}

/// Kiracıdan gelen bir renk stil dosyasına giriyor. §11 F ile aynı gerekçe:
/// biçimi sabitlenmezse `#fff; } body { background: url(...)` gibi bir değer
/// stil kuralından kaçar. Yalnızca onaltılık renk kabul edilir.
fn colour(value: Option<&str>, fallback: &str) -> String {
    let Some(value) = value else {
        return fallback.to_owned();
    };

    let ok = value.starts_with('#')
        && matches!(value.len(), 4 | 7)
        && value.chars().skip(1).all(|c| c.is_ascii_hexdigit());

    if ok {
        value.to_owned()
    } else {
        fallback.to_owned()
    }
}
