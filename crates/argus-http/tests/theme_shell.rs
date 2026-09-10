#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_core::theme::{Link, Theme, ThemeFault};
use argus_http::pages::{Shell, ShellFault, content_security_policy};

fn theme() -> Theme {
    Theme {
        name: "Acme".to_owned(),
        ..Theme::default()
    }
}

const BOX: &str = "<form method=\"post\" action=\"/login\">the sign-in box</form>";

#[test]
fn the_default_shell_places_the_sign_in_box() {
    let page = Shell::new().render(&theme(), None, BOX).expect("render");
    assert!(page.contains("the sign-in box"));
    assert!(page.contains("Acme"));
}

/// Kararın tamamı buna dayanıyor: Liquid'in fonksiyon çağırma sözdizimi yok ve
/// şablon kendisine verilmeyene ulaşamıyor. `FreeMarker`'ın "kötü niyetli bir
/// şablon süreç yetkisiyle kod çalıştırabilir" sınıfı burada yok.
#[test]
fn a_shell_cannot_reach_anything_it_was_not_given() {
    let shell = Shell::new();

    for source in [
        "{{ argus_login_box }}{{ secret }}",
        "{{ argus_login_box }}{{ theme.name.len }}",
        "{{ argus_login_box }}{{ system }}",
        "{{ argus_login_box }}{{ env }}",
    ] {
        let theme = Theme {
            shell: Some(source.to_owned()),
            ..theme()
        };
        let page = shell.render(&theme, None, BOX);
        assert!(
            page.is_err() || page.as_deref().is_ok_and(|p| !p.contains("secret")),
            "{source} reached something it was not handed"
        );
    }
}

/// §23 §5.2 ve Auth0'ın kendi uyarısı: kabuk kiracınındır, ve kaçırma bizim
/// işimiz. Bu test, kiracının şablonunun İSTEK verisine hiç ulaşamadığını
/// sabitliyor — kutu bize ait ve ayrı render ediliyor.
#[test]
fn the_shell_never_sees_request_data() {
    let theme = Theme {
        shell: Some(
            "{{ argus_login_box }}[{{ error }}][{{ return_to }}][{{ identifier }}]".to_owned(),
        ),
        ..theme()
    };

    // Ölçüldü: liquid verilmemiş bir değişkende sessizce boş basmıyor, HATA
    // veriyor. Varsaydığımdan güçlü — bir kabuk istek verisine uzanmaya
    // kalkarsa sayfa çıkmaz, ve `render_or_default` derlenmiş kabuğa düşer.
    let outcome = Shell::new().render(&theme, None, BOX);
    assert!(
        matches!(outcome, Err(ShellFault::NotValid(_))),
        "reaching for request data must fail, not render empty: {outcome:?}"
    );

    let page = Shell::new().render_or_default(&theme, None, BOX);
    assert!(page.contains("the sign-in box"));
    assert!(
        !page.contains("[]"),
        "the failing shell must not be used: {page}"
    );
}

#[test]
fn a_shell_that_never_places_the_box_is_refused_before_it_is_stored() {
    let theme = Theme {
        shell: Some("<h1>{{ theme.name }}</h1>".to_owned()),
        ..theme()
    };
    assert!(matches!(theme.check(), Err(ThemeFault::NoLoginBox)));
}

#[test]
fn a_shell_that_is_not_valid_liquid_is_refused() {
    let shell = Shell::new();
    assert!(matches!(
        shell.check("{% for x in %}{{ argus_login_box }}"),
        Err(ShellFault::NotValid(_))
    ));
}

/// Bozuk bir tema o kiracıyı giriş ekranından etmemeli.
#[test]
fn a_broken_shell_falls_back_to_the_compiled_one() {
    let theme = Theme {
        shell: Some("{% for x in %}broken".to_owned()),
        ..theme()
    };

    let page = Shell::new().render_or_default(&theme, None, BOX);
    assert!(
        page.contains("the sign-in box"),
        "the fallback must still carry the box: {page}"
    );
}

/// §11 F: kiracıdan gelen bir URL sayfaya girecekse şeması sabitlenir.
/// `javascript:` bir logo alanından geçerse XSS olur.
#[test]
fn a_logo_that_is_not_https_is_refused() {
    for bad in [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "http://plain.test/logo.png",
        "https://x.test/\"><script>alert(1)</script>",
    ] {
        let theme = Theme {
            logo_url: Some(bad.to_owned()),
            ..theme()
        };
        assert!(
            matches!(theme.check(), Err(ThemeFault::NotHttps { .. })),
            "{bad} must not be accepted as a logo"
        );
    }

    let good = Theme {
        logo_url: Some("https://cdn.acme.test/logo.png".to_owned()),
        ..theme()
    };
    good.check().expect("an https logo is fine");
}

#[test]
fn a_footer_link_is_held_to_the_same_rule() {
    let theme = Theme {
        footer_links: vec![Link {
            label: "help".to_owned(),
            url: "javascript:alert(1)".to_owned(),
        }],
        ..theme()
    };
    assert!(matches!(theme.check(), Err(ThemeFault::NotHttps { .. })));
}

/// §23 §8 #19: kontrol CSP. Kiracının kabuğu bir script yazsa bile çalışmaz,
/// çünkü politika hiçbir script kaynağına izin vermiyor.
#[test]
fn the_policy_allows_no_script_at_all() {
    let policy = content_security_policy(&theme());
    assert!(policy.contains("default-src 'none'"));
    assert!(
        !policy.contains("script-src"),
        "no script source is allowed"
    );
    assert!(!policy.contains("unsafe-inline"));
    assert!(policy.contains("frame-ancestors 'none'"));
    assert!(policy.contains("form-action 'self'"));
}

#[test]
fn the_policy_admits_exactly_the_logo_origin_and_no_other() {
    let theme = Theme {
        logo_url: Some("https://cdn.acme.test/a/b/logo.png".to_owned()),
        ..theme()
    };
    let policy = content_security_policy(&theme);
    assert!(policy.contains("https://cdn.acme.test"));
    assert!(
        !policy.contains("/a/b/"),
        "a path must not leak into the policy: {policy}"
    );
}

#[test]
fn an_oversized_shell_is_refused() {
    let theme = Theme {
        shell: Some(format!(
            "{{{{ {} }}}}{}",
            "argus_login_box",
            "x".repeat(70_000)
        )),
        ..theme()
    };
    assert!(matches!(
        theme.check(),
        Err(ThemeFault::ShellTooLarge { .. })
    ));
}

/// Kararın ne SATIN ALDIĞINI gösteriyor. Kiracı sayfanın kabuğunu tamamen
/// yeniden kuruyor: iki sütun, sağda kendi tanıtım paneli, kendi altbilgisi.
/// Giriş kutusu bizim ve kiracı onu yalnızca YERLEŞTİRİYOR.
#[test]
fn a_tenant_can_rebuild_the_whole_shell_around_the_box() {
    let theme = Theme {
        name: "Globex".to_owned(),
        logo_url: Some("https://cdn.globex.test/logo.svg".to_owned()),
        footer_links: vec![
            Link {
                label: "Gizlilik".to_owned(),
                url: "https://globex.test/privacy".to_owned(),
            },
            Link {
                label: "Yardım".to_owned(),
                url: "https://globex.test/help".to_owned(),
            },
        ],
        shell: Some(
            r#"<!doctype html><html><body class="split">
<section class="left">
  <img src="{{ theme.logo_url }}" alt="">
  <h1>{{ theme.name }}</h1>
  {{ argus_login_box }}
</section>
<aside class="right">
  <h2>{{ theme.strings.pitch_title }}</h2>
  <p>{{ theme.strings.pitch_body }}</p>
</aside>
<footer>{% for link in theme.footer_links %}<a href="{{ link.url }}">{{ link.label }}</a>{% endfor %}</footer>
</body></html>"#
                .to_owned(),
        ),
        strings: [
            ("pitch_title".to_owned(), "Tek hesap".to_owned()),
            ("pitch_body".to_owned(), "Her yerde geçerli.".to_owned()),
        ]
        .into_iter()
        .collect(),
        ..Theme::default()
    };

    theme.check().expect("a valid theme");
    let page = Shell::new().render(&theme, None, BOX).expect("render");

    // Kabuk kiracının: iki sütun, tanıtım paneli, altbilgi bağlantıları.
    assert!(page.contains(r#"class="split""#));
    assert!(page.contains("Tek hesap"));
    assert!(page.contains("https://globex.test/privacy"));
    assert!(page.contains("Yardım"));

    // Kutu bizim ve olduğu gibi duruyor.
    assert!(page.contains("the sign-in box"));
    assert!(page.contains(r#"action="/login""#));
}

/// Ve kiracı kabuğa bir script yazarsa: sunucuda hiçbir şey olmaz, tarayıcıda
/// da CSP onu çalıştırmaz. `FreeMarker`'da aynı şablon süreç yetkisiyle kod
/// çalıştırırdı.
#[test]
fn a_script_in_the_shell_runs_nowhere() {
    let theme = Theme {
        shell: Some("<script>fetch('https://evil.test')</script>{{ argus_login_box }}".to_owned()),
        ..theme()
    };

    // Sunucu tarafı: render sorunsuz biter, hiçbir kod çalışmaz.
    let page = Shell::new().render(&theme, None, BOX).expect("render");
    assert!(page.contains("the sign-in box"));

    // Tarayıcı tarafı: politika hiçbir script kaynağına izin vermiyor.
    let policy = content_security_policy(&theme);
    assert!(policy.contains("default-src 'none'"));
    assert!(!policy.contains("script"));
}

/// Liquid'de boş dizge ve boş dizi DOĞRU sayılır. Bunu bilmeden yazılan bir
/// `{% if theme.logo_url %}`, logosu olmayan kiracıda boş bir img etiketi
/// çizer. Ölçüldü ve sabitlendi.
#[test]
fn an_absent_logo_and_an_empty_footer_draw_nothing() {
    let page = Shell::new().render(&theme(), None, BOX).expect("render");
    assert!(
        !page.contains("<img"),
        "an empty logo must not be drawn: {page}"
    );
    assert!(
        !page.contains("<footer"),
        "an empty footer must not be drawn: {page}"
    );

    let with = Theme {
        logo_url: Some("https://cdn.acme.test/logo.png".to_owned()),
        footer_links: vec![Link {
            label: "help".to_owned(),
            url: "https://acme.test/help".to_owned(),
        }],
        ..theme()
    };
    let page = Shell::new().render(&with, None, BOX).expect("render");
    assert!(page.contains("https://cdn.acme.test/logo.png"));
    assert!(page.contains("<footer"));
}
