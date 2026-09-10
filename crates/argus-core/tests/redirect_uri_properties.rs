#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use argus_core::redirect_uri::{RedirectUri, RedirectUriMatch};
use proptest::prelude::*;

// §1 #24 ve RFC 9700: eşleştirme yalnızca exact string. authentik
// CVE-2024-52289 kaçırılmamış bir regex noktasıydı ve `app.example.com`
// konfigürasyonunu `app0example.com` ile eşleştirdi; kurban doğrudan
// saldırgana yönlendirildi. Buradaki özellikler o sınıfı hedefler.

fn host() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("example.com".to_owned()),
        Just("app.example.com".to_owned()),
        Just("app0example.com".to_owned()),
        Just("appXexample.com".to_owned()),
        Just("example.com.evil.test".to_owned()),
        Just("evil.test".to_owned()),
        Just("sub.app.example.com".to_owned()),
    ]
}

fn path() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("/cb".to_owned()),
        Just("/callback".to_owned()),
        Just("/cb/".to_owned()),
        Just("/cb/deeper".to_owned()),
        Just("/CB".to_owned()),
    ]
}

fn https_uri() -> impl Strategy<Value = String> {
    (host(), path()).prop_map(|(h, p)| format!("https://{h}{p}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Kayıtlı olandan farklı HER dizge reddedilir. Tek istisna loopback'tir ve
    /// bu üretici hiç loopback üretmiyor.
    #[test]
    fn only_the_exact_string_matches(
        registered in https_uri(),
        presented in https_uri(),
    ) {
        let Ok(uri) = RedirectUri::register(registered.clone()) else {
            return Ok(());
        };

        let outcome = uri.match_presented(&presented);

        if registered == presented {
            prop_assert_eq!(outcome, Some(RedirectUriMatch::Exact));
        } else {
            prop_assert_eq!(
                outcome,
                None,
                "{} matched {}, which is not the same string",
                registered,
                presented
            );
        }
    }

    /// Bir yıldız taşıyan hiçbir şey KAYDEDİLEMEZ. Wildcard "opt-in tehlikeli
    /// özellik" olarak bile implemente edilmiyor.
    #[test]
    fn nothing_carrying_a_wildcard_can_be_registered(
        left in https_uri(),
        at in 0_usize..40,
    ) {
        let mut raw = left;
        let at = at.min(raw.len());
        raw.insert(at, '*');
        prop_assert!(RedirectUri::register(raw).is_err());
    }

    /// Kayıtlı URI'nin bir ÖNEKİ ya da bir UZANTISI eşleşmez. Prefix eşleştirme
    /// açık yönlendirmenin en yaygın biçimidir.
    #[test]
    fn neither_a_prefix_nor_an_extension_matches(
        registered in https_uri(),
        suffix in prop_oneof![
            Just("/more".to_owned()),
            Just("?x=1".to_owned()),
            Just("@evil.test".to_owned()),
            Just(".evil.test".to_owned()),
        ],
    ) {
        let Ok(uri) = RedirectUri::register(registered.clone()) else {
            return Ok(());
        };

        prop_assert_eq!(uri.match_presented(&format!("{registered}{suffix}")), None);

        if let Some(shorter) = registered.get(..registered.len().saturating_sub(1))
            && shorter != registered
        {
            prop_assert_eq!(uri.match_presented(shorter), None);
        }
    }

    /// Loopback istisnası YALNIZCA port'u yok sayar (RFC 8252 §7.3). Şema, host
    /// ve yol hâlâ birebir eşleşmek zorunda.
    #[test]
    fn the_loopback_exception_ignores_the_port_and_nothing_else(
        registered_port in 1024_u16..65535,
        presented_port in 1024_u16..65535,
        path in path(),
        other in path(),
    ) {
        let registered = format!("http://127.0.0.1:{registered_port}{path}");
        let Ok(uri) = RedirectUri::register(registered) else {
            return Ok(());
        };

        let same_path = format!("http://127.0.0.1:{presented_port}{path}");
        prop_assert!(
            uri.match_presented(&same_path).is_some(),
            "the port must be ignored on loopback"
        );

        if other != path {
            let other_path = format!("http://127.0.0.1:{presented_port}{other}");
            prop_assert_eq!(
                uri.match_presented(&other_path),
                None,
                "only the port is ignored, never the path"
            );
        }

        // Ve istisna loopback DIŞINA taşmaz.
        let elsewhere = format!("http://example.com:{presented_port}{path}");
        prop_assert_eq!(uri.match_presented(&elsewhere), None);
    }

    /// Kayıtlı bir loopback URI'si, loopback OLMAYAN bir host'la eşleşmez, ve
    /// tersi de geçerlidir.
    #[test]
    fn a_public_registration_never_gains_the_loopback_exception(
        port in 1024_u16..65535,
        other in 1024_u16..65535,
        path in path(),
    ) {
        let registered = format!("https://example.com:{port}{path}");
        let Ok(uri) = RedirectUri::register(registered) else {
            return Ok(());
        };

        if port != other {
            prop_assert_eq!(
                uri.match_presented(&format!("https://example.com:{other}{path}")),
                None,
                "the port is only ignored on loopback"
            );
        }
    }
}
