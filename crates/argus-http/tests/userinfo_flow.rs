//! `UserInfo` endpoint'i — OIDC Core §5.3 ve `RFC` 9449 §7.1.
//!
//! # Burada test edilen şey bir kaynak sunucudur
//!
//! Token endpoint'i sırrı doğrulayıp iddia üretir; `UserInfo` iddiayı doğrular.
//! Bu testlerin çoğu **ret** yollarını sınıyor, çünkü kaynak sunucuda asıl
//! tehlike yanlış kabuldür: geçersiz bir token'ı kabul etmek, bağlamayı
//! uygulamamak ya da süresi dolmuşu geçirmek.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use argus_core::dpop::ReplayGuard;
use argus_core::time::{Duration, Timestamp};
use argus_crypto::{AwsLcSha256, SigningKey};
use argus_http::endpoints::userinfo::{UserInfoError, UserInfoRequest, handle};
use argus_http::state::TenantContext;
use argus_proto::jwt::{AccessTokenClaims, Confirmation, sign};
use argus_proto::{AuthorizationServerMetadata, oidc};
use base64ct::{Base64UrlUnpadded, Encoding as _};

const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);
const ISSUER: &str = "https://acme.argus.test";
const USERINFO: &str = "https://acme.argus.test/userinfo";
const SUBJECT: &str = "0000000000000000000000000000a1";

/// Hiçbir `jti`'yi görülmüş saymaz.
///
/// ⚠️ Üretimde bu yeterli DEĞİL (`RFC` 9449 §11.1); burada tekrar korumasının
/// **dışındaki** kuralları izole etmek için kullanılıyor.
struct NoReplay;

impl ReplayGuard for NoReplay {
    fn seen(&self, _jti: &str) -> bool {
        false
    }
}

/// Her `jti`'yi görülmüş sayar — tekrar reddinin gerçekten bağlı olduğunu
/// kanıtlamak için.
struct EverythingSeen;

impl ReplayGuard for EverythingSeen {
    fn seen(&self, _jti: &str) -> bool {
        true
    }
}

fn tenant() -> (TenantContext, Arc<SigningKey>) {
    let (key, _) = SigningKey::generate("k1").expect("key");
    let key = Arc::new(key);
    (
        TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer(ISSUER),
            active_key: Arc::clone(&key),
            published_keys: vec![Arc::clone(&key)],
        },
        key,
    )
}

fn claims(cnf: Option<Confirmation>) -> AccessTokenClaims {
    AccessTokenClaims {
        iss: ISSUER.to_owned(),
        sub: SUBJECT.to_owned(),
        aud: "acme-web".to_owned(),
        exp: NOW
            .saturating_add(Duration::from_seconds(300))
            .as_unix_seconds(),
        iat: NOW.as_unix_seconds(),
        jti: "t1".to_owned(),
        scope: Some("openid".to_owned()),
        sess: 0,
        cnf,
    }
}

/// Gerçek bir `DPoP` kanıtı üretir.
fn make_proof(key: &SigningKey, htm: &str, htu: &str, iat: i64, ath: Option<&str>) -> String {
    let c = key.public_components().expect("components");
    let x = Base64UrlUnpadded::encode_string(&c.x);
    let y = Base64UrlUnpadded::encode_string(&c.y);
    let header = format!(
        r#"{{"alg":"ES256","typ":"dpop+jwt","jwk":{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}}}"#
    );
    let ath_field = ath.map_or_else(String::new, |a| format!(r#","ath":"{a}""#));
    let payload = format!(r#"{{"jti":"j1","htm":"{htm}","htu":"{htu}","iat":{iat}{ath_field}}}"#);
    let input = format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(header.as_bytes()),
        Base64UrlUnpadded::encode_string(payload.as_bytes())
    );
    let sig = key.sign(input.as_bytes()).expect("sign");
    format!("{input}.{}", Base64UrlUnpadded::encode_string(&sig))
}

fn request<'a>(authorization: Option<&'a str>, dpop: Option<&'a str>) -> UserInfoRequest<'a> {
    UserInfoRequest {
        authorization,
        form_access_token: None,
        dpop,
        method: "GET",
        uri: USERINFO,
    }
}

/// Token'ı gövdede sunan istek.
fn body_request(token: &str) -> UserInfoRequest<'_> {
    UserInfoRequest {
        authorization: None,
        form_access_token: Some(token),
        dpop: None,
        method: "GET",
        uri: USERINFO,
    }
}

// --- Bearer yolu -----------------------------------------------------------

/// §5.3.2: `sub` `id_token`'daki ile AYNI olmalı, yoksa istemci iki kimliği
/// eşleştiremez.
#[test]
fn a_valid_bearer_token_returns_the_subject() {
    let (ctx, key) = tenant();
    let token = sign(&claims(None), &key).expect("sign");
    let header = format!("Bearer {token}");

    let info = handle(&ctx, &request(Some(&header), None), NOW, &NoReplay).expect("accepted");
    assert_eq!(info.sub, SUBJECT);
}

/// `RFC` 7235 §2.1: şema harf büyüklüğüne duyarsızdır. `bearer` gönderen
/// istemciler var; reddetmek uyum hatası olurdu.
#[test]
fn the_scheme_is_case_insensitive() {
    let (ctx, key) = tenant();
    let token = sign(&claims(None), &key).expect("sign");
    let header = format!("bEaReR {token}");

    assert!(handle(&ctx, &request(Some(&header), None), NOW, &NoReplay).is_ok());
}

/// `RFC` 6750 §3.1: kimlik bilgisi HİÇ yoksa `error` yazılmaz — istemciye
/// "kimlik doğrula" denir, "token'ın bozuk" denmez.
#[test]
fn a_missing_authorization_header_is_a_plain_challenge() {
    let (ctx, _) = tenant();
    let err = handle(&ctx, &request(None, None), NOW, &NoReplay).unwrap_err();

    assert_eq!(err, UserInfoError::MissingCredentials);
    assert_eq!(err.challenge(), "Bearer");
    assert!(!err.challenge().contains("error="));
    assert_eq!(err.http_status(), 401);
}

#[test]
fn unknown_schemes_and_empty_tokens_are_refused() {
    let (ctx, _) = tenant();
    for header in ["Basic abc", "Bearer", "Bearer   ", "DPoP ", "garbage"] {
        assert_eq!(
            handle(&ctx, &request(Some(header), None), NOW, &NoReplay).unwrap_err(),
            UserInfoError::MissingCredentials,
            "must not accept {header:?}"
        );
    }
}

/// BAŞKA bir anahtarla imzalanmış token kabul edilmemeli; aksi hâlde imza
/// kontrolü hiçbir şey yapmıyor demektir.
#[test]
fn a_token_signed_by_another_key_is_rejected() {
    let (ctx, _) = tenant();
    let (foreign, _) = SigningKey::generate("evil").expect("key");
    let token = sign(&claims(None), &foreign).expect("sign");
    let header = format!("Bearer {token}");

    assert_eq!(
        handle(&ctx, &request(Some(&header), None), NOW, &NoReplay).unwrap_err(),
        UserInfoError::InvalidToken
    );
}

/// İmza geçerli olsa bile süresi dolmuş token kabul edilmez.
#[test]
fn an_expired_token_is_rejected() {
    let (ctx, key) = tenant();
    let token = sign(&claims(None), &key).expect("sign");
    let header = format!("Bearer {token}");

    let later = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 301);
    assert_eq!(
        handle(&ctx, &request(Some(&header), None), later, &NoReplay).unwrap_err(),
        UserInfoError::InvalidToken
    );
}

/// Başka bir issuer'ın token'ı, imzası doğrulansa bile bu kiracıya ait değildir.
#[test]
fn a_token_from_another_issuer_is_rejected() {
    let (ctx, key) = tenant();
    let mut c = claims(None);
    c.iss = "https://evil.argus.test".to_owned();
    let token = sign(&c, &key).expect("sign");
    let header = format!("Bearer {token}");

    assert_eq!(
        handle(&ctx, &request(Some(&header), None), NOW, &NoReplay).unwrap_err(),
        UserInfoError::InvalidToken
    );
}

/// §1 §9: rotasyon penceresinde eski anahtarla imzalanmış token'lar hâlâ
/// dolaşımdadır. "0 adet 401" kriteri tam olarak burada sınanıyor.
#[test]
fn a_token_signed_by_a_retired_but_published_key_still_verifies() {
    let (old, _) = SigningKey::generate("old").expect("key");
    let (new, _) = SigningKey::generate("new").expect("key");
    let old = Arc::new(old);
    let new = Arc::new(new);

    let ctx = TenantContext {
        metadata: AuthorizationServerMetadata::for_issuer(ISSUER),
        active_key: Arc::clone(&new),
        published_keys: vec![Arc::clone(&old), new],
    };

    let token = sign(&claims(None), &old).expect("sign");
    let header = format!("Bearer {token}");

    assert!(
        handle(&ctx, &request(Some(&header), None), NOW, &NoReplay).is_ok(),
        "a token signed by a published-but-retired key must not 401"
    );
}

// --- `DPoP` bağlaması ------------------------------------------------------

/// `RFC` 9449 §7.1: bağlı bir token'ı kanıtsız kabul etmek, bağlamayı tamamen
/// anlamsız kılar — çalınmış token hâlâ kullanılabilir olurdu.
#[test]
fn a_bound_token_presented_as_bearer_is_refused() {
    let (ctx, key) = tenant();
    let (holder, _) = SigningKey::generate("holder").expect("key");
    let jkt = thumbprint(&holder);
    let token = sign(&claims(Some(Confirmation { jkt })), &key).expect("sign");
    let header = format!("Bearer {token}");

    assert_eq!(
        handle(&ctx, &request(Some(&header), None), NOW, &NoReplay).unwrap_err(),
        UserInfoError::MissingProof
    );
}

#[test]
fn a_bound_token_without_a_proof_header_is_refused() {
    let (ctx, key) = tenant();
    let (holder, _) = SigningKey::generate("holder").expect("key");
    let jkt = thumbprint(&holder);
    let token = sign(&claims(Some(Confirmation { jkt })), &key).expect("sign");
    let header = format!("DPoP {token}");

    assert_eq!(
        handle(&ctx, &request(Some(&header), None), NOW, &NoReplay).unwrap_err(),
        UserInfoError::MissingProof
    );
}

/// Bağlamanın TAMAMI bu karşılaştırmada: başka bir anahtarla imzalanmış geçerli
/// bir kanıt, token'ı kullanılabilir kılmamalı.
#[test]
fn a_proof_from_a_different_key_does_not_unlock_the_token() {
    let (ctx, key) = tenant();
    let (holder, _) = SigningKey::generate("holder").expect("key");
    let (attacker, _) = SigningKey::generate("attacker").expect("key");
    let token = sign(
        &claims(Some(Confirmation {
            jkt: thumbprint(&holder),
        })),
        &key,
    )
    .expect("sign");

    let header = format!("DPoP {token}");
    let ath = access_token_hash(&token);
    let proof = make_proof(
        &attacker,
        "GET",
        USERINFO,
        NOW.as_unix_seconds(),
        Some(&ath),
    );

    assert_eq!(
        handle(&ctx, &request(Some(&header), Some(&proof)), NOW, &NoReplay).unwrap_err(),
        UserInfoError::InvalidProof
    );
}

/// Doğru anahtar, doğru `htm`/`htu` ve doğru `ath` — kabul.
#[test]
fn a_matching_proof_unlocks_the_bound_token() {
    let (ctx, key) = tenant();
    let (holder, _) = SigningKey::generate("holder").expect("key");
    let token = sign(
        &claims(Some(Confirmation {
            jkt: thumbprint(&holder),
        })),
        &key,
    )
    .expect("sign");

    let header = format!("DPoP {token}");
    let ath = access_token_hash(&token);
    let proof = make_proof(&holder, "GET", USERINFO, NOW.as_unix_seconds(), Some(&ath));

    let info = handle(&ctx, &request(Some(&header), Some(&proof)), NOW, &NoReplay).expect("ok");
    assert_eq!(info.sub, SUBJECT);
}

/// `RFC` 9449 §4.3: `ath` olmadan, bir kaynak için üretilmiş kanıt BAŞKA bir
/// token'la eşleştirilebilirdi.
#[test]
fn a_proof_without_ath_is_refused() {
    let (ctx, key) = tenant();
    let (holder, _) = SigningKey::generate("holder").expect("key");
    let token = sign(
        &claims(Some(Confirmation {
            jkt: thumbprint(&holder),
        })),
        &key,
    )
    .expect("sign");

    let header = format!("DPoP {token}");
    let proof = make_proof(&holder, "GET", USERINFO, NOW.as_unix_seconds(), None);

    assert_eq!(
        handle(&ctx, &request(Some(&header), Some(&proof)), NOW, &NoReplay).unwrap_err(),
        UserInfoError::InvalidProof
    );
}

/// BAŞKA bir token'ın `ath`'ini taşıyan kanıt reddedilmeli.
#[test]
fn a_proof_bound_to_another_token_is_refused() {
    let (ctx, key) = tenant();
    let (holder, _) = SigningKey::generate("holder").expect("key");
    let token = sign(
        &claims(Some(Confirmation {
            jkt: thumbprint(&holder),
        })),
        &key,
    )
    .expect("sign");

    let header = format!("DPoP {token}");
    let wrong = access_token_hash("some-other-access-token");
    let proof = make_proof(
        &holder,
        "GET",
        USERINFO,
        NOW.as_unix_seconds(),
        Some(&wrong),
    );

    assert_eq!(
        handle(&ctx, &request(Some(&header), Some(&proof)), NOW, &NoReplay).unwrap_err(),
        UserInfoError::InvalidProof
    );
}

/// Başka bir endpoint için üretilmiş kanıt buraya taşınamamalı.
#[test]
fn a_proof_for_another_uri_is_refused() {
    let (ctx, key) = tenant();
    let (holder, _) = SigningKey::generate("holder").expect("key");
    let token = sign(
        &claims(Some(Confirmation {
            jkt: thumbprint(&holder),
        })),
        &key,
    )
    .expect("sign");

    let header = format!("DPoP {token}");
    let ath = access_token_hash(&token);
    let proof = make_proof(
        &holder,
        "GET",
        "https://acme.argus.test/token",
        NOW.as_unix_seconds(),
        Some(&ath),
    );

    assert_eq!(
        handle(&ctx, &request(Some(&header), Some(&proof)), NOW, &NoReplay).unwrap_err(),
        UserInfoError::InvalidProof
    );
}

/// Tekrar reddi gerçekten bağlı olmalı; kanıtın geri kalanı kusursuz olsa bile.
#[test]
fn a_replayed_proof_is_refused() {
    let (ctx, key) = tenant();
    let (holder, _) = SigningKey::generate("holder").expect("key");
    let token = sign(
        &claims(Some(Confirmation {
            jkt: thumbprint(&holder),
        })),
        &key,
    )
    .expect("sign");

    let header = format!("DPoP {token}");
    let ath = access_token_hash(&token);
    let proof = make_proof(&holder, "GET", USERINFO, NOW.as_unix_seconds(), Some(&ath));

    assert_eq!(
        handle(
            &ctx,
            &request(Some(&header), Some(&proof)),
            NOW,
            &EverythingSeen
        )
        .unwrap_err(),
        UserInfoError::InvalidProof
    );
}

/// Bağsız bir token'ı `DPoP` şemasıyla sunmak bir çelişkidir: istemci bağlama
/// olduğunu sanıyor ama yok.
#[test]
fn an_unbound_token_presented_as_dpop_is_refused() {
    let (ctx, key) = tenant();
    let token = sign(&claims(None), &key).expect("sign");
    let header = format!("DPoP {token}");

    assert_eq!(
        handle(&ctx, &request(Some(&header), None), NOW, &NoReplay).unwrap_err(),
        UserInfoError::InvalidToken
    );
}

/// `RFC` 6750 §3 ve `RFC` 9449 §7.1: her ret yolu istemciye NASIL kimlik
/// doğrulayacağını söylemeli; başlıksız 401 kör yeniden denemeye iter.
#[test]
fn every_refusal_carries_a_usable_challenge() {
    for err in [
        UserInfoError::MissingCredentials,
        UserInfoError::InvalidToken,
        UserInfoError::MissingProof,
        UserInfoError::InvalidProof,
    ] {
        let c = err.challenge();
        assert!(
            c.starts_with("Bearer") || c.starts_with("DPoP"),
            "unusable challenge: {c}"
        );
        assert_eq!(err.http_status(), 401);
    }
    // `DPoP` yollarında istemci hangi algoritmayı kullanacağını bilmeli.
    assert!(UserInfoError::MissingProof.challenge().contains("algs="));
}

// --- Yardımcılar -----------------------------------------------------------

fn thumbprint(key: &SigningKey) -> String {
    let c = key.public_components().expect("components");
    argus_proto::jwk_thumbprint(
        "P-256",
        &Base64UrlUnpadded::encode_string(&c.x),
        &Base64UrlUnpadded::encode_string(&c.y),
    )
}

fn access_token_hash(token: &str) -> String {
    use argus_core::pkce::Sha256 as _;
    Base64UrlUnpadded::encode_string(&AwsLcSha256.sha256(token.as_bytes()))
}

/// `at_hash` ile `ath` KARIŞTIRILMAMALI: biri digest'in sol yarısı (OIDC Core
/// §3.1.3.6), diğeri tamamı (`RFC` 9449 §4.3). Karıştırmak sessiz bir ret
/// üretir ve hata ayıklaması çok zordur.
#[test]
fn at_hash_and_ath_are_different_values() {
    let half = oidc::at_hash("a-token", &AwsLcSha256);
    let full = access_token_hash("a-token");
    assert_ne!(half, full);
    // 16 bayt 22 BASE64 karakteri doldurur ama son karakter yalnızca 4 gerçek
    // bit taşır; 32 baytlık kodlamada o karakter 6 bit taşıdığı için farklıdır.
    // Ortak önek tam 21 karakterdir — "biri diğerinin önekidir" demek yanlış.
    assert_eq!(&full[..21], &half[..21]);
    assert_eq!(half.len(), 22);
    assert_eq!(full.len(), 43);
}

// --- Gövdedeki token — RFC 6750 §2.2 --------------------------------------

/// OIDC Core §5.3.1 form-encoded gövdeyle token sunmaya izin verir;
/// `oidcc-userinfo-post-body` bunu sınar.
#[test]
fn a_token_in_the_request_body_is_accepted() {
    let (ctx, key) = tenant();
    let token = sign(&claims(None), &key).expect("sign");

    let info = handle(&ctx, &body_request(&token), NOW, &NoReplay).expect("accepted");
    assert_eq!(info.sub, SUBJECT);
}

/// `RFC` 6750 §2: *"Clients MUST NOT use more than one method to transmit the
/// token in each request."* İkisi birden geldiğinde hangisinin geçerli olduğunu
/// seçmek, sunucular arasında farklı davranış üretir.
#[test]
fn presenting_the_token_twice_is_refused() {
    let (ctx, key) = tenant();
    let token = sign(&claims(None), &key).expect("sign");
    let header = format!("Bearer {token}");

    let r = UserInfoRequest {
        authorization: Some(&header),
        form_access_token: Some(&token),
        dpop: None,
        method: "GET",
        uri: USERINFO,
    };
    assert_eq!(
        handle(&ctx, &r, NOW, &NoReplay).unwrap_err(),
        UserInfoError::InvalidToken
    );
}

/// Gövde yolunda şema yoktur; `DPoP` bağlı bir token bu yolla sunulamaz.
/// Geçebilseydi, bağlama gövde kullanılarak atlatılabilirdi.
#[test]
fn a_bound_token_cannot_slip_through_the_body_path() {
    let (ctx, key) = tenant();
    let (holder, _) = SigningKey::generate("holder").expect("key");
    let token = sign(
        &claims(Some(Confirmation {
            jkt: thumbprint(&holder),
        })),
        &key,
    )
    .expect("sign");

    assert_eq!(
        handle(&ctx, &body_request(&token), NOW, &NoReplay).unwrap_err(),
        UserInfoError::MissingProof
    );
}

/// Boş gövde bir kimlik bilgisi değildir.
#[test]
fn an_empty_body_token_is_not_credentials() {
    let (ctx, _) = tenant();
    for empty in ["", "   "] {
        assert_eq!(
            handle(&ctx, &body_request(empty), NOW, &NoReplay).unwrap_err(),
            UserInfoError::MissingCredentials
        );
    }
}
