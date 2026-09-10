#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use argus_crypto::password::Verdict;
use argus_http::hashing::{PasswordWork, WorkRefusal};

#[tokio::test]
async fn a_correct_password_verifies_through_the_bounded_runtime() {
    let work = PasswordWork::new(2, Duration::from_secs(10));
    let phc = work.hash("correct horse").await.expect("hash");

    assert_eq!(
        work.verify("correct horse", &phc).await.expect("verify"),
        Verdict::Correct
    );
    assert_eq!(
        work.verify("wrong horse", &phc).await.expect("verify"),
        Verdict::Wrong
    );
}

/// §9.5: kuyruk dolunca reddedilir, BEKLETİLMEZ. Bekleyen bir istek hâlâ bellek
/// ve bir bağlantı tutar.
#[tokio::test]
async fn work_beyond_the_ceiling_is_refused_rather_than_queued() {
    let work = Arc::new(PasswordWork::new(1, Duration::from_secs(10)));
    let phc = work.hash("a password").await.expect("hash");

    // Tek izin var; ilki onu alır ve koşarken ikincisi anında reddedilmeli.
    let busy = {
        let work = Arc::clone(&work);
        let phc = phc.clone();
        tokio::spawn(async move { work.verify("a password", &phc).await })
    };

    // İlk işin izni almasına fırsat ver.
    let mut refusal = None;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        if work.in_flight() == 0 {
            continue;
        }
        let started = Instant::now();
        refusal = Some(work.verify("a password", &phc).await);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "a refusal must be immediate, not a wait"
        );
        break;
    }

    let refusal = refusal.expect("the first hash never occupied the permit");
    assert_eq!(refusal.unwrap_err(), WorkRefusal::Saturated);

    assert_eq!(busy.await.expect("join").expect("verify"), Verdict::Correct);
}

#[tokio::test]
async fn the_permit_is_returned_when_the_work_finishes() {
    let work = PasswordWork::new(1, Duration::from_secs(10));
    let phc = work.hash("a password").await.expect("hash");

    for _ in 0..3 {
        assert_eq!(
            work.verify("a password", &phc).await.expect("verify"),
            Verdict::Correct
        );
        assert_eq!(work.in_flight(), 0, "the permit must come back every time");
    }
}

#[tokio::test]
async fn a_broken_stored_hash_is_not_a_correct_password() {
    let work = PasswordWork::new(2, Duration::from_secs(10));

    assert_eq!(
        work.verify("anything", "this is not a PHC string")
            .await
            .unwrap_err(),
        WorkRefusal::Failed
    );
}

/// Argon2 on milisaniyelerce CPU yakar. Blocking havuzuna gitmezse tek bir
/// login akışı sunucunun tamamını durdurur; bu test, hash koşarken async
/// çalışanının hâlâ ilerlediğini ölçer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hashing_does_not_stall_the_async_runtime() {
    let work = Arc::new(PasswordWork::new(2, Duration::from_secs(10)));
    let phc = work.hash("a password").await.expect("hash");

    let hashing = {
        let work = Arc::clone(&work);
        let phc = phc.clone();
        tokio::spawn(async move { work.verify("a password", &phc).await })
    };

    // Hash koşarken sıradan async işi ilerlemeli.
    let started = Instant::now();
    let mut ticks = 0_u32;
    while !hashing.is_finished() && started.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(1)).await;
        ticks += 1;
    }

    assert!(
        ticks > 1,
        "the runtime did not advance while a hash was running"
    );
    assert_eq!(
        hashing.await.expect("join").expect("verify"),
        Verdict::Correct
    );
}
