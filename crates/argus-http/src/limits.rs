use std::time::Duration;

// §11 G.1. hyper'ın kendi dokümanı varsayılanları için "not considered stable"
// diyor; §11 bunun anlamını açıkça yazıyor: varsayılana güvenmek, bir minor
// upgrade'de sessizce DoS'a açılmaktır. Bu yüzden hepsi burada, tek yerde ve
// açıkça duruyor, ve başlangıçta log'lanıyor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_buf_size: usize,
    pub max_headers: usize,
    // ⚠️ §11 G.1: bunun çalışması için Builder'a bir Timer verilmek ZORUNDA.
    // hyper'ın dokümanı: "calling serve_connection panics if a timeout is
    // configured without a Timer". Timer'sız bir sunucu ya panikler ya da
    // slowloris'e açıktır; ikisi de kabul edilemez.
    pub header_read_timeout: Duration,

    pub max_concurrent_streams: u32,
    pub max_header_list_size: u32,
    // CVE-2023-44487 (Rapid Reset) ve RUSTSEC-2023-0034: saldırgan HEADERS ile
    // RST_STREAM çiftlerini akış hâlinde göndererek kabul kuyruğunu şişirir.
    pub max_pending_accept_reset_streams: usize,
    // RUSTSEC-2024-0003: geçersiz frame akışıyla üretilen reset'lerin sınırsız
    // kuyruklanması.
    pub max_local_error_reset_streams: usize,
    pub initial_stream_window_size: u32,
    pub initial_connection_window_size: u32,
    pub max_frame_size: u32,
    pub keep_alive_interval: Duration,
    pub keep_alive_timeout: Duration,

    // axum'un DefaultBodyLimit varsayılanı 2 MB. Bir IdP'nin en büyük meşru
    // gövdesi bir SAML yanıtı ya da bir SCIM toplu isteğidir.
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_buf_size: 64 * 1024,
            max_headers: 64,
            header_read_timeout: Duration::from_secs(10),

            max_concurrent_streams: 100,
            max_header_list_size: 16 * 1024,
            max_pending_accept_reset_streams: 20,
            max_local_error_reset_streams: 256,
            initial_stream_window_size: 256 * 1024,
            initial_connection_window_size: 1024 * 1024,
            max_frame_size: 16 * 1024,
            keep_alive_interval: Duration::from_secs(20),
            keep_alive_timeout: Duration::from_secs(20),

            max_body_bytes: 1024 * 1024,
        }
    }
}

impl Limits {
    // §11 G.1: "değerleri log'layın". Bir DoS soruşturmasında ilk sorulan şey
    // sunucunun hangi limitlerle koştuğudur.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "http1(buf={} headers={} header_read={}s) \
             http2(streams={} header_list={} pending_reset={} local_reset={} frame={}) \
             body={}",
            self.max_buf_size,
            self.max_headers,
            self.header_read_timeout.as_secs(),
            self.max_concurrent_streams,
            self.max_header_list_size,
            self.max_pending_accept_reset_streams,
            self.max_local_error_reset_streams,
            self.max_frame_size,
            self.max_body_bytes,
        )
    }

    /// Her iki dinleyici de bu yapıcıdan geçer. İki ayrı yapılandırma yolu,
    /// birinin unutulduğu bir dağıtım demektir.
    #[must_use]
    pub fn connection_builder(
        &self,
    ) -> hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor> {
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());

        builder
            .http1()
            .timer(hyper_util::rt::TokioTimer::new())
            .max_buf_size(self.max_buf_size)
            .header_read_timeout(Some(self.header_read_timeout))
            .keep_alive(true);

        builder
            .http2()
            .timer(hyper_util::rt::TokioTimer::new())
            .max_concurrent_streams(Some(self.max_concurrent_streams))
            .max_header_list_size(self.max_header_list_size)
            .max_pending_accept_reset_streams(Some(self.max_pending_accept_reset_streams))
            .max_local_error_reset_streams(Some(self.max_local_error_reset_streams))
            .initial_stream_window_size(Some(self.initial_stream_window_size))
            .initial_connection_window_size(Some(self.initial_connection_window_size))
            .max_frame_size(Some(self.max_frame_size))
            .keep_alive_interval(Some(self.keep_alive_interval))
            .keep_alive_timeout(self.keep_alive_timeout);

        builder
    }
}
