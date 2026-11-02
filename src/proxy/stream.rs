use actix_web::web::Bytes;
use dashmap::DashMap;
use futures::{Stream, StreamExt};
use reqwest::{Client, Proxy, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};
use tracing::error;

use crate::{
    config::{ProxyConfig, ProxyRouteConfig, ProxyRouter},
    error::{AppError, AppResult},
    metrics::upstream::{ByteTally, UpstreamStats},
};

/// Body bytes an upstream task may read ahead of its client.
///
/// Bounds per-stream memory and the data fetched for nothing when a player
/// seeks or goes away, and carries back-pressure: once a slow client lets
/// the buffer fill up, the upstream task stops reading and TCP flow control
/// throttles the origin. Counted in bytes because chunk sizes vary a lot:
/// one TLS record (≤ 16 KiB) per chunk over HTTPS, but up to hyper's read
/// buffer (hundreds of KiB) from a fast plain-HTTP origin. A chunk larger
/// than the whole budget still goes through, alone.
const BODY_BUFFER_BYTES: usize = 256 * 1024;

/// Upper bound on queued chunks, so tiny chunks can't pile up either.
const BODY_CHANNEL_CAPACITY: usize = 64;

/// A body chunk on its way to the client, holding its share of the
/// read-ahead budget until the client-facing body hands it out.
type QueuedChunk = (AppResult<Bytes>, OwnedSemaphorePermit);

/// Name of the upstream runtime's threads (≤ 15 bytes so `top -H` shows it whole).
const UPSTREAM_THREAD_NAME: &str = "upstream-io";

/// The multi-threaded runtime that performs every upstream request.
///
/// actix-web pins each client connection to one worker thread for its whole
/// life, and actix-server hands connections to workers round-robin. Doing
/// the upstream work (TLS decryption, mostly) on that worker made a worker's
/// share of the CPU depend on which connections happened to land on it:
/// behind a reverse proxy that opens and closes keep-alive connections all
/// the time, concurrent streams regularly piled up on a single worker and
/// capped total throughput at one core while the others sat idle.
///
/// Running upstream I/O here instead lets Tokio's work-stealing scheduler
/// spread it over every core, whichever worker accepted the client. The
/// actix workers only relay the decrypted chunks, which is cheap.
fn upstream_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .thread_name(UPSTREAM_THREAD_NAME)
            .enable_all()
            .build()
            .expect("Failed to build the upstream I/O runtime")
    })
}

/// Spawn `fut` on the upstream runtime.
///
/// The returned handle aborts the task when dropped, so a cancelled caller
/// (client gone, handler timed out) never leaves an upstream request
/// running or a per-host permit held.
fn spawn_upstream<F, T>(fut: F) -> UpstreamTask<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    UpstreamTask(upstream_runtime().spawn(fut))
}

/// A task on the upstream runtime, aborted when dropped.
struct UpstreamTask<T>(JoinHandle<T>);

impl<T> Drop for UpstreamTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> Future for UpstreamTask<T> {
    type Output = AppResult<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map_err(|e| AppError::Internal(format!("Upstream task failed: {e}")))
    }
}

/// Client-facing body of a proxied stream, fed by its upstream task.
///
/// Dropping it (response fully sent, or client disconnected) aborts the
/// task, which closes the upstream connection and releases the per-host
/// permit, even if the origin is stalled mid-body.
pub struct UpstreamBody {
    chunks: mpsc::Receiver<QueuedChunk>,
    _task: UpstreamTask<()>,
}

impl Stream for UpstreamBody {
    type Item = AppResult<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Dropping the permit gives the chunk's bytes back to the read-ahead budget.
        self.chunks
            .poll_recv(cx)
            .map(|queued| queued.map(|(chunk, _permit)| chunk))
    }
}

#[derive(Clone)]
pub struct StreamManager {
    /// Client for upstream requests that match no transport route. Shared
    /// by every request: all of them run on the upstream runtime, so its
    /// connection pool and the tasks driving its connections live there.
    default_client: Client,
    /// Per-route client cache — keyed by a hash of the route config so we
    /// never create more than one client per unique (proxy_url, verify_ssl)
    /// combination, even under high concurrency.
    route_clients: Arc<DashMap<String, Client>>,
    /// Per-host concurrency limiter — caps simultaneous in-flight upstream
    /// requests to the same origin.  Forces HTTP/1.1 keep-alive reuse when
    /// many requests target the same host, which dramatically reduces
    /// per-request latency for bursts to a single upstream.
    per_host_semaphores: Arc<DashMap<String, Arc<Semaphore>>>,
    config: Arc<ProxyConfig>,
    proxy_router: Arc<ProxyRouter>,
    /// Per-host health for the dashboard; `None` when not wired up.
    upstream_stats: Option<Arc<UpstreamStats>>,
}

impl StreamManager {
    pub fn new(config: ProxyConfig) -> Self {
        // Start the upstream runtime now, so a failure to spawn its threads
        // stops the server at startup rather than on the first request.
        upstream_runtime();
        let proxy_router = ProxyRouter::from_config(&config);
        let default_client = Self::create_default_client(&config, &proxy_router);

        Self {
            default_client,
            route_clients: Arc::new(DashMap::new()),
            per_host_semaphores: Arc::new(DashMap::new()),
            config: Arc::new(config),
            proxy_router: Arc::new(proxy_router),
            upstream_stats: None,
        }
    }

    /// Report per-host time-to-first-byte, failures and body bytes to `stats`.
    pub fn with_upstream_stats(mut self, stats: Arc<UpstreamStats>) -> Self {
        self.upstream_stats = Some(stats);
        self
    }

    fn record_upstream<E>(
        &self,
        url: &str,
        started: Instant,
        sent: &Result<Result<Response, reqwest::Error>, E>,
    ) -> ByteTally {
        let Some(stats) = &self.upstream_stats else {
            return ByteTally::default();
        };
        match sent {
            Ok(Ok(response)) => {
                let status = response.status();
                let failed = status.is_client_error() || status.is_server_error();
                stats.record_response(url, started.elapsed(), failed)
            }
            _ => {
                stats.record_unreachable(url);
                ByteTally::default()
            }
        }
    }

    /// Get or create the semaphore limiting concurrent in-flight upstream
    /// requests to a given host.  Returns `None` when the limiter is disabled
    /// (config value 0).
    fn host_semaphore(&self, host: &str) -> Option<Arc<Semaphore>> {
        if self.config.max_concurrent_per_host == 0 {
            return None;
        }
        // `entry` locks the shard, so two first requests to a host can't each
        // create (and use) their own semaphore.
        let sem = self
            .per_host_semaphores
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.config.max_concurrent_per_host)))
            .clone();
        Some(sem)
    }

    /// Build the default shared client used when no transport route matches.
    ///
    /// Connection pooling is ENABLED (up to 100 idle connections per host).
    /// This is the most important performance lever: re-using TCP connections
    /// eliminates per-request handshake latency and dramatically reduces
    /// overhead at high concurrency.
    fn create_default_client(config: &ProxyConfig, proxy_router: &ProxyRouter) -> Client {
        let follow_redirects = config.follow_redirects;
        let mut builder = Client::builder()
            // TCP connect timeout (handshake only — does NOT include pool-acquisition wait).
            .connect_timeout(Duration::from_secs(config.connect_timeout))
            // NO .timeout() here — a client-level timeout applies to the full request
            // lifecycle including body streaming, which would kill live streams after
            // connect_timeout × request_timeout_factor seconds.  Instead, a timeout is
            // applied only around send() in make_request_raw (headers phase), so that
            // stalled connections are detected without ever capping a live body stream.
            .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout))
            // Cap idle connections retained per upstream host.
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            // Use a browser-like User-Agent so CDNs (e.g. Akamai) don't block the request.
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
            // Disable auto-decompression so we stream the raw bytes unchanged.
            .no_brotli()
            .no_deflate()
            .no_gzip()
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if follow_redirects {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }));

        if let Some(default_proxy) = proxy_router.default_proxy() {
            if let Ok(proxy) = Proxy::all(default_proxy) {
                builder = builder.proxy(proxy);
            }
        }

        builder.build().expect("Failed to create HTTP client")
    }

    /// Build a client for a specific transport route config.
    ///
    /// Called at most once per unique route config (results are cached in
    /// `self.route_clients`).  Never called in the common case where
    /// `all_proxy = false` and no transport route patterns match.
    fn build_route_client(
        config: &ProxyConfig,
        route_config: &ProxyRouteConfig,
    ) -> AppResult<Client> {
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(config.connect_timeout))
            // No client-level timeout — see create_default_client for rationale.
            .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout))
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .no_brotli()
            .no_deflate()
            .no_gzip()
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

        if route_config.proxy {
            if let Some(proxy_url) = route_config.proxy_url.as_ref() {
                match Proxy::all(proxy_url) {
                    Ok(proxy) => {
                        tracing::info!("Building route client with proxy {}", proxy_url);
                        builder = builder.proxy(proxy);
                    }
                    Err(e) => {
                        error!("Failed to create proxy for route: {}", e);
                        return Err(AppError::Internal(format!(
                            "Failed to create route proxy client: {}",
                            e
                        )));
                    }
                }
            }
        }

        if !route_config.verify_ssl {
            tracing::warn!("SSL verification disabled for route");
            builder = builder.danger_accept_invalid_certs(true);
        }

        builder
            .build()
            .map_err(|e| AppError::Internal(format!("Failed to build route client: {}", e)))
    }

    /// Extract the host (and port) from a URL for per-host limiting.
    fn url_host_key(url: &str) -> String {
        url::Url::parse(url)
            .ok()
            .and_then(|u| {
                u.host_str().map(|h| match u.port() {
                    Some(p) => format!("{}:{}", h, p),
                    None => h.to_string(),
                })
            })
            .unwrap_or_else(|| "_unknown_".to_string())
    }

    /// Send a request upstream and return the response for the caller to
    /// consume (e.g. `.json()`).
    ///
    /// The request runs on the upstream runtime. The per-host permit covers
    /// connect + response headers and is released when the response is
    /// returned; streaming callers should use `create_stream`, which holds
    /// it until the body is done.
    pub async fn make_request(
        &self,
        url: String,
        headers: reqwest::header::HeaderMap,
    ) -> AppResult<Response> {
        let this = self.clone();
        spawn_upstream(async move {
            let _permit = this.acquire_host_permit(&url).await?;
            this.make_request_raw(url, headers)
                .await
                .map(|(response, _)| response)
        })
        .await?
    }

    /// Acquire a permit from the per-host semaphore.  Returns an owned permit
    /// that can be carried by a streaming body so the slot stays reserved
    /// until the body is fully consumed (or the client disconnects).
    ///
    /// Returns `Ok(None)` when the limiter is disabled (`max_concurrent_per_host = 0`).
    pub async fn acquire_host_permit(
        &self,
        url: &str,
    ) -> AppResult<Option<tokio::sync::OwnedSemaphorePermit>> {
        let host = Self::url_host_key(url);
        let Some(sem) = self.host_semaphore(&host) else {
            return Ok(None);
        };
        sem.acquire_owned()
            .await
            .map(Some)
            .map_err(|_| AppError::Proxy("Upstream semaphore closed".to_string()))
    }

    /// Inner request without the per-host limiter — used when the caller
    /// has already acquired a permit and wants to carry it with the body.
    /// The returned tally counts body bytes against the upstream host.
    ///
    /// Must run on the upstream runtime (see `spawn_upstream`): the client
    /// spawns the task driving a new connection on the current runtime.
    async fn make_request_raw(
        &self,
        url: String,
        headers: reqwest::header::HeaderMap,
    ) -> AppResult<(Response, ByteTally)> {
        let proxy_config = self.proxy_router.get_proxy_config(&url);

        let client = if let Some(route_config) = proxy_config {
            let cache_key = format!(
                "{}|{}|{}",
                route_config.proxy,
                route_config.proxy_url.as_deref().unwrap_or(""),
                route_config.verify_ssl,
            );

            if let Some(cached) = self.route_clients.get(&cache_key) {
                cached.clone()
            } else {
                let new_client = Self::build_route_client(&self.config, &route_config)?;
                self.route_clients.insert(cache_key, new_client.clone());
                new_client
            }
        } else {
            self.default_client.clone()
        };

        // Apply timeout only to the connection + response-headers phase.
        // Once send() resolves the header timeout has been satisfied; body
        // streaming (create_stream) continues without a deadline so that
        // live MPEG-TS or other indefinite streams are never cut off.
        let header_timeout =
            Duration::from_secs(self.config.connect_timeout * self.config.request_timeout_factor);
        let started = Instant::now();
        let sent = timeout(header_timeout, client.get(&url).headers(headers).send()).await;
        let tally = self.record_upstream(&url, started, &sent);
        let response = sent
            .map_err(|_| {
                AppError::Proxy(format!(
                    "Request timed out after {} s waiting for response headers from {url}",
                    header_timeout.as_secs()
                ))
            })?
            .map_err(|e| AppError::Proxy(format!("Failed to connect to upstream: {}", e)))?;

        // Accept 2xx (including 206 Partial Content) and 3xx redirects that reqwest follows.
        // Reject only genuine error status codes (4xx, 5xx).
        if response.status().is_client_error() || response.status().is_server_error() {
            return Err(AppError::Upstream(format!(
                "Upstream returned error status: {}",
                response.status()
            )));
        }

        Ok((response, tally))
    }

    /// Open `url` upstream and return its status, headers and (unless
    /// `is_head`) a body stream.
    ///
    /// Everything upstream (connect, TLS, reading the body) happens in a task
    /// on the upstream runtime, which forwards body chunks through a channel,
    /// at most `BODY_BUFFER_BYTES` ahead of the client. The task holds the
    /// per-host permit for the whole transfer:
    /// this caps parallel in-flight upstream connections per host at
    /// `config.max_concurrent_per_host`, forcing HTTP/1.1 keep-alive reuse
    /// when many requests target the same origin. Dropping the returned body,
    /// or this future before it resolves, aborts the task.
    pub async fn create_stream(
        &self,
        url: String,
        headers: reqwest::header::HeaderMap,
        is_head: bool,
    ) -> AppResult<(
        reqwest::StatusCode,
        reqwest::header::HeaderMap,
        Option<UpstreamBody>,
    )> {
        let (head_tx, head_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::channel(BODY_CHANNEL_CAPACITY);
        let this = self.clone();

        let task = spawn_upstream(async move {
            let opened = async {
                let permit = this.acquire_host_permit(&url).await?;
                let (response, tally) = this.make_request_raw(url, headers).await?;
                Ok::<_, AppError>((permit, response, tally))
            };
            let (permit, response, tally) = match opened.await {
                Ok(opened) => opened,
                Err(e) => {
                    let _ = head_tx.send(Err(e));
                    return;
                }
            };

            let head = (response.status(), response.headers().clone());
            if head_tx.send(Ok(head)).is_err() || is_head {
                return;
            }

            let read_ahead = Arc::new(Semaphore::new(BODY_BUFFER_BYTES));
            let mut chunks = response.bytes_stream();
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk
                    .inspect(|bytes| tally.add(bytes.len()))
                    .map_err(|e| AppError::Proxy(format!("Stream error: {}", e)));
                let failed = chunk.is_err();
                // Bounded by the budget itself, so the cast can't truncate.
                let size = chunk.as_ref().map_or(0, Bytes::len).min(BODY_BUFFER_BYTES) as u32;
                let Ok(room) = read_ahead.clone().acquire_many_owned(size).await else {
                    break;
                };
                if body_tx.send((chunk, room)).await.is_err() || failed {
                    break;
                }
            }
            drop(permit);
        });

        let (status, response_headers) = head_rx.await.map_err(|_| {
            AppError::Internal("Upstream task ended before the response headers".to_string())
        })??;

        let body = (!is_head).then(|| UpstreamBody {
            chunks: body_rx,
            _task: task,
        });
        Ok((status, response_headers, body))
    }

    /// Wrap a stream so that errors are logged with the byte offset.
    ///
    /// Not async — avoids a state-machine allocation.
    /// Does NOT Box::pin — the caller's ResponseStream::new() handles that.
    pub fn stream_with_progress<S>(&self, stream: S) -> impl Stream<Item = Result<Bytes, AppError>>
    where
        S: Stream<Item = Result<Bytes, AppError>>,
    {
        let mut total_bytes = 0usize;

        stream.map(move |chunk| match chunk {
            Ok(bytes) => {
                total_bytes += bytes.len();
                Ok(bytes)
            }
            Err(e) => {
                error!("Streaming error after {} bytes: {}", total_bytes, e);
                Err(e)
            }
        })
    }
}

pub struct ResponseStream<S> {
    inner: Pin<Box<S>>,
}

impl<S> ResponseStream<S>
where
    S: Stream<Item = Result<Bytes, AppError>>,
{
    pub fn new(stream: S) -> Self {
        Self {
            inner: Box::pin(stream),
        }
    }
}

impl<S> Stream for ResponseStream<S>
where
    S: Stream<Item = Result<Bytes, AppError>>,
{
    type Item = Result<Bytes, AppError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const PIECE: usize = 16 * 1024;

    /// Minimal HTTP/1.1 origin, one request per connection. Answers each
    /// request with a body of `len` bytes, written in 16 KiB pieces with
    /// `pause` between them. Special paths: `/hang` gets no answer at all,
    /// `/missing` a 404, and `/truncated` loses its connection after the
    /// first piece.
    async fn origin(len: usize, pause: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let request = String::from_utf8_lossy(&request);
                    if request.contains(" /hang ") {
                        std::future::pending::<()>().await;
                    }
                    let status = if request.contains(" /missing ") {
                        "404 Not Found"
                    } else {
                        "200 OK"
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n"
                    );
                    if socket.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let piece = [b'x'; PIECE];
                    let mut sent = 0;
                    while sent < len {
                        let n = PIECE.min(len - sent);
                        if socket.write_all(&piece[..n]).await.is_err()
                            || request.contains(" /truncated ")
                        {
                            return;
                        }
                        sent += n;
                        tokio::time::sleep(pause).await;
                    }
                });
            }
        });
        base
    }

    /// Built by hand rather than from the environment, so proxy or config
    /// variables set on the machine running the tests can't change them.
    fn manager(max_concurrent_per_host: usize) -> StreamManager {
        StreamManager::new(ProxyConfig {
            connect_timeout: 5,
            follow_redirects: true,
            proxy_url: None,
            all_proxy: false,
            transport_routes: Default::default(),
            request_timeout_factor: 8,
            max_concurrent_per_host,
            pool_idle_timeout: 90,
            pool_max_idle_per_host: 100,
        })
    }

    /// Free per-host slots for the origin at `base`.
    fn free_slots(manager: &StreamManager, base: &str) -> usize {
        manager
            .host_semaphore(&StreamManager::url_host_key(base))
            .unwrap()
            .available_permits()
    }

    /// Poll `fut` until the origin at `base` has no free slot left, i.e. the
    /// request is in flight upstream, then drop it.
    async fn cancel_once_in_flight<F: Future>(fut: F, manager: &StreamManager, base: &str) {
        tokio::pin!(fut);
        let deadline = Instant::now() + Duration::from_secs(5);
        while free_slots(manager, base) > 0 {
            assert!(
                Instant::now() < deadline,
                "request never took the host slot"
            );
            tokio::select! {
                _ = &mut fut => panic!("request was expected to hang"),
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    }

    async fn body_len(body: UpstreamBody) -> usize {
        body.fold(
            0,
            |total, chunk| async move { total + chunk.unwrap().len() },
        )
        .await
    }

    async fn open(manager: &StreamManager, url: String) -> UpstreamBody {
        let (_, _, body) = timeout(
            Duration::from_secs(5),
            manager.create_stream(url, HeaderMap::new(), false),
        )
        .await
        .expect("host slot was not released in time")
        .unwrap();
        body.unwrap()
    }

    #[tokio::test]
    async fn upstream_work_runs_on_the_upstream_runtime() {
        let thread = spawn_upstream(async { std::thread::current().name().map(String::from) })
            .await
            .unwrap();
        assert_eq!(thread.as_deref(), Some(UPSTREAM_THREAD_NAME));
    }

    #[tokio::test]
    async fn streams_the_whole_body() {
        let base = origin(1_000_000, Duration::ZERO).await;
        let (status, headers, body) = manager(10)
            .create_stream(format!("{base}/file.mkv"), HeaderMap::new(), false)
            .await
            .unwrap();

        assert_eq!(status, reqwest::StatusCode::OK);
        assert_eq!(headers["content-length"], "1000000");
        assert_eq!(body_len(body.unwrap()).await, 1_000_000);
    }

    #[tokio::test]
    async fn upstream_error_status_is_reported() {
        let base = origin(10, Duration::ZERO).await;
        let result = manager(10)
            .create_stream(format!("{base}/missing"), HeaderMap::new(), false)
            .await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
    }

    #[tokio::test]
    async fn upstream_failure_mid_body_ends_the_stream_with_an_error() {
        let base = origin(10 * PIECE, Duration::ZERO).await;
        let body = open(&manager(10), format!("{base}/truncated")).await;

        let items: Vec<_> = body.collect().await;
        assert!(matches!(items.last(), Some(Err(AppError::Proxy(_)))));
        let received: usize = items.iter().flatten().map(Bytes::len).sum();
        assert!(received < 10 * PIECE);
    }

    #[tokio::test]
    async fn read_ahead_is_bounded_in_bytes() {
        let base = origin(64 * 1024 * 1024, Duration::ZERO).await;
        let mut body = open(&manager(10), format!("{base}/file.mkv")).await;

        // Let the upstream task fill its buffer, then take what it queued,
        // keeping each chunk's share of the budget so nothing is refilled.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut queued = Vec::new();
        while let Ok(item) = body.chunks.try_recv() {
            queued.push(item);
        }
        let bytes: usize = queued
            .iter()
            .map(|(chunk, _)| chunk.as_ref().unwrap().len())
            .sum();

        assert!(!queued.is_empty(), "upstream task read nothing ahead");
        // A chunk bigger than the whole budget is let through alone.
        assert!(
            bytes <= BODY_BUFFER_BYTES || queued.len() == 1,
            "{bytes} bytes in {} chunks read ahead",
            queued.len()
        );
    }

    #[tokio::test]
    async fn head_request_has_no_body_and_frees_the_host_slot() {
        let base = origin(1_000, Duration::ZERO).await;
        let manager = manager(1);

        let (status, _, body) = manager
            .create_stream(format!("{base}/file.mkv"), HeaderMap::new(), true)
            .await
            .unwrap();
        assert_eq!(status, reqwest::StatusCode::OK);
        assert!(body.is_none());

        let next = open(&manager, format!("{base}/file.mkv")).await;
        assert_eq!(body_len(next).await, 1_000);
    }

    #[tokio::test]
    async fn host_slot_is_held_until_the_body_is_dropped() {
        let base = origin(100 * PIECE, Duration::from_millis(20)).await;
        let manager = manager(1);

        let mut body = open(&manager, format!("{base}/file.mkv")).await;
        assert!(body.next().await.unwrap().is_ok());
        assert_eq!(free_slots(&manager, &base), 0);
        let second = timeout(
            Duration::from_millis(300),
            manager.create_stream(format!("{base}/file.mkv"), HeaderMap::new(), false),
        )
        .await;
        assert!(
            second.is_err(),
            "second stream got a slot while the first was open"
        );

        drop(body);
        open(&manager, format!("{base}/file.mkv")).await;
    }

    #[tokio::test]
    async fn dropping_the_body_frees_the_host_slot_even_if_upstream_stalls() {
        // One piece, then the origin stalls for an hour mid-body: only
        // aborting the upstream task can release the permit.
        let base = origin(10 * PIECE, Duration::from_secs(3600)).await;
        let manager = manager(1);

        let mut body = open(&manager, format!("{base}/file.mkv")).await;
        assert!(body.next().await.unwrap().is_ok());
        drop(body);

        open(&manager, format!("{base}/file.mkv")).await;
    }

    #[tokio::test]
    async fn cancelled_stream_request_frees_the_host_slot() {
        let base = origin(1_000, Duration::ZERO).await;
        let manager = manager(1);

        let hung = manager.create_stream(format!("{base}/hang"), HeaderMap::new(), false);
        cancel_once_in_flight(hung, &manager, &base).await;

        assert_eq!(
            body_len(open(&manager, format!("{base}/file.mkv")).await).await,
            1_000
        );
    }

    #[tokio::test]
    async fn cancelled_plain_request_frees_the_host_slot() {
        let base = origin(1_000, Duration::ZERO).await;
        let manager = manager(1);

        let hung = manager.make_request(format!("{base}/hang"), HeaderMap::new());
        cancel_once_in_flight(hung, &manager, &base).await;

        let response = timeout(
            Duration::from_secs(5),
            manager.make_request(format!("{base}/file.mkv"), HeaderMap::new()),
        )
        .await
        .expect("host slot was not released in time")
        .unwrap();
        assert_eq!(response.bytes().await.unwrap().len(), 1_000);
    }
}
