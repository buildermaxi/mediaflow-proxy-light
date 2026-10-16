//! Traffic meter middleware: the single place where media usage is recorded
//! (bytes served per stream kind, open streams per client, response
//! outcomes), so every media route is covered without per-handler bookkeeping.
//!
//! UI pages, health checks and the dashboard's own polling are not media
//! routes and don't count as usage.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use actix_web::{
    body::{BodySize, BoxBody, EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::header::USER_AGENT,
    middleware::Next,
    web::{self, Bytes},
    Error,
};

use super::{clients::player_from_user_agent, AppMetrics, StreamKind};

pub async fn traffic_meter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody, MeteredBody>>, Error> {
    let metrics = req
        .app_data::<web::Data<Arc<AppMetrics>>>()
        .map(|m| Arc::clone(m.get_ref()));
    let kind = StreamKind::from_path(req.path());
    let client = kind.and_then(|_| client_ip(&req)).map(|ip| {
        let user_agent = req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok());
        (ip, player_from_user_agent(user_agent.unwrap_or_default()))
    });

    let res = next.call(req).await;

    let (Some(metrics), Some(kind)) = (metrics, kind) else {
        return res.map(ServiceResponse::map_into_left_body);
    };
    let status = match &res {
        Ok(r) => r.status(),
        Err(e) => e.as_response_error().status_code(),
    };
    metrics.record_media_response(status);

    match (res?, client) {
        (res, Some((ip, player))) if status.is_success() => Ok(res
            .map_body(|_, body| MeteredBody::new(body, metrics, kind, ip, player))
            .map_into_right_body()),
        (res, _) => Ok(res.map_into_left_body()),
    }
}

/// Client address, honouring `Forwarded` / `X-Forwarded-For` so users behind
/// a reverse proxy aren't all collapsed into the proxy's own IP.
fn client_ip(req: &ServiceRequest) -> Option<IpAddr> {
    let forwarded = req.connection_info().realip_remote_addr().and_then(|addr| {
        addr.parse::<SocketAddr>()
            .map(|a| a.ip())
            .or_else(|_| addr.parse::<IpAddr>())
            .ok()
    });
    forwarded
        .or_else(|| req.peer_addr().map(|a| a.ip()))
        .map(|ip| ip.to_canonical())
}

/// Response body that counts bytes as actix sends them, and keeps the stream
/// registered as open until actix drops it (fully sent or client gone).
pub struct MeteredBody {
    inner: BoxBody,
    metrics: Arc<AppMetrics>,
    kind: StreamKind,
    client: IpAddr,
    client_bytes: Arc<AtomicU64>,
}

impl MeteredBody {
    fn new(
        body: impl MessageBody + 'static,
        metrics: Arc<AppMetrics>,
        kind: StreamKind,
        client: IpAddr,
        player: &'static str,
    ) -> Self {
        let client_bytes = metrics.stream_opened(client, kind, player);
        Self {
            inner: BoxBody::new(body),
            metrics,
            kind,
            client,
            client_bytes,
        }
    }
}

impl Drop for MeteredBody {
    fn drop(&mut self) {
        self.metrics.stream_closed(self.client, self.kind);
    }
}

impl MessageBody for MeteredBody {
    type Error = <BoxBody as MessageBody>::Error;

    fn size(&self) -> BodySize {
        self.inner.size()
    }

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        let this = self.get_mut();
        let chunk = Pin::new(&mut this.inner).poll_next(cx);
        if let Poll::Ready(Some(Ok(bytes))) = &chunk {
            let n = bytes.len() as u64;
            this.metrics.add_bytes(this.kind, n);
            this.client_bytes.fetch_add(n, Ordering::Relaxed);
        }
        chunk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{middleware::from_fn, test, App, HttpResponse};

    #[actix_web::test]
    async fn meters_media_routes_only() {
        let metrics = AppMetrics::new();
        let app = test::init_service(
            App::new()
                .wrap(from_fn(traffic_meter))
                .app_data(web::Data::new(Arc::clone(&metrics)))
                .route("/proxy/stream", web::get().to(|| async { "0123456789" }))
                .route("/proxy/hls/missing", web::get().to(HttpResponse::NotFound))
                .route("/health", web::get().to(|| async { "OK" })),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/proxy/stream")
            .insert_header(("x-forwarded-for", "203.0.113.7"))
            .insert_header(("user-agent", "TiviMate/5.1"))
            .to_request();
        let body = test::call_and_read_body(&app, req).await;
        assert_eq!(body.len(), 10);

        for uri in ["/health", "/proxy/hls/missing"] {
            let req = test::TestRequest::get()
                .uri(uri)
                .insert_header(("x-forwarded-for", "198.51.100.1"))
                .to_request();
            test::call_and_read_body(&app, req).await;
        }

        assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), 10);
        assert_eq!(metrics.bytes_served(StreamKind::Direct), 10);
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.open_streams(StreamKind::Direct), 0);
        assert_eq!(metrics.recent_outcomes(), (2, 1));

        let clients = metrics.clients();
        assert_eq!(clients.len(), 1);
        assert_eq!(
            (clients[0].ip.as_str(), clients[0].player, clients[0].bytes),
            ("203.0.113.x", "TiviMate", 10)
        );
    }
}
