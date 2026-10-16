//! Traffic meter middleware: the single place where bytes served and open
//! streams are recorded, so every media route is covered without per-handler
//! bookkeeping.
//!
//! Only successful responses on media routes are metered — UI pages, health
//! checks and the dashboard's own polling don't count as "usage".

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use actix_web::{
    body::{BodySize, BoxBody, EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web::{self, Bytes},
    Error,
};

use super::AppMetrics;
use crate::auth::middleware::is_xtream_route;

pub async fn traffic_meter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody, MeteredBody>>, Error> {
    let metrics = req
        .app_data::<web::Data<Arc<AppMetrics>>>()
        .map(|m| Arc::clone(m.get_ref()));
    let client = if is_media_path(req.path()) {
        client_ip(&req)
    } else {
        None
    };

    let res = next.call(req).await?;

    match (metrics, client) {
        (Some(metrics), Some(client)) if res.status().is_success() => Ok(res
            .map_body(|_, body| MeteredBody::new(body, metrics, client))
            .map_into_right_body()),
        _ => Ok(res.map_into_left_body()),
    }
}

fn is_media_path(path: &str) -> bool {
    path.starts_with("/proxy/") || path.starts_with("/extractor/") || is_xtream_route(path)
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
    forwarded.or_else(|| req.peer_addr().map(|a| a.ip()))
}

/// Response body that counts bytes as actix sends them, and keeps the stream
/// registered as open until actix drops it (fully sent or client gone).
pub struct MeteredBody {
    inner: BoxBody,
    metrics: Arc<AppMetrics>,
    client: IpAddr,
}

impl MeteredBody {
    fn new(body: impl MessageBody + 'static, metrics: Arc<AppMetrics>, client: IpAddr) -> Self {
        metrics.stream_opened(client);
        Self {
            inner: BoxBody::new(body),
            metrics,
            client,
        }
    }
}

impl Drop for MeteredBody {
    fn drop(&mut self) {
        self.metrics.stream_closed(self.client);
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
            this.metrics.add_bytes_out(bytes.len() as u64);
        }
        chunk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{middleware::from_fn, test, App, HttpResponse};
    use std::sync::atomic::Ordering;

    #[actix_web::test]
    async fn meters_media_routes_only() {
        let metrics = AppMetrics::new();
        let app = test::init_service(
            App::new()
                .wrap(from_fn(traffic_meter))
                .app_data(web::Data::new(Arc::clone(&metrics)))
                .route("/proxy/stream", web::get().to(|| async { "0123456789" }))
                .route("/proxy/missing", web::get().to(HttpResponse::NotFound))
                .route("/health", web::get().to(|| async { "OK" })),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/proxy/stream")
            .insert_header(("x-forwarded-for", "203.0.113.7"))
            .to_request();
        let body = test::call_and_read_body(&app, req).await;
        assert_eq!(body.len(), 10);

        for uri in ["/health", "/proxy/missing"] {
            let req = test::TestRequest::get()
                .uri(uri)
                .insert_header(("x-forwarded-for", "198.51.100.1"))
                .to_request();
            test::call_and_read_body(&app, req).await;
        }

        assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), 10);
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.active_clients(), 1);
    }
}
