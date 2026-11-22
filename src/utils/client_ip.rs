use actix_web::dev::ServiceRequest;
use std::net::{IpAddr, SocketAddr};

/// Client address, honouring `Forwarded` / `X-Forwarded-For` so users behind
/// a reverse proxy aren't all collapsed into the proxy's own IP. IPv4-mapped
/// IPv6 addresses are reduced to plain IPv4.
pub fn client_ip(req: &ServiceRequest) -> Option<IpAddr> {
    let forwarded = req
        .connection_info()
        .realip_remote_addr()
        .and_then(parse_ip);
    forwarded
        .or_else(|| req.peer_addr().map(|a| a.ip()))
        .map(|ip| ip.to_canonical())
}

/// Parses `ip`, `ip:port`, `[v6]` or `[v6]:port` into a canonical address.
pub fn parse_ip(addr: &str) -> Option<IpAddr> {
    let addr = addr.trim();
    addr.parse::<IpAddr>()
        .ok()
        .or_else(|| addr.parse::<SocketAddr>().ok().map(|a| a.ip()))
        .or_else(|| {
            addr.strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|v6| v6.parse::<IpAddr>().ok())
        })
        .map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::parse_ip;

    #[test]
    fn parses_every_spelling_to_the_same_address() {
        let v4 = parse_ip("1.2.3.4");
        assert!(v4.is_some());
        for spelling in [
            "1.2.3.4:5678",
            "::ffff:1.2.3.4",
            "[::ffff:1.2.3.4]:80",
            " 1.2.3.4 ",
        ] {
            assert_eq!(parse_ip(spelling), v4, "{spelling}");
        }
        let v6 = parse_ip("2001:db8::1");
        for spelling in ["2001:db8:0::1", "[2001:db8::1]", "[2001:db8::1]:443"] {
            assert_eq!(parse_ip(spelling), v6, "{spelling}");
        }
        for invalid in ["", "unknown", "1.2.3", "_hidden"] {
            assert_eq!(parse_ip(invalid), None, "{invalid}");
        }
    }
}
