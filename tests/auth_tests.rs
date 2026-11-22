use mediaflow_proxy_light::auth::encryption::{EncryptionHandler, ProxyData};
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_encryption_handler() {
    let handler = EncryptionHandler::new(b"test_password").unwrap();

    // Get current timestamp and add 1 hour to ensure it's not expired
    let future_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let proxy_data = ProxyData {
        destination: "https://example.com/video.mp4".to_string(),
        exp: Some(future_timestamp),
        ..Default::default()
    };

    let token = handler.encrypt(&proxy_data).unwrap();
    let decrypted = handler.decrypt(&token, None).unwrap();

    assert_eq!(decrypted.destination, proxy_data.destination);
    assert_eq!(decrypted.exp, proxy_data.exp);
}

#[tokio::test]
async fn test_token_expiration() {
    let handler = EncryptionHandler::new(b"test_password").unwrap();

    let proxy_data = ProxyData {
        destination: "https://example.com/video.mp4".to_string(),
        exp: Some(0), // Expired timestamp
        ..Default::default()
    };

    let token = handler.encrypt(&proxy_data).unwrap();
    let result = handler.decrypt(&token, None);

    assert!(result.is_err());
}
