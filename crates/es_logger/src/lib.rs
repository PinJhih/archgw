use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, LogLevel};
use std::time::Duration;

// Base64 編碼函數
fn base64_encode(input: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    
    for chunk in input.chunks(3) {
        let mut buf = [0u8; 3];
        for (i, &byte) in chunk.iter().enumerate() {
            buf[i] = byte;
        }
        
        let b1 = (buf[0] >> 2) as usize;
        let b2 = (((buf[0] & 0x03) << 4) | (buf[1] >> 4)) as usize;
        let b3 = (((buf[1] & 0x0F) << 2) | (buf[2] >> 6)) as usize;
        let b4 = (buf[2] & 0x3F) as usize;
        
        result.push(CHARSET[b1] as char);
        result.push(CHARSET[b2] as char);
        result.push(if chunk.len() > 1 { CHARSET[b3] as char } else { '=' });
        result.push(if chunk.len() > 2 { CHARSET[b4] as char } else { '=' });
    }
    
    result
}

struct DebugRoot;

impl Context for DebugRoot {}

impl RootContext for DebugRoot {
    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        proxy_wasm::hostcalls::log(LogLevel::Info, "[debug_wasm] VM started").unwrap();
        true
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(DebugHttp::new()))
    }

    fn get_type(&self) -> Option<proxy_wasm::types::ContextType> {
        Some(proxy_wasm::types::ContextType::HttpContext)
    }
}

struct DebugHttp {
    token: Option<u32>,
}

impl DebugHttp {
    fn new() -> Self {
        Self { token: None }
    }
}

impl Context for DebugHttp {
    fn on_http_call_response(
        &mut self,
        token_id: u32,
        num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        proxy_wasm::hostcalls::log(
            LogLevel::Info,
            &format!(
                "[debug_wasm] HTTP Call Response! token={}, headers={}, body_size={}",
                token_id, num_headers, body_size
            ),
        )
        .unwrap();

        if let Some(expected) = self.token {
            if expected == token_id {
                proxy_wasm::hostcalls::log(LogLevel::Info, "[debug_wasm] ✅ Token matched!")
                    .unwrap();
            } else {
                proxy_wasm::hostcalls::log(LogLevel::Warn, "[debug_wasm] ⚠ Token mismatch!")
                    .unwrap();
            }
        }

        // 印出 headers
        for (name, value) in self.get_http_call_response_headers() {
            proxy_wasm::hostcalls::log(
                LogLevel::Info,
                &format!("[debug_wasm] header: {}={}", name, value),
            )
            .unwrap();
        }

        // 印出 body
        if body_size > 0 {
            if let Some(body) = self.get_http_call_response_body(0, body_size) {
                if let Ok(s) = std::str::from_utf8(&body) {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Info,
                        &format!("[debug_wasm] body: {}", s),
                    )
                    .unwrap();
                }
            }
        }

        // 關鍵修正：繼續處理原始請求
        self.resume_http_request();
    }
}

impl HttpContext for DebugHttp {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        proxy_wasm::hostcalls::log(
            LogLevel::Info,
            "[debug_wasm] on_http_request_headers called",
        )
        .unwrap();

        // ---- 收集原始請求資訊 ----
        let method = self.get_http_request_header(":method").unwrap_or_default();
        let path = self.get_http_request_header(":path").unwrap_or_default();
        let authority = self.get_http_request_header(":authority").unwrap_or_default();
        let scheme = self.get_http_request_header(":scheme").unwrap_or_else(|| "http".to_string());

        // 將所有 headers 打包成 Vec<(String, String)>
        let mut headers_map = vec![];
        for (k, v) in self.get_http_request_headers() {
            headers_map.push(format!("\"{}\": \"{}\"", k, v));
        }
        let headers_json = format!("{{{}}}", headers_map.join(", "));

        // 組成要傳給 Elasticsearch 的 JSON body
        let body_json = format!(
            r#"{{
                "method": "{}",
                "path": "{}",
                "authority": "{}",
                "scheme": "{}",
                "headers": {},
                "message": "hello from wasm",
                "timestamp": {}
            }}"#,
            method,
            path,
            authority,
            scheme,
            headers_json,
            chrono::Utc::now().timestamp_millis()
        );

        // ---- 設定 Basic Auth ----
        let auth_string = "elastic:Acs110134@ntcu";
        let auth_encoded = base64_encode(auth_string.as_bytes());
        let authorization = format!("Basic {}", auth_encoded);

        // ---- 準備要送給上游 ES 的 HTTP 請求 ----
        let content_length = body_json.len().to_string();
        let upstream_headers = vec![
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/demo/_doc"),
            (":authority", "es.coding-guy.space"),
            ("content-type", "application/json"),
            ("content-length", content_length.as_str()),
            ("authorization", authorization.as_str()),
        ];

        let body = Some(body_json.as_bytes().to_vec());
        let timeout = Duration::from_secs(5);

        match self.dispatch_http_call(
            "elasticsearch",
            upstream_headers,
            body.as_deref(),
            vec![],
            timeout,
        ) {
            Ok(token) => {
                self.token = Some(token);
                proxy_wasm::hostcalls::log(
                    LogLevel::Info,
                    &format!("[debug_wasm] ✓ Dispatched HTTP call, token={}", token),
                )
                .unwrap();
                return Action::Pause;
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("[debug_wasm] ❌ dispatch_http_call failed: {:?}", e),
                )
                .unwrap();
            }
        }

        Action::Continue
    }
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(DebugRoot)
    });
}}
