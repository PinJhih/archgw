<<<<<<< Updated upstream
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use log::{info, warn, error};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};
use base64::engine::{Engine, general_purpose};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(ElasticsearchLoggerRoot::new())
    });
}}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct LogEntry {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    method: String,
    url: String,
    path: String,
    query_string: Option<String>,
    user_agent: Option<String>,
    host: Option<String>,
    x_forwarded_for: Option<String>,
    content_type: Option<String>,
    content_length: Option<u64>,
    request_id: Option<String>,
    status_code: Option<u32>,
    response_size: Option<u64>,
    processing_time_ms: Option<u64>,
    source: String,
    service: String,
}

struct ElasticsearchLoggerRoot {
    es_url: String,
    es_user: String,
    es_password: String,
    auth_header: String,
}

impl ElasticsearchLoggerRoot {
    fn new() -> Self {
        let es_user = "elastic";
        let es_password = "Acs110134@ntcu";
        let auth_string = format!("{}:{}", es_user, es_password);
        let auth_header = format!("Basic {}", general_purpose::STANDARD.encode(auth_string));
        
        Self {
            es_url: "https://es.coding-guy.space/".to_string(),
            es_user: es_user.to_string(),
            es_password: es_password.to_string(),
            auth_header,
        }
    }
}

impl Context for ElasticsearchLoggerRoot {}

impl RootContext for ElasticsearchLoggerRoot {
    fn on_vm_start(&mut self, _: usize) -> bool {
        info!("Elasticsearch Logger WASM filter started");
        info!("ES URL: {}", self.es_url);
        true
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(ElasticsearchLogger::new(
            context_id,
            self.es_url.clone(),
            self.auth_header.clone(),
        )))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct ElasticsearchLogger {
    context_id: u32,
    es_url: String,
    auth_header: String,
    request_start_time: Option<u64>,
    request_headers: HashMap<String, String>,
    response_headers: HashMap<String, String>,
    log_entry: LogEntry,
}

impl ElasticsearchLogger {
    fn new(context_id: u32, es_url: String, auth_header: String) -> Self {
        Self {
            context_id,
            es_url,
            auth_header,
            request_start_time: None,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            log_entry: LogEntry {
                timestamp: Self::get_current_timestamp(),
                method: String::new(),
                url: String::new(),
                path: String::new(),
                query_string: None,
                user_agent: None,
                host: None,
                x_forwarded_for: None,
                content_type: None,
                content_length: None,
                request_id: None,
                status_code: None,
                response_size: None,
                processing_time_ms: None,
                source: "archgw".to_string(),
                service: "proxy".to_string(),
            },
        }
    }

    fn get_current_timestamp() -> String {
        // 使用简单的数字时间戳，因为 WASM 环境中 SystemTime 处理复杂
        match proxy_wasm::hostcalls::get_current_time() {
            Ok(time) => {
                // 将 SystemTime 转换为 Unix 时间戳
                match time.duration_since(std::time::UNIX_EPOCH) {
                    Ok(duration) => {
                        let secs = duration.as_secs();
                        let millis = duration.subsec_millis();
                        format!("{}T{}Z", secs, millis)
                    }
                    Err(_) => "1970-01-01T00:00:00.000Z".to_string()
                }
            }
            Err(_) => "1970-01-01T00:00:00.000Z".to_string()
        }
    }

    fn extract_request_headers(&mut self) {
        self.request_headers.clear();
        
        // 获取常见的HTTP头部
        let header_names = vec![
            ":method", ":path", ":scheme", ":authority",
            "host", "user-agent", "content-type", "content-length",
            "x-forwarded-for", "x-request-id", "x-correlation-id", "x-trace-id"
        ];

        for header_name in header_names {
            if let Some(value) = self.get_http_request_header(header_name) {
                self.request_headers.insert(header_name.to_lowercase(), value);
            }
        }
    }

    fn extract_response_headers(&mut self) {
        self.response_headers.clear();
        
        // 获取响应头部
        let header_names = vec![":status", "content-length", "content-type"];
        
        for header_name in header_names {
            if let Some(value) = self.get_http_response_header(header_name) {
                self.response_headers.insert(header_name.to_lowercase(), value);
            }
        }
    }

    fn parse_url(&mut self) {
        // 从头部获取信息构建完整URL
        let scheme = if let Some(scheme) = self.request_headers.get(":scheme") {
            scheme.clone()
        } else {
            "https".to_string()
        };

        let host = if let Some(host) = self.request_headers.get(":authority") {
            host.clone()
        } else if let Some(host) = self.request_headers.get("host") {
            host.clone()
        } else {
            "unknown".to_string()
        };

        let path = if let Some(path) = self.request_headers.get(":path") {
            path.clone()
        } else {
            "/".to_string()
        };

        // 分离路径和查询字符串
        let parts: Vec<&str> = path.splitn(2, '?').collect();
        self.log_entry.path = parts[0].to_string();
        
        if parts.len() > 1 {
            self.log_entry.query_string = Some(parts[1].to_string());
        }

        // 构建完整URL
        self.log_entry.url = if let Some(ref query) = self.log_entry.query_string {
            format!("{}://{}{}?{}", scheme, host, self.log_entry.path, query)
        } else {
            format!("{}://{}{}", scheme, host, self.log_entry.path)
        };

        // 设置其他字段
        self.log_entry.host = Some(host);
    }

    fn populate_request_info(&mut self) {
        // HTTP方法
        if let Some(method) = self.request_headers.get(":method") {
            self.log_entry.method = method.clone();
        }

        // User-Agent
        if let Some(ua) = self.request_headers.get("user-agent") {
            self.log_entry.user_agent = Some(ua.clone());
        }

        // X-Forwarded-For
        if let Some(xff) = self.request_headers.get("x-forwarded-for") {
            self.log_entry.x_forwarded_for = Some(xff.clone());
        }

        // Content-Type
        if let Some(ct) = self.request_headers.get("content-type") {
            self.log_entry.content_type = Some(ct.clone());
        }

        // Content-Length
        if let Some(cl) = self.request_headers.get("content-length") {
            if let Ok(length) = cl.parse::<u64>() {
                self.log_entry.content_length = Some(length);
            }
        }

        // Request ID (从各种可能的头部获取)
        if let Some(req_id) = self.request_headers.get("x-request-id")
            .or_else(|| self.request_headers.get("x-correlation-id"))
            .or_else(|| self.request_headers.get("x-trace-id")) {
            self.log_entry.request_id = Some(req_id.clone());
        }
    }

    fn populate_response_info(&mut self) {
        // Content-Length from response
        if let Some(cl) = self.response_headers.get("content-length") {
            if let Ok(length) = cl.parse::<u64>() {
                self.log_entry.response_size = Some(length);
            }
        }
    }

    fn send_to_elasticsearch(&self) {
        // 使用简单的日期格式作为索引名
        let days_since_epoch = match proxy_wasm::hostcalls::get_current_time() {
            Ok(time) => {
                match time.duration_since(UNIX_EPOCH) {
                    Ok(duration) => duration.as_secs() / (24 * 60 * 60),
                    Err(_) => 0
                }
            }
            Err(_) => 0
        };
        let index_name = format!("archgw-logs-{}", days_since_epoch);
        
        let es_endpoint = format!("{}/{}/_doc", self.es_url, index_name);
        
        match serde_json::to_string(&self.log_entry) {
            Ok(json_body) => {
                info!("Sending log to ES: {}", json_body);
                
                let headers = vec![
                    ("Content-Type", "application/json"),
                    ("Authorization", &self.auth_header),
                ];

                // 发起HTTP请求到Elasticsearch
                match self.dispatch_http_call(
                    "elasticsearch",
                    headers,
                    Some(json_body.as_bytes()),
                    vec![],
                    Duration::from_secs(5),
                ) {
                    Ok(call_id) => {
                        info!("ES request dispatched with call_id: {}", call_id);
                    }
                    Err(e) => {
                        error!("Failed to dispatch ES request: {:?}", e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to serialize log entry: {}", e);
            }
        }
    }
}

impl Context for ElasticsearchLogger {
    fn on_http_call_response(&mut self, _token_id: u32, _num_headers: usize, _body_size: usize, _num_trailers: usize) {
        info!("Received ES response for context {}", self.context_id);
        
        // 检查响应状态
        if let Some(status) = self.get_http_call_response_header(":status") {
            if status.starts_with("2") {
                info!("Log successfully sent to Elasticsearch");
            } else {
                warn!("ES returned non-2xx status: {}", status);
            }
        }
    }
}

impl HttpContext for ElasticsearchLogger {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // 记录请求开始时间
        if let Ok(current_time) = proxy_wasm::hostcalls::get_current_time() {
            if let Ok(duration) = current_time.duration_since(UNIX_EPOCH) {
                self.request_start_time = Some(duration.as_millis() as u64);
            }
        }
        
        // 更新时间戳
        self.log_entry.timestamp = Self::get_current_timestamp();
        
        // 提取请求头
        self.extract_request_headers();
        
        // 解析URL和填充请求信息
        self.parse_url();
        self.populate_request_info();
        
        info!("Processing request: {} {}", self.log_entry.method, self.log_entry.url);
        
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // 计算处理时间
        if let Some(start_time) = self.request_start_time {
            if let Ok(current_time) = proxy_wasm::hostcalls::get_current_time() {
                if let Ok(duration) = current_time.duration_since(UNIX_EPOCH) {
                    let current_time_ms = duration.as_millis() as u64;
                    self.log_entry.processing_time_ms = Some(current_time_ms - start_time);
                }
            }
        }

        // 获取状态码
        if let Some(status) = self.get_http_response_header(":status") {
            if let Ok(status_code) = status.parse::<u32>() {
                self.log_entry.status_code = Some(status_code);
            }
        }

        self.extract_response_headers();
        self.populate_response_info();

        self.send_to_elasticsearch();
        
        Action::Continue
    }

    fn on_http_request_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        Action::Continue
    }

    fn on_http_response_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        Action::Continue
    }
}
=======
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
>>>>>>> Stashed changes
