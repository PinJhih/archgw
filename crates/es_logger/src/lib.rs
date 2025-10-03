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
