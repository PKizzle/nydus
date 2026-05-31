// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Prometheus text exposition adapter for existing nydusd metrics endpoints.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use dbs_uhttp::{Method, Request};
use serde_json::Value;

use crate::http::{
    ApiError, ApiRequest, ApiResponse, ApiResponsePayload, DaemonErrorKind, HttpError,
    MetricsError, MetricsErrorKind,
};
use crate::http_handler::{
    error_response, extract_query_part, success_response, translate_status_code, EndpointHandler,
    HttpResult,
};

/// Non-versioned Prometheus scrape endpoint.
pub(crate) const PROMETHEUS_METRICS_PATH: &str = "/metrics";

/// Convert existing JSON metric endpoints into Prometheus text exposition.
pub struct PrometheusMetricsHandler {}

impl EndpointHandler for PrometheusMetricsHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let include_files = query_bool(req, "include_files");
                let include_patterns = query_bool(req, "include_patterns");
                match render_prometheus(kicker, id, include_files, include_patterns) {
                    Ok(body) => Ok(success_response(Some(body))),
                    Err(e) => {
                        let status = translate_status_code(&e);
                        Ok(error_response(HttpError::PrometheusMetrics(e), status))
                    }
                }
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

fn query_bool(req: &Request, key: &str) -> bool {
    extract_query_part(req, key).is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"))
}

fn render_prometheus(
    kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    id: Option<String>,
    include_files: bool,
    include_patterns: bool,
) -> Result<String, ApiError> {
    let mut renderer = PrometheusRenderer::default();

    renderer.append_source_response(
        "nydusd_fs",
        "Filesystem global metrics exported by the existing nydusd /api/v1/metrics endpoint.",
        kicker(ApiRequest::ExportFsGlobalMetrics(id.clone())),
    )?;
    renderer.append_source_response(
        "nydusd_backend",
        "Storage backend metrics exported by the existing nydusd /api/v1/metrics/backend endpoint.",
        kicker(ApiRequest::ExportBackendMetrics(id.clone())),
    )?;
    renderer.append_source_response(
        "nydusd_blobcache",
        "Blob cache metrics exported by the existing nydusd /api/v1/metrics/blobcache endpoint.",
        kicker(ApiRequest::ExportBlobcacheMetrics(id.clone())),
    )?;
    renderer.append_source_response(
        "nydusd_inflight",
        "Inflight filesystem request metrics exported by the existing nydusd /api/v1/metrics/inflight endpoint.",
        kicker(ApiRequest::ExportFsInflightMetrics),
    )?;

    if include_files {
        renderer.append_source_response(
            "nydusd_file",
            "Per-file filesystem metrics exported by the existing nydusd /api/v1/metrics/files endpoint.",
            kicker(ApiRequest::ExportFsFilesMetrics(id.clone(), false)),
        )?;
    }

    if include_patterns {
        renderer.append_source_response(
            "nydusd_access_pattern",
            "File access pattern metrics exported by the existing nydusd /api/v1/metrics/pattern endpoint.",
            kicker(ApiRequest::ExportFsAccessPatterns(id)),
        )?;
    }

    Ok(renderer.finish())
}

#[derive(Default)]
struct PrometheusRenderer {
    out: String,
    emitted_descriptors: BTreeSet<String>,
}

impl PrometheusRenderer {
    fn append_source_response(
        &mut self,
        source: &str,
        help: &str,
        response: ApiResponse,
    ) -> Result<(), ApiError> {
        let Some(json) = response_payload_body(source, response)? else {
            return Ok(());
        };
        let value = serde_json::from_str::<Value>(&json)
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Stats(MetricsError::Serialize(e))))?;
        let mut labels = Vec::new();
        self.append_json_value(source, help, &mut labels, &value);
        Ok(())
    }

    fn append_json_value(
        &mut self,
        metric_prefix: &str,
        help: &str,
        labels: &mut Vec<(String, String)>,
        value: &Value,
    ) {
        match value {
            Value::Null | Value::String(_) => {}
            Value::Bool(v) => self.push_metric(metric_prefix, help, labels, u64::from(*v)),
            Value::Number(v) => {
                if let Some(n) = v.as_u64() {
                    self.push_metric(metric_prefix, help, labels, n);
                } else if let Some(n) = v.as_i64() {
                    self.push_metric_value(metric_prefix, help, labels, &n.to_string());
                } else if let Some(n) = v.as_f64() {
                    self.push_metric_value(metric_prefix, help, labels, &format!("{n:.6}"));
                }
            }
            Value::Array(values) => {
                for (idx, item) in values.iter().enumerate() {
                    labels.push(("index".to_string(), idx.to_string()));
                    self.append_json_value(metric_prefix, help, labels, item);
                    labels.pop();
                }
            }
            Value::Object(map) => {
                for (key, item) in map {
                    let next_prefix = format!("{}_{}", metric_prefix, sanitize_metric_part(key));
                    self.append_json_value(&next_prefix, help, labels, item);
                }
            }
        }
    }

    fn push_metric(&mut self, name: &str, help: &str, labels: &[(String, String)], value: u64) {
        self.push_metric_value(name, help, labels, &value.to_string());
    }

    fn push_metric_value(
        &mut self,
        name: &str,
        help: &str,
        labels: &[(String, String)],
        value: &str,
    ) {
        if self.emitted_descriptors.insert(name.to_string()) {
            let _ = writeln!(self.out, "# HELP {name} {help}");
            let _ = writeln!(self.out, "# TYPE {name} gauge");
        }

        self.out.push_str(name);
        if !labels.is_empty() {
            self.out.push('{');
            for (idx, (key, value)) in labels.iter().enumerate() {
                if idx > 0 {
                    self.out.push(',');
                }
                self.out.push_str(key);
                self.out.push_str("=\"");
                self.out.push_str(&escape_label_value(value));
                self.out.push('"');
            }
            self.out.push('}');
        }
        let _ = writeln!(self.out, " {value}");
    }

    fn finish(mut self) -> String {
        if self.out.is_empty() {
            self.out
                .push_str("# No nydusd metrics are currently registered.\n");
        }
        self.out
    }
}

fn response_payload_body(source: &str, response: ApiResponse) -> Result<Option<String>, ApiError> {
    match response {
        Ok(payload) => match payload {
            ApiResponsePayload::BackendMetrics(body)
            | ApiResponsePayload::BlobcacheMetrics(body)
            | ApiResponsePayload::FsGlobalMetrics(body)
            | ApiResponsePayload::FsFilesMetrics(body)
            | ApiResponsePayload::FsFilesPatterns(body)
            | ApiResponsePayload::FsInflightMetrics(body) => Ok(Some(body)),
            ApiResponsePayload::Empty => Ok(None),
            _ => Err(ApiError::ResponsePayloadType),
        },
        Err(e) if is_optional_metrics_error(&e) => Ok(None),
        Err(e) => {
            debug!("failed to collect Prometheus source {}: {:?}", source, e);
            Err(e)
        }
    }
}

fn is_optional_metrics_error(e: &ApiError) -> bool {
    matches!(
        e,
        ApiError::Metrics(MetricsErrorKind::Stats(MetricsError::NoCounter))
            | ApiError::DaemonAbnormal(DaemonErrorKind::Unsupported)
    )
}

fn sanitize_metric_part(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    if out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    out
}

fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn get_req(url: &str) -> Request {
        let raw = format!("GET {} HTTP/1.0\r\n\r\n", url);
        Request::try_from(raw.as_bytes(), None).unwrap()
    }

    #[test]
    fn renders_numeric_json_leaves() {
        let mut renderer = PrometheusRenderer::default();
        renderer
            .append_source_response(
                "nydusd_test",
                "test metrics",
                Ok(ApiResponsePayload::FsGlobalMetrics(
                    r#"{"read_count":2,"nested":{"items":[1,3]},"ignored":"text"}"#.into(),
                )),
            )
            .unwrap();
        let body = renderer.finish();

        assert!(body.contains("# TYPE nydusd_test_read_count gauge"));
        assert!(body.contains("nydusd_test_read_count 2"));
        assert!(body.contains("nydusd_test_nested_items{index=\"0\"} 1"));
        assert!(body.contains("nydusd_test_nested_items{index=\"1\"} 3"));
        assert!(!body.contains("ignored"));
    }

    #[test]
    fn renders_bool_signed_and_float_json_leaves() {
        let mut renderer = PrometheusRenderer::default();
        renderer
            .append_source_response(
                "nydusd_test",
                "test metrics",
                Ok(ApiResponsePayload::BackendMetrics(
                    r#"{"enabled":true,"disabled":false,"delta":-7,"ratio":1.25}"#.into(),
                )),
            )
            .unwrap();
        let body = renderer.finish();

        assert!(body.contains("nydusd_test_enabled 1"));
        assert!(body.contains("nydusd_test_disabled 0"));
        assert!(body.contains("nydusd_test_delta -7"));
        assert!(body.contains("nydusd_test_ratio 1.250000"));
    }

    #[test]
    fn sanitizes_metric_name_parts_and_escapes_label_values() {
        assert_eq!(sanitize_metric_part("Read-Count"), "read_count");
        assert_eq!(sanitize_metric_part("123.bad/key"), "_123_bad_key");
        assert_eq!(sanitize_metric_part(""), "_");
        assert_eq!(escape_label_value("a\\b\"c\n"), "a\\\\b\\\"c\\n");
    }

    #[test]
    fn reports_invalid_json_from_metric_source() {
        let mut renderer = PrometheusRenderer::default();
        let err = renderer
            .append_source_response(
                "nydusd_test",
                "test metrics",
                Ok(ApiResponsePayload::BackendMetrics("not-json".into())),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            ApiError::Metrics(MetricsErrorKind::Stats(MetricsError::Serialize(_)))
        ));
    }

    #[test]
    fn skips_absent_optional_metric_sources() {
        let mut renderer = PrometheusRenderer::default();
        renderer
            .append_source_response(
                "nydusd_test",
                "test metrics",
                Err(ApiError::Metrics(MetricsErrorKind::Stats(
                    MetricsError::NoCounter,
                ))),
            )
            .unwrap();

        assert_eq!(
            renderer.finish(),
            "# No nydusd metrics are currently registered.\n"
        );
    }

    #[test]
    fn handler_reuses_existing_metric_requests() {
        let handler = PrometheusMetricsHandler {};
        let req = get_req("http://localhost/metrics?include_files=true&include_patterns=true");
        let seen = Mutex::new(Vec::new());
        let result = handler.handle_request(&req, &|request| {
            seen.lock().unwrap().push(match request {
                ApiRequest::ExportFsGlobalMetrics(_) => "global",
                ApiRequest::ExportBackendMetrics(_) => "backend",
                ApiRequest::ExportBlobcacheMetrics(_) => "blobcache",
                ApiRequest::ExportFsInflightMetrics => "inflight",
                ApiRequest::ExportFsFilesMetrics(_, false) => "files",
                ApiRequest::ExportFsAccessPatterns(_) => "patterns",
                _ => "other",
            });
            Ok(ApiResponsePayload::FsGlobalMetrics("{}".into()))
        });

        assert!(result.is_ok());
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                "global",
                "backend",
                "blobcache",
                "inflight",
                "files",
                "patterns"
            ]
        );
    }

    #[test]
    fn handler_rejects_non_get_requests() {
        let handler = PrometheusMetricsHandler {};
        let req = Request::try_from(
            b"PUT http://localhost/metrics HTTP/1.0\r\n\r\n".as_slice(),
            None,
        )
        .unwrap();
        let result = handler.handle_request(&req, &|_| Ok(ApiResponsePayload::Empty));

        assert!(matches!(result, Err(HttpError::BadRequest)));
    }
}
