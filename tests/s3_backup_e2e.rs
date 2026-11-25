use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;

use cfms_ctl::cli::GlobalOpts;
use cfms_ctl::cli::backup::{BackupCommand, BackupExportArgs, BackupImportArgs, BackupVerifyArgs};
use cfms_ctl::cli::doctor::DoctorArgs;
use cfms_ctl::core::{CfmsError, ConfigDocument, WorkspacePaths};
use cfms_ctl::db::DbPool;
use cfms_ctl::db::schema::{LATEST_SCHEMA_REVISION, create_head_schema, set_alembic_version};
use cfms_ctl::ops::backup::format::read_backup_header;
use cfms_ctl::ops::backup::{self, export, import};
use cfms_ctl::ops::{AppContext, doctor};
use cfms_ctl::storage::{LocalFsStorage, resolve_storage};
use cfms_ctl::ui::{OutputFormat, UiConsole};

#[derive(Debug, Clone)]
struct MockMultipart {
    bucket: String,
    key: String,
    parts: BTreeMap<i32, Vec<u8>>,
}

#[derive(Debug, Default)]
struct MockS3Stats {
    head_bucket_calls: usize,
    head_object_calls: usize,
    get_object_calls: usize,
    put_object_calls: usize,
    copy_object_calls: usize,
    create_multipart_calls: usize,
    upload_part_calls: usize,
    complete_multipart_calls: usize,
    abort_multipart_calls: usize,
    delete_objects_calls: usize,
    delete_object_calls: usize,
    saw_if_none_match_on_put: usize,
    saw_if_none_match_on_complete: usize,
    saw_if_none_match_on_copy: usize,
}

#[derive(Debug, Default)]
struct MockS3State {
    buckets: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
    multiparts: BTreeMap<String, MockMultipart>,
    next_upload_seq: u64,
    stats: MockS3Stats,
    simulate_if_none_match_501: bool,
    simulate_delete_objects_501: bool,
    fail_get_with_403_for_key: Option<String>,
    fail_complete_multipart_with_403: bool,
    fail_put_if_bucket_nonempty: bool,
    race_insert_before_put_key: Option<String>,
    bucket_error_override: Option<(u16, &'static str)>,
    response_delay: Option<Duration>,
}

struct MockS3Server {
    endpoint_url: String,
    state: Arc<Mutex<MockS3State>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for MockS3Server {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl MockS3Server {
    async fn start(initial_buckets: &[&str]) -> Self {
        let mut init = MockS3State::default();
        for b in initial_buckets {
            init.buckets.insert((*b).to_string(), BTreeMap::new());
        }
        let state = Arc::new(Mutex::new(init));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock s3");
        let addr: SocketAddr = listener.local_addr().unwrap();
        let endpoint_url = format!("http://{addr}");
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

        let state_srv = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_res = listener.accept() => {
                        let Ok((stream, _)) = accept_res else {
                            break;
                        };
                        let st = Arc::clone(&state_srv);
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let svc = service_fn(move |req| handle_s3_request(req, Arc::clone(&st)));
                            let _ = ConnBuilder::new(TokioExecutor::new())
                                .serve_connection(io, svc)
                                .await;
                        });
                    }
                }
            }
        });

        Self {
            endpoint_url,
            state,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    fn put_object(&self, bucket: &str, key: &str, bytes: &[u8]) {
        let mut guard = self.state.lock().unwrap();
        guard
            .buckets
            .entry(bucket.to_string())
            .or_default()
            .insert(key.to_string(), bytes.to_vec());
    }

    fn snapshot_bucket(&self, bucket: &str) -> BTreeMap<String, Vec<u8>> {
        let guard = self.state.lock().unwrap();
        guard.buckets.get(bucket).cloned().unwrap_or_default()
    }

    fn active_multipart_count(&self) -> usize {
        self.state.lock().unwrap().multiparts.len()
    }
}

fn s3_xml_error(status: StatusCode, code: &str, msg: &str) -> Response<Full<Bytes>> {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{msg}</Message></Error>"
    );
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn s3_head_error(status: StatusCode, code: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("x-amz-error-code", code)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn decode_percent(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push(((hi << 4) | lo) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn split_path_bucket_key(path: &str) -> (&str, Option<String>) {
    let trimmed = path.trim_start_matches('/');
    match trimmed.split_once('/') {
        Some((bucket, rest)) => (bucket, Some(decode_percent(rest))),
        None => (trimmed, None),
    }
}

fn query_has_flag(query: Option<&str>, name: &str) -> bool {
    let Some(q) = query else {
        return false;
    };
    q.split('&')
        .any(|pair| pair == name || pair.split_once('=').is_some_and(|(k, _)| k == name))
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    let q = query?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Some(decode_percent(v));
        }
    }
    None
}

fn extract_xml_tags(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut results = Vec::new();
    let mut cursor = xml;
    while let Some(start) = cursor.find(&open) {
        let after_open = &cursor[start + open.len()..];
        if let Some(end) = after_open.find(&close) {
            let val = after_open[..end]
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'");
            results.push(val);
            cursor = &after_open[end + close.len()..];
        } else {
            break;
        }
    }
    results
}

async fn handle_s3_request(
    req: Request<Incoming>,
    state: Arc<Mutex<MockS3State>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let delay = state.lock().unwrap().response_delay;
    if let Some(d) = delay {
        tokio::time::sleep(d).await;
    }

    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().map(ToString::to_string);
    let headers = req.headers().clone();

    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            return Ok(s3_xml_error(
                StatusCode::BAD_REQUEST,
                "IncompleteBody",
                &e.to_string(),
            ));
        }
    };

    let (bucket, maybe_key) = split_path_bucket_key(&path);
    let key_non_empty = maybe_key.filter(|k| !k.is_empty());

    let mut st = state.lock().unwrap();

    // Check optional bucket-level override first (e.g. simulated AccessDenied or NoSuchBucket)
    if let Some((status_u16, code)) = st.bucket_error_override {
        let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if method == Method::HEAD {
            if key_non_empty.is_none() {
                st.stats.head_bucket_calls += 1;
            }
            return Ok(s3_head_error(status, code));
        }
        return Ok(s3_xml_error(status, code, "Injected bucket error"));
    }

    let bucket_exists = st.buckets.contains_key(bucket);

    // Bucket-level requests (`/<bucket>`)
    if key_non_empty.is_none() {
        match method {
            Method::HEAD => {
                st.stats.head_bucket_calls += 1;
                if bucket_exists {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::new()))
                        .unwrap());
                }
                return Ok(s3_head_error(StatusCode::NOT_FOUND, "NoSuchBucket"));
            }
            Method::POST if query_has_flag(query.as_deref(), "delete") => {
                if !bucket_exists {
                    return Ok(s3_xml_error(
                        StatusCode::NOT_FOUND,
                        "NoSuchBucket",
                        "Bucket does not exist",
                    ));
                }
                if st.simulate_delete_objects_501 {
                    return Ok(s3_xml_error(
                        StatusCode::NOT_IMPLEMENTED,
                        "NotImplemented",
                        "DeleteObjects not implemented",
                    ));
                }
                st.stats.delete_objects_calls += 1;
                let xml = String::from_utf8_lossy(&body);
                let keys = extract_xml_tags(&xml, "Key");
                if let Some(objects) = st.buckets.get_mut(bucket) {
                    for k in keys {
                        objects.remove(&k);
                    }
                }
                let resp_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></DeleteResult>";
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/xml")
                    .body(Full::new(Bytes::from_static(resp_xml.as_bytes())))
                    .unwrap());
            }
            _ => {
                return Ok(s3_xml_error(
                    StatusCode::NOT_IMPLEMENTED,
                    "NotImplemented",
                    "Unsupported bucket op",
                ));
            }
        }
    }

    let key = key_non_empty.unwrap();
    if !bucket_exists {
        return Ok(if method == Method::HEAD {
            s3_head_error(StatusCode::NOT_FOUND, "NoSuchBucket")
        } else {
            s3_xml_error(StatusCode::NOT_FOUND, "NoSuchBucket", "Bucket does not exist")
        });
    }

    let has_if_none_match = headers
        .get(hyper::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some("*");

    match method {
        Method::HEAD => {
            st.stats.head_object_calls += 1;
            if let Some(obj) = st.buckets.get(bucket).and_then(|b| b.get(&key)) {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-length", obj.len().to_string())
                    .header("etag", "\"mock-etag\"")
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
            Ok(s3_head_error(StatusCode::NOT_FOUND, "NoSuchKey"))
        }
        Method::GET => {
            st.stats.get_object_calls += 1;
            if st.fail_get_with_403_for_key.as_deref() == Some(key.as_str()) {
                return Ok(s3_xml_error(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "Access Denied for key",
                ));
            }
            if let Some(obj) = st.buckets.get(bucket).and_then(|b| b.get(&key)).cloned() {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-length", obj.len().to_string())
                    .header("etag", "\"mock-etag\"")
                    .body(Full::new(Bytes::from(obj)))
                    .unwrap());
            }
            Ok(s3_xml_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist.",
            ))
        }
        Method::POST if query_has_flag(query.as_deref(), "uploads") => {
            st.stats.create_multipart_calls += 1;
            st.next_upload_seq += 1;
            let upload_id = format!("upload-{}", st.next_upload_seq);
            st.multiparts.insert(
                upload_id.clone(),
                MockMultipart {
                    bucket: bucket.to_string(),
                    key: key.clone(),
                    parts: BTreeMap::new(),
                },
            );
            let resp_xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{bucket}</Bucket><Key>{key}</Key><UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>"
            );
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Full::new(Bytes::from(resp_xml)))
                .unwrap())
        }
        Method::PUT => {
            if let (Some(upload_id), Some(part_num_str)) = (
                query_param(query.as_deref(), "uploadId"),
                query_param(query.as_deref(), "partNumber"),
            ) {
                st.stats.upload_part_calls += 1;
                let part_num: i32 = part_num_str.parse().unwrap_or(0);
                let Some(mp) = st.multiparts.get_mut(&upload_id) else {
                    return Ok(s3_xml_error(
                        StatusCode::NOT_FOUND,
                        "NoSuchUpload",
                        "Upload session missing",
                    ));
                };
                mp.parts.insert(part_num, body.to_vec());
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        "etag",
                        HeaderValue::from_str(&format!("\"part-{part_num}\"")).unwrap(),
                    )
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }

            if let Some(copy_src_hdr) = headers.get("x-amz-copy-source") {
                st.stats.copy_object_calls += 1;
                if has_if_none_match {
                    st.stats.saw_if_none_match_on_copy += 1;
                    if st.simulate_if_none_match_501 {
                        return Ok(s3_xml_error(
                            StatusCode::NOT_IMPLEMENTED,
                            "NotImplemented",
                            "If-None-Match unsupported",
                        ));
                    }
                    if st
                        .buckets
                        .get(bucket)
                        .is_some_and(|b| b.contains_key(&key))
                    {
                        return Ok(s3_xml_error(
                            StatusCode::PRECONDITION_FAILED,
                            "PreconditionFailed",
                            "Object already exists",
                        ));
                    }
                }
                let raw_src = copy_src_hdr.to_str().unwrap_or("");
                let (src_bucket, src_key_opt) = split_path_bucket_key(raw_src);
                let Some(src_key) = src_key_opt else {
                    return Ok(s3_xml_error(StatusCode::BAD_REQUEST, "InvalidRequest", "Bad copy source"));
                };
                let Some(src_bytes) = st
                    .buckets
                    .get(src_bucket)
                    .and_then(|b| b.get(&src_key))
                    .cloned()
                else {
                    return Ok(s3_xml_error(StatusCode::NOT_FOUND, "NoSuchKey", "Missing copy source"));
                };
                st.buckets
                    .get_mut(bucket)
                    .unwrap()
                    .insert(key, src_bytes);
                let resp_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyObjectResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ETag>\"copied\"</ETag></CopyObjectResult>";
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/xml")
                    .body(Full::new(Bytes::from_static(resp_xml.as_bytes())))
                    .unwrap());
            }

            st.stats.put_object_calls += 1;
            if st.race_insert_before_put_key.as_deref() == Some(key.as_str()) {
                st.buckets
                    .get_mut(bucket)
                    .unwrap()
                    .insert(key.clone(), b"CONCURRENT_PREEXISTING_OWNER".to_vec());
            }
            if has_if_none_match {
                st.stats.saw_if_none_match_on_put += 1;
                if st.simulate_if_none_match_501 {
                    return Ok(s3_xml_error(
                        StatusCode::NOT_IMPLEMENTED,
                        "NotImplemented",
                        "If-None-Match unsupported",
                    ));
                }
                if st
                    .buckets
                    .get(bucket)
                    .is_some_and(|b| b.contains_key(&key))
                {
                    return Ok(s3_xml_error(
                        StatusCode::PRECONDITION_FAILED,
                        "PreconditionFailed",
                        "Precondition failed: key already exists",
                    ));
                }
            }
            if st.fail_put_if_bucket_nonempty
                && st.buckets.get(bucket).is_some_and(|b| !b.is_empty())
            {
                return Ok(s3_xml_error(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "Injected non-retryable upload failure after first object",
                ));
            }
            st.buckets
                .get_mut(bucket)
                .unwrap()
                .insert(key, body.to_vec());
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("etag", "\"put-etag\"")
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
        Method::POST => {
            let Some(upload_id) = query_param(query.as_deref(), "uploadId") else {
                return Ok(s3_xml_error(StatusCode::BAD_REQUEST, "InvalidRequest", "Missing uploadId"));
            };
            st.stats.complete_multipart_calls += 1;
            if st.fail_complete_multipart_with_403 {
                return Ok(s3_xml_error(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "Injected non-retryable complete multipart failure",
                ));
            }
            if st.race_insert_before_put_key.as_deref() == Some(key.as_str()) {
                st.buckets
                    .get_mut(bucket)
                    .unwrap()
                    .insert(key.clone(), b"CONCURRENT_MULTIPART_RACER".to_vec());
            }
            if has_if_none_match {
                st.stats.saw_if_none_match_on_complete += 1;
                if st.simulate_if_none_match_501 {
                    return Ok(s3_xml_error(
                        StatusCode::NOT_IMPLEMENTED,
                        "NotImplemented",
                        "If-None-Match unsupported",
                    ));
                }
                if st
                    .buckets
                    .get(bucket)
                    .is_some_and(|b| b.contains_key(&key))
                {
                    return Ok(s3_xml_error(
                        StatusCode::PRECONDITION_FAILED,
                        "PreconditionFailed",
                        "Object already exists",
                    ));
                }
            }

            let Some(mp) = st.multiparts.remove(&upload_id) else {
                return Ok(s3_xml_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchUpload",
                    "UploadId not found",
                ));
            };
            if mp.bucket != bucket || mp.key != key {
                return Ok(s3_xml_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "Upload target mismatch",
                ));
            }

            let req_xml = String::from_utf8_lossy(&body);
            let requested_parts = extract_xml_tags(&req_xml, "PartNumber");
            let mut combined = Vec::new();
            for p_str in requested_parts {
                let p_num: i32 = p_str.parse().unwrap_or(0);
                let Some(part_data) = mp.parts.get(&p_num) else {
                    return Ok(s3_xml_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidPart",
                        "Missing part in upload",
                    ));
                };
                combined.extend_from_slice(part_data);
            }
            st.buckets
                .get_mut(bucket)
                .unwrap()
                .insert(key.clone(), combined);
            let resp_xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{bucket}</Bucket><Key>{key}</Key><ETag>\"mp-etag\"</ETag></CompleteMultipartUploadResult>"
            );
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Full::new(Bytes::from(resp_xml)))
                .unwrap())
        }
        Method::DELETE => {
            if let Some(upload_id) = query_param(query.as_deref(), "uploadId") {
                st.stats.abort_multipart_calls += 1;
                if st.multiparts.remove(&upload_id).is_some() {
                    return Ok(Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Full::new(Bytes::new()))
                        .unwrap());
                }
                return Ok(s3_xml_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchUpload",
                    "Missing upload",
                ));
            }
            st.stats.delete_object_calls += 1;
            if let Some(objects) = st.buckets.get_mut(bucket) {
                objects.remove(&key);
            }
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
        _ => Ok(s3_xml_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "Unsupported HTTP method",
        )),
    }
}

fn test_ctx(root: &Path) -> AppContext {
    let global = GlobalOpts {
        root: Some(root.to_path_buf()),
        config: None,
        output: OutputFormat::Json,
        yes: true,
        verbose: false,
    };
    AppContext::new(global, UiConsole::new(OutputFormat::Json))
}

#[allow(clippy::too_many_arguments)]
fn create_workspace(
    root: &Path,
    db_file: &str,
    storage_provider: &str,
    s3_bucket: Option<&str>,
    s3_endpoint: Option<&str>,
    pepper: &str,
    secret_key: &str,
) -> PathBuf {
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let s3_block = if let (Some(bucket), Some(ep)) = (s3_bucket, s3_endpoint) {
        format!(
            r#"
[s3]
bucket = "{bucket}"
endpoint_url = "{ep}"
access_key_id = "TESTACCESS"
secret_access_key = "TESTSECRET"
region_name = ""
addressing_style = "auto"
max_pool_connections = 8
"#
        )
    } else {
        String::new()
    };

    let cfg = format!(
        r#"# preserved comment header
debug = false

[server]
host = "127.0.0.1"
port = 5104
secret_key = "{secret_key}"

[security]
# preserved pepper comment
pepper = "{pepper}"

[database]
type = "sqlite"
file = "{db_file}"

[provider]
storage = "{storage_provider}"
{s3_block}
"#
    );
    fs::write(src_dir.join("config.toml"), cfg).unwrap();
    fs::write(src_dir.join("main.py"), "# stub\n").unwrap();
    fs::write(
        root.join("release-manifest.json"),
        r#"{"version":"0.15.0"}"#,
    )
    .unwrap();
    root.to_path_buf()
}

async fn open_sqlite_pool(ws: &Path) -> DbPool {
    let paths = WorkspacePaths::discover(Some(ws), None).unwrap();
    let doc = ConfigDocument::load(&paths.config_path).unwrap();
    let db = doc.database_config().unwrap();
    DbPool::connect(&db, &paths).await.unwrap()
}

async fn seed_source_db(pool: &DbPool, entries: &[(&str, &str, bool, i64)]) {
    create_head_schema(pool, false).await.unwrap();
    set_alembic_version(pool, LATEST_SCHEMA_REVISION)
        .await
        .unwrap();
    let DbPool::Sqlite(p) = pool else { unreachable!() };

    let alice_uuid = uuid::Uuid::from_bytes([0x42u8; 16]).simple().to_string();
    let digest = [0x11u8; 32];
    sqlx::query(
        "INSERT INTO comments (comment_id, digest_version, content_digest, comment_text, comment_data) \
         VALUES (1, 1, ?, 'User note', NULL)",
    )
    .bind(digest.as_slice())
    .execute(p)
    .await
    .unwrap();

    for (file_id, path, active, size) in entries {
        sqlx::query(
            "INSERT INTO files (id, sha256, path, size, created_time, active) \
             VALUES (?, '0000', ?, ?, 100.0, ?)",
        )
        .bind(file_id)
        .bind(path)
        .bind(*size)
        .bind(i32::from(*active))
        .execute(p)
        .await
        .unwrap();
    }

    sqlx::query(
        "INSERT INTO users (id, username, nickname, avatar_id, last_login, created_time, status, status_comment_id, secret_key, preference_dek_id) \
         VALUES (?, 'alice', 'Alice', NULL, 105.0, 100.0, 0, 1, 'user-secret-key', NULL)",
    )
    .bind(&alice_uuid)
    .execute(p)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO nodes (id, type, name, parent_id, inherit, status, status_operation_id) \
         VALUES ('/', 'directory', '/', NULL, 1, 0, NULL)",
    )
    .execute(p)
    .await
    .unwrap();

    sqlx::query("INSERT INTO folders (id, created_time) VALUES ('/', 100.0)")
        .execute(p)
        .await
        .unwrap();
}

#[tokio::test]
async fn s3_export_info_verify_and_import_roundtrip_with_multipart_dedup_and_missing() {
    let mock = MockS3Server::start(&["src-bucket", "dst-bucket"]).await;
    let tmp = tempfile::tempdir().unwrap();

    let src_ws = create_workspace(
        &tmp.path().join("src_ws"),
        "src.db",
        "s3",
        Some("src-bucket"),
        Some(&mock.endpoint_url),
        "src-pepper",
        "src-secret",
    );
    let small_blob = b"AVATAR_SMALL_PAYLOAD".to_vec();
    let empty_blob: Vec<u8> = Vec::new();
    // 17.5 MiB -> exercises 3 multipart parts (8 MiB + 8 MiB + 1.5 MiB) across S3!
    let multipart_len = 17 * 1024 * 1024 + 512 * 1024;
    let large_blob: Vec<u8> = (0..multipart_len)
        .map(|i| ((i * 29 + 13) % 251) as u8)
        .collect();
    let shared_blob = b"DEDUPLICATED_SHARED_CONTENT_987654321".to_vec();

    mock.put_object("src-bucket", "content/files/2026/small.bin", &small_blob);
    mock.put_object("src-bucket", "content/files/2026/empty.txt", &empty_blob);
    mock.put_object("src-bucket", "content/files/2026/large.bin", &large_blob);
    mock.put_object("src-bucket", "content/files/2026/shared.bin", &shared_blob);
    // Note `gone.bin` intentionally omitted (`active = false`) to test single-RTT missing accounting!

    let src_pool = open_sqlite_pool(&src_ws).await;
    seed_source_db(
        &src_pool,
        &[
            ("f-small", "content/files/2026/small.bin", true, small_blob.len() as i64),
            ("f-empty", "content/files/2026/empty.txt", true, 0),
            ("f-large", "content/files/2026/large.bin", true, large_blob.len() as i64),
            ("f-dup-1", "content/files/2026/shared.bin", true, shared_blob.len() as i64),
            ("f-dup-2", "content/files/2026/shared.bin", true, shared_blob.len() as i64),
            ("f-gone", "content/files/2026/gone.bin", false, 42),
        ],
    )
    .await;
    src_pool.close().await;

    let archive_path = tmp.path().join("s3_backup.confbak");
    let key_path = tmp.path().join("s3_backup.key");

    export::run_export(
        &test_ctx(&src_ws),
        BackupExportArgs {
            output_path: Some(archive_path.clone()),
            key_out: Some(key_path.clone()),
            components: vec![],
            interactive: false,
        },
    )
    .await
    .unwrap();

    // Confirm export used single-RTT GetObject without issuing HeadObject
    {
        let st = mock.state.lock().unwrap();
        assert_eq!(st.stats.head_bucket_calls, 1);
        assert_eq!(st.stats.head_object_calls, 0);
        // 5 unique paths (`small`, `empty`, `large`, `shared` once, `gone` once)
        assert_eq!(st.stats.get_object_calls, 5);
    }

    // Check unencrypted envelope header via `backup info` & programmatic reader
    backup::handle(
        &test_ctx(&src_ws),
        BackupCommand::Info(cfms_ctl::cli::backup::BackupInfoArgs {
            backup_path: archive_path.clone(),
        }),
    )
    .await
    .unwrap();
    let header = read_backup_header(&archive_path).unwrap();
    assert_eq!(header.storage_provider, "s3");

    // Verify encrypted stream offline
    backup::handle(
        &test_ctx(&src_ws),
        BackupCommand::Verify(BackupVerifyArgs {
            backup_path: archive_path.clone(),
            key: None,
            key_file: Some(key_path.clone()),
        }),
    )
    .await
    .unwrap();

    // Import into blank target workspace backed by `dst-bucket`
    let dst_ws = create_workspace(
        &tmp.path().join("dst_ws"),
        "dst.db",
        "s3",
        Some("dst-bucket"),
        Some(&mock.endpoint_url),
        "old-pepper",
        "old-secret",
    );

    import::run_import(
        &test_ctx(&dst_ws),
        BackupImportArgs {
            backup_path: archive_path,
            key: None,
            key_file: Some(key_path),
        },
    )
    .await
    .unwrap();

    let restored = mock.snapshot_bucket("dst-bucket");
    assert_eq!(restored.len(), 4);
    assert_eq!(restored.get("content/files/2026/small.bin").unwrap(), &small_blob);
    assert_eq!(restored.get("content/files/2026/empty.txt").unwrap(), &empty_blob);
    assert_eq!(restored.get("content/files/2026/large.bin").unwrap(), &large_blob);
    assert_eq!(restored.get("content/files/2026/shared.bin").unwrap(), &shared_blob);
    assert!(!restored.contains_key("content/files/2026/gone.bin"));
    assert_eq!(mock.active_multipart_count(), 0);

    {
        let st = mock.state.lock().unwrap();
        assert_eq!(st.stats.create_multipart_calls, 1);
        assert_eq!(st.stats.upload_part_calls, 3);
        assert_eq!(st.stats.complete_multipart_calls, 1);
        assert_eq!(st.stats.saw_if_none_match_on_complete, 1);
        assert_eq!(st.stats.abort_multipart_calls, 0);
        // 3 small files uploaded with If-None-Match: *
        assert_eq!(st.stats.saw_if_none_match_on_put, 3);
        // Batch absent precheck checked 5 unique files paths
        assert_eq!(st.stats.head_object_calls, 5);
    }

    let dst_cfg = fs::read_to_string(dst_ws.join("src").join("config.toml")).unwrap();
    assert!(dst_cfg.contains("src-pepper"));
    assert!(dst_cfg.contains("src-secret"));
    assert!(dst_cfg.contains("# preserved comment header"));
}

#[tokio::test]
async fn s3_export_403_and_missing_bucket_fail_cleanly_without_orphans() {
    let mock = MockS3Server::start(&["src-bucket"]).await;
    let tmp = tempfile::tempdir().unwrap();

    let src_ws = create_workspace(
        &tmp.path().join("src_ws"),
        "src.db",
        "s3",
        Some("src-bucket"),
        Some(&mock.endpoint_url),
        "p",
        "s",
    );
    let src_pool = open_sqlite_pool(&src_ws).await;
    seed_source_db(
        &src_pool,
        &[("f-inactive", "content/files/2026/forbidden.bin", false, 10)],
    )
    .await;
    src_pool.close().await;

    // 1. Inactive file with 403 AccessDenied must NOT be swallowed as missing_inactive_files
    mock.state.lock().unwrap().fail_get_with_403_for_key =
        Some("content/files/2026/forbidden.bin".to_string());
    let out = tmp.path().join("fail_403.confbak");
    let key_out = tmp.path().join("fail_403.key");
    let err_403 = export::run_export(
        &test_ctx(&src_ws),
        BackupExportArgs {
            output_path: Some(out.clone()),
            key_out: Some(key_out.clone()),
            components: vec![],
            interactive: false,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err_403, CfmsError::Config(_)), "got {err_403:?}");
    assert!(!out.exists());
    assert!(!key_out.exists());

    // 2. Non-existent bucket fails in preflight (`HeadBucket`) before reading DB / touching files
    let bad_ws = create_workspace(
        &tmp.path().join("missing_bucket_ws"),
        "missing.db",
        "s3",
        Some("nonexistent-bucket"),
        Some(&mock.endpoint_url),
        "p",
        "s",
    );
    let err_bucket = export::run_export(
        &test_ctx(&bad_ws),
        BackupExportArgs {
            output_path: Some(out.clone()),
            key_out: None,
            components: vec![],
            interactive: false,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err_bucket, CfmsError::Config(_)), "got {err_bucket:?}");
    assert!(!out.exists());
}

#[tokio::test]
async fn s3_import_race_412_and_midflight_failure_rollback_preserve_existing_objects() {
    let mock = MockS3Server::start(&["src-bucket", "dst-bucket"]).await;
    let tmp = tempfile::tempdir().unwrap();

    let src_ws = create_workspace(
        &tmp.path().join("src_ws"),
        "src.db",
        "s3",
        Some("src-bucket"),
        Some(&mock.endpoint_url),
        "src-pepper",
        "src-secret",
    );
    let large_len = 9 * 1024 * 1024;
    let large_blob = vec![0x5Au8; large_len];
    mock.put_object("src-bucket", "content/files/2026/a_first.bin", b"FIRST");
    mock.put_object("src-bucket", "content/files/2026/b_raced.bin", b"ARCHIVE_COPY");
    mock.put_object("src-bucket", "content/files/2026/c_large.bin", &large_blob);

    let src_pool = open_sqlite_pool(&src_ws).await;
    seed_source_db(
        &src_pool,
        &[
            ("f1", "content/files/2026/a_first.bin", true, 5),
            ("f2", "content/files/2026/b_raced.bin", true, 12),
            ("f3", "content/files/2026/c_large.bin", true, large_len as i64),
        ],
    )
    .await;
    src_pool.close().await;

    let archive = tmp.path().join("race.confbak");
    let key_file = tmp.path().join("race.key");
    export::run_export(
        &test_ctx(&src_ws),
        BackupExportArgs {
            output_path: Some(archive.clone()),
            key_out: Some(key_file.clone()),
            components: vec![],
            interactive: false,
        },
    )
    .await
    .unwrap();

    // Case 1: Pre-flight HeadObject collision before writing anything
    mock.put_object("dst-bucket", "content/files/2026/a_first.bin", b"DO_NOT_TOUCH");
    let dst_ws_1 = create_workspace(
        &tmp.path().join("dst_ws_1"),
        "dst1.db",
        "s3",
        Some("dst-bucket"),
        Some(&mock.endpoint_url),
        "p0",
        "s0",
    );
    let collision_err = import::run_import(
        &test_ctx(&dst_ws_1),
        BackupImportArgs {
            backup_path: archive.clone(),
            key: None,
            key_file: Some(key_file.clone()),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(collision_err, CfmsError::ArchiveIntegrity(_)));
    assert_eq!(
        mock.snapshot_bucket("dst-bucket")
            .get("content/files/2026/a_first.bin")
            .unwrap(),
        b"DO_NOT_TOUCH"
    );

    // Clear dst-bucket for Case 2
    mock.state.lock().unwrap().buckets.get_mut("dst-bucket").unwrap().clear();

    // Case 2: Concurrent racer injects `b_raced.bin` right as PutObject executes -> 412!
    // Must delete `a_first.bin` cleanly, MUST preserve `b_raced.bin` created by racer, abort multiparts, and drop DB tables!
    mock.state.lock().unwrap().race_insert_before_put_key =
        Some("content/files/2026/b_raced.bin".to_string());
    let dst_ws_2 = create_workspace(
        &tmp.path().join("dst_ws_2"),
        "dst2.db",
        "s3",
        Some("dst-bucket"),
        Some(&mock.endpoint_url),
        "p0",
        "s0",
    );
    let race_err = import::run_import(
        &test_ctx(&dst_ws_2),
        BackupImportArgs {
            backup_path: archive.clone(),
            key: None,
            key_file: Some(key_file.clone()),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(race_err, CfmsError::ArchiveIntegrity(_)));

    let dst_after_race = mock.snapshot_bucket("dst-bucket");
    assert!(!dst_after_race.contains_key("content/files/2026/a_first.bin"));
    assert_eq!(
        dst_after_race.get("content/files/2026/b_raced.bin").unwrap(),
        b"CONCURRENT_PREEXISTING_OWNER"
    );
    assert!(!dst_after_race.contains_key("content/files/2026/c_large.bin"));
    assert_eq!(mock.active_multipart_count(), 0);
    assert!(!dst_ws_2.join("src").join("init").exists());

    // Blank SQLite tables created during preflight must be dropped on rollback
    let check_pool = open_sqlite_pool(&dst_ws_2).await;
    assert!(check_pool.list_tables().await.unwrap().is_empty());
    check_pool.close().await;

    // Case 3: Mid-flight failure on CompleteMultipartUpload -> aborts multipart & batch-deletes committed objects
    mock.state.lock().unwrap().buckets.get_mut("dst-bucket").unwrap().clear();
    {
        let mut st = mock.state.lock().unwrap();
        st.race_insert_before_put_key = None;
        st.fail_complete_multipart_with_403 = true;
    }
    let dst_ws_3 = create_workspace(
        &tmp.path().join("dst_ws_3"),
        "dst3.db",
        "s3",
        Some("dst-bucket"),
        Some(&mock.endpoint_url),
        "p0",
        "s0",
    );
    let fail_mid = import::run_import(
        &test_ctx(&dst_ws_3),
        BackupImportArgs {
            backup_path: archive,
            key: None,
            key_file: Some(key_file),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(fail_mid, CfmsError::Config(_)), "got {fail_mid:?}");
    assert!(mock.snapshot_bucket("dst-bucket").is_empty());
    assert_eq!(mock.active_multipart_count(), 0);
    assert!(mock.state.lock().unwrap().stats.abort_multipart_calls >= 1);
    assert!(mock.state.lock().unwrap().stats.delete_objects_calls >= 1);
}

#[tokio::test]
async fn s3_501_fallback_for_if_none_match_and_delete_objects_works() {
    let mock = MockS3Server::start(&["src-bucket", "dst-bucket"]).await;
    {
        let mut st = mock.state.lock().unwrap();
        st.simulate_if_none_match_501 = true;
        st.simulate_delete_objects_501 = true;
    }

    let tmp = tempfile::tempdir().unwrap();
    let src_ws = create_workspace(
        &tmp.path().join("src_ws"),
        "src.db",
        "s3",
        Some("src-bucket"),
        Some(&mock.endpoint_url),
        "p1",
        "s1",
    );
    mock.put_object("src-bucket", "content/files/2026/one.bin", b"ONE");
    mock.put_object("src-bucket", "content/files/2026/two.bin", b"TWO");
    let src_pool = open_sqlite_pool(&src_ws).await;
    seed_source_db(
        &src_pool,
        &[
            ("f1", "content/files/2026/one.bin", true, 3),
            ("f2", "content/files/2026/two.bin", true, 3),
        ],
    )
    .await;
    src_pool.close().await;

    let archive = tmp.path().join("501.confbak");
    let key_file = tmp.path().join("501.key");
    export::run_export(
        &test_ctx(&src_ws),
        BackupExportArgs {
            output_path: Some(archive.clone()),
            key_out: Some(key_file.clone()),
            components: vec![],
            interactive: false,
        },
    )
    .await
    .unwrap();

    // 1. Successful import despite 501 on If-None-Match (falls back cleanly to HeadObject + unconditional PutObject)
    let dst_ws = create_workspace(
        &tmp.path().join("dst_ws"),
        "dst.db",
        "s3",
        Some("dst-bucket"),
        Some(&mock.endpoint_url),
        "p0",
        "s0",
    );
    import::run_import(
        &test_ctx(&dst_ws),
        BackupImportArgs {
            backup_path: archive.clone(),
            key: None,
            key_file: Some(key_file.clone()),
        },
    )
    .await
    .unwrap();

    let bucket_after = mock.snapshot_bucket("dst-bucket");
    assert_eq!(bucket_after.get("content/files/2026/one.bin").unwrap(), b"ONE");
    assert_eq!(bucket_after.get("content/files/2026/two.bin").unwrap(), b"TWO");

    // 2. Rollback with simulated 501 DeleteObjects falls back cleanly to per-key DeleteObject
    mock.state.lock().unwrap().buckets.get_mut("dst-bucket").unwrap().clear();
    {
        let mut st = mock.state.lock().unwrap();
        st.fail_put_if_bucket_nonempty = true;
    }
    let dst_ws_fail = create_workspace(
        &tmp.path().join("dst_ws_fail"),
        "dst_fail.db",
        "s3",
        Some("dst-bucket"),
        Some(&mock.endpoint_url),
        "p0",
        "s0",
    );
    assert!(
        import::run_import(
            &test_ctx(&dst_ws_fail),
            BackupImportArgs {
                backup_path: archive,
                key: None,
                key_file: Some(key_file),
            },
        )
        .await
        .is_err()
    );
    assert!(mock.snapshot_bucket("dst-bucket").is_empty());
    assert!(mock.state.lock().unwrap().stats.delete_object_calls >= 1);
}

#[tokio::test]
async fn cross_storage_restore_local_to_s3_and_s3_to_local_succeeds() {
    let mock = MockS3Server::start(&["s3-target"]).await;
    let tmp = tempfile::tempdir().unwrap();

    // 1. Seed a LOCAL storage workspace
    let local_src = create_workspace(
        &tmp.path().join("local_src"),
        "local.db",
        "local",
        None,
        None,
        "local-pepper",
        "local-secret",
    );
    let payload = b"CROSS_STORAGE_MIGRATION_BYTES".to_vec();
    let local_paths = WorkspacePaths::discover(Some(&local_src), None).unwrap();
    LocalFsStorage::new(local_paths.server_root.clone())
        .write_bytes_sync("content/files/migr/asset.bin", &payload)
        .unwrap();

    let local_pool = open_sqlite_pool(&local_src).await;
    seed_source_db(
        &local_pool,
        &[("f-mig", "content/files/migr/asset.bin", true, payload.len() as i64)],
    )
    .await;
    local_pool.close().await;

    let archive_local = tmp.path().join("from_local.confbak");
    let key_local = tmp.path().join("from_local.key");
    export::run_export(
        &test_ctx(&local_src),
        BackupExportArgs {
            output_path: Some(archive_local.clone()),
            key_out: Some(key_local.clone()),
            components: vec![],
            interactive: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(read_backup_header(&archive_local).unwrap().storage_provider, "local");

    // Verify encrypted archive cleanly before cross-storage import
    backup::handle(
        &test_ctx(&local_src),
        BackupCommand::Verify(BackupVerifyArgs {
            backup_path: archive_local.clone(),
            key: None,
            key_file: Some(key_local.clone()),
        }),
    )
    .await
    .unwrap();

    // 2. Import LOCAL archive directly into S3 workspace (`local -> s3`)
    let s3_dst = create_workspace(
        &tmp.path().join("s3_dst"),
        "s3dst.db",
        "s3",
        Some("s3-target"),
        Some(&mock.endpoint_url),
        "old-p",
        "old-s",
    );
    import::run_import(
        &test_ctx(&s3_dst),
        BackupImportArgs {
            backup_path: archive_local,
            key: None,
            key_file: Some(key_local),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        mock.snapshot_bucket("s3-target")
            .get("content/files/migr/asset.bin")
            .unwrap(),
        &payload
    );

    // 3. Re-export from S3 and import back into a fresh LOCAL workspace (`s3 -> local`)
    let archive_s3 = tmp.path().join("from_s3.confbak");
    let key_s3 = tmp.path().join("from_s3.key");
    export::run_export(
        &test_ctx(&s3_dst),
        BackupExportArgs {
            output_path: Some(archive_s3.clone()),
            key_out: Some(key_s3.clone()),
            components: vec![],
            interactive: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(read_backup_header(&archive_s3).unwrap().storage_provider, "s3");

    let local_dst = create_workspace(
        &tmp.path().join("local_dst"),
        "localdst.db",
        "local",
        None,
        None,
        "old-p2",
        "old-s2",
    );
    import::run_import(
        &test_ctx(&local_dst),
        BackupImportArgs {
            backup_path: archive_s3,
            key: None,
            key_file: Some(key_s3),
        },
    )
    .await
    .unwrap();
    let local_dst_paths = WorkspacePaths::discover(Some(&local_dst), None).unwrap();
    assert_eq!(
        LocalFsStorage::new(local_dst_paths.server_root)
            .read_bytes_sync("content/files/migr/asset.bin")
            .unwrap(),
        payload
    );
}

#[tokio::test]
async fn doctor_diagnoses_s3_health_failure_and_skip_storage_with_delayed_spinner() {
    let mock = MockS3Server::start(&["health-bucket"]).await;
    let tmp = tempfile::tempdir().unwrap();

    let ws = create_workspace(
        &tmp.path().join("doc_ws"),
        "doc.db",
        "s3",
        Some("health-bucket"),
        Some(&mock.endpoint_url),
        "pepper-ok",
        "secret-ok",
    );
    let pool = open_sqlite_pool(&ws).await;
    create_head_schema(&pool, false).await.unwrap();
    set_alembic_version(&pool, LATEST_SCHEMA_REVISION)
        .await
        .unwrap();
    pool.close().await;

    // 1. Healthy S3 + slow delay triggering delayed spinner path cleanly in Human mode
    mock.state.lock().unwrap().response_delay = Some(Duration::from_millis(280));
    let human_ctx = AppContext::new(
        GlobalOpts {
            root: Some(ws.clone()),
            config: None,
            output: OutputFormat::Human,
            yes: true,
            verbose: false,
        },
        UiConsole::new(OutputFormat::Human),
    );
    let report = doctor::diagnose(
        &human_ctx,
        &DoctorArgs {
            skip_db: false,
            skip_storage: false,
        },
    )
    .await
    .unwrap();
    assert!(report.healthy);
    let sh = report.storage_health.as_ref().unwrap();
    assert!(sh.healthy);
    assert_eq!(sh.provider, "s3");
    assert_eq!(sh.resolved_region.as_deref(), Some("us-east-1"));
    assert_eq!(sh.force_path_style, Some(true));

    // Confirm JSON serialization contains zero secret credentials
    let report_json = serde_json::to_string(&report).unwrap();
    assert!(!report_json.contains("TESTSECRET"));
    mock.state.lock().unwrap().response_delay = None;

    // 2. Bucket 404/403 reported accurately
    mock.state.lock().unwrap().bucket_error_override = Some((403, "AccessDenied"));
    let bad_report = doctor::diagnose(
        &test_ctx(&ws),
        &DoctorArgs {
            skip_db: false,
            skip_storage: false,
        },
    )
    .await
    .unwrap();
    assert!(!bad_report.healthy);
    let bad_sh = bad_report.storage_health.unwrap();
    assert!(!bad_sh.healthy);
    assert!(bad_sh.error.as_deref().unwrap_or("").contains("AccessDenied"));

    // 3. `--skip-storage` bypasses S3 preflight
    let before_heads = mock.state.lock().unwrap().stats.head_bucket_calls;
    let skipped = doctor::diagnose(
        &test_ctx(&ws),
        &DoctorArgs {
            skip_db: false,
            skip_storage: true,
        },
    )
    .await
    .unwrap();
    assert!(skipped.healthy);
    assert!(skipped.storage_health.is_none());
    assert_eq!(mock.state.lock().unwrap().stats.head_bucket_calls, before_heads);
}

#[tokio::test]
#[ignore = "Requires live S3-compatible endpoint configured via CFMS_TEST_S3_* env vars"]
async fn live_s3_compatible_backup_roundtrip_smoke() {
    let bucket = std::env::var("CFMS_TEST_S3_BUCKET")
        .expect("CFMS_TEST_S3_BUCKET must be set to run ignored live S3 test");
    let endpoint = std::env::var("CFMS_TEST_S3_ENDPOINT_URL").unwrap_or_default();
    let access_key = std::env::var("CFMS_TEST_S3_ACCESS_KEY_ID").unwrap_or_default();
    let secret_key = std::env::var("CFMS_TEST_S3_SECRET_ACCESS_KEY").unwrap_or_default();
    let region = std::env::var("CFMS_TEST_S3_REGION").unwrap_or_default();
    let style = std::env::var("CFMS_TEST_S3_ADDRESSING_STYLE").unwrap_or_else(|_| "auto".to_string());

    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("live_s3_ws");
    fs::create_dir_all(ws.join("src")).unwrap();
    fs::write(ws.join("src/app.py"), "# live test\n").unwrap();
    fs::write(
        ws.join("src/config.toml"),
        format!(
            r#"
[database]
type = "sqlite"
file = "live.db"

[provider]
storage = "s3"

[s3]
bucket = "{bucket}"
endpoint_url = "{endpoint}"
access_key_id = "{access_key}"
secret_access_key = "{secret_key}"
region_name = "{region}"
addressing_style = "{style}"
"#
        ),
    )
    .unwrap();

    let paths = WorkspacePaths::discover(Some(&ws), None).unwrap();
    let doc = ConfigDocument::load(&paths.config_path).unwrap();
    let storage = resolve_storage(&paths, &doc).await.unwrap();
    storage.preflight().await.unwrap();

    let unique_prefix = format!("content/files/cfms-ctl-smoke-{}", uuid::Uuid::new_v4());
    let key = format!("{unique_prefix}/probe.bin");
    let tracker = cfms_ctl::storage::RollbackTracker::new();
    let mut writer = storage
        .begin_staged_write(&key, Some(16), std::sync::Arc::clone(&tracker))
        .await
        .unwrap();
    writer.write_chunk(Bytes::from_static(b"LIVE_S3_SMOKE_OK")).await.unwrap();
    writer.finish().await.unwrap();

    let mut reader = storage.open_read_optional(&key).await.unwrap().expect("present");
    use futures_util::StreamExt;
    let mut collected = Vec::new();
    while let Some(chunk) = reader.next().await {
        collected.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(collected, b"LIVE_S3_SMOKE_OK");

    let rb = storage.rollback_written(&tracker).await;
    assert!(rb.errors.is_empty(), "cleanup errors: {:?}", rb.errors);
    assert!(storage.open_read_optional(&key).await.unwrap().is_none());
}
