//! Amazon S3 and S3-compatible object storage backend (`aws-sdk-s3` + `rustls-ring`).

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
};
use aws_sdk_s3::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, Delete, ObjectIdentifier};
use bytes::Bytes;
use futures_util::stream::{self, FuturesUnordered, StreamExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use crate::core::config::{S3AddressingStyle, S3SectionConfig};
use crate::core::error::{CfmsError, Result};
use crate::storage::{
    BoxFuture, RollbackOutcome, RollbackTracker, StagedStorageWriter, StorageBackend,
    StorageByteStream, validate_storage_relative_path,
};

const DEFAULT_S3_PART_BYTES: usize = 8 * 1024 * 1024;
const MIN_S3_PART_BYTES: usize = 5 * 1024 * 1024;
const MAX_S3_PART_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const MAX_S3_PARTS: u64 = 10_000;
const DEFAULT_S3_TRANSFER_CONCURRENCY_CAP: usize = 16;
const MAX_MULTIPART_CONCURRENT_PARTS: usize = 4;
const MAX_DELETE_OBJECTS_BATCH: usize = 1000;
/// Global in-flight S3 upload buffer budget counted in 1 KiB permits (`64 MiB` total).
const MAX_GLOBAL_S3_BUFFER_PERMITS: usize = 64 * 1024;

#[derive(Debug)]
struct S3Inner {
    client: Client,
    bucket: String,
    endpoint_url: Option<String>,
    region: String,
    addressing_style: S3AddressingStyle,
    force_path_style: bool,
    transfer_concurrency: usize,
    buffer_semaphore: Arc<Semaphore>,
    if_none_match_unsupported: AtomicBool,
    delete_objects_unsupported: AtomicBool,
    warnings: std::sync::Mutex<Vec<String>>,
}

/// Asynchronous S3 storage backend built on `aws-sdk-s3` with `rustls-ring`.
#[derive(Debug, Clone)]
pub struct S3Storage {
    inner: Arc<S3Inner>,
}

impl S3Storage {
    /// Construct an [`S3Storage`] client from validated `[s3]` configuration.
    pub async fn from_config(cfg: &S3SectionConfig) -> Result<Self> {
        let bucket = cfg.bucket.trim().to_string();
        if bucket.is_empty() {
            return Err(CfmsError::Config(
                "Configuration key 's3.bucket' must not be empty".to_string(),
            ));
        }

        let http_client = aws_smithy_http_client::Builder::new()
            .pool_max_idle_per_host(cfg.max_pool_connections)
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();

        let timeout_config = TimeoutConfig::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(60))
            .operation_attempt_timeout(Duration::from_secs(300))
            .build();

        let retry_config = RetryConfig::standard().with_max_attempts(5);
        let force_path_style = resolve_force_path_style(
            cfg.addressing_style,
            cfg.endpoint_url.as_deref(),
            &bucket,
        );

        let (s3_config, effective_region) =
            if let (Some(ak), Some(sk)) = (&cfg.access_key_id, &cfg.secret_access_key) {
                let creds = Credentials::new(
                    ak.clone(),
                    sk.as_str().to_string(),
                    cfg.session_token.as_ref().map(|s| s.as_str().to_string()),
                    None,
                    "cfms-config",
                );
                let region_str = cfg
                    .region_name
                    .clone()
                    .or_else(|| non_empty_env("AWS_REGION"))
                    .or_else(|| non_empty_env("AWS_DEFAULT_REGION"))
                    .unwrap_or_else(|| "us-east-1".to_string());

                let mut builder = aws_sdk_s3::Config::builder()
                    .behavior_version(BehaviorVersion::latest())
                    .http_client(http_client)
                    .credentials_provider(creds)
                    .region(Region::new(region_str.clone()))
                    .force_path_style(force_path_style)
                    .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
                    .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
                    .timeout_config(timeout_config)
                    .retry_config(retry_config);

                if let Some(ref ep) = cfg.endpoint_url {
                    builder = builder.endpoint_url(ep);
                }
                (builder.build(), region_str)
            } else {
                let mut loader = aws_config::defaults(BehaviorVersion::latest())
                    .http_client(http_client.clone());
                if let Some(ref region) = cfg.region_name {
                    loader = loader.region(Region::new(region.clone()));
                }
                if let Some(ref ep) = cfg.endpoint_url {
                    loader = loader.endpoint_url(ep);
                }
                let sdk_config = loader.load().await;

                let resolved_region = if let Some(r) = sdk_config.region() {
                    r.as_ref().to_string()
                } else if cfg.endpoint_url.is_some() {
                    "us-east-1".to_string()
                } else {
                    return Err(CfmsError::Config(
                        "S3 region could not be determined; configure [s3].region_name or AWS_REGION"
                            .to_string(),
                    ));
                };

                let mut builder = aws_sdk_s3::config::Builder::from(&sdk_config)
                    .behavior_version(BehaviorVersion::latest())
                    .http_client(http_client)
                    .region(Region::new(resolved_region.clone()))
                    .force_path_style(force_path_style)
                    .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
                    .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
                    .timeout_config(timeout_config)
                    .retry_config(retry_config);

                if let Some(ref ep) = cfg.endpoint_url {
                    builder = builder.endpoint_url(ep);
                }
                (builder.build(), resolved_region)
            };

        let client = Client::from_conf(s3_config);
        let transfer_concurrency = cfg
            .max_pool_connections
            .clamp(1, DEFAULT_S3_TRANSFER_CONCURRENCY_CAP);

        Ok(Self {
            inner: Arc::new(S3Inner {
                client,
                bucket,
                endpoint_url: cfg.endpoint_url.clone(),
                region: effective_region,
                addressing_style: cfg.addressing_style,
                force_path_style,
                transfer_concurrency,
                buffer_semaphore: Arc::new(Semaphore::new(MAX_GLOBAL_S3_BUFFER_PERMITS)),
                if_none_match_unsupported: AtomicBool::new(false),
                delete_objects_unsupported: AtomicBool::new(false),
                warnings: std::sync::Mutex::new(Vec::new()),
            }),
        })
    }

    /// Configured target bucket name.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.inner.bucket
    }

    /// Effective signing region resolved for S3 operations.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.inner.region
    }

    /// Effective `force_path_style` setting matching `botocore` semantics.
    #[must_use]
    pub fn force_path_style(&self) -> bool {
        self.inner.force_path_style
    }

    /// Configured addressing style enum.
    #[must_use]
    pub fn addressing_style(&self) -> S3AddressingStyle {
        self.inner.addressing_style
    }

    fn record_warning_once(&self, message: String) {
        if let Ok(mut guard) = self.inner.warnings.lock()
            && !guard.iter().any(|existing| existing == &message)
        {
            guard.push(message);
        }
    }

    async fn head_object_exists(&self, key: &str) -> Result<bool> {
        let valid = validate_storage_relative_path(key)?;
        let res = self
            .inner
            .client
            .head_object()
            .bucket(&self.inner.bucket)
            .key(valid)
            .send()
            .await;

        match res {
            Ok(_) => Ok(true),
            Err(err) => {
                if is_object_not_found_error(&err) {
                    Ok(false)
                } else {
                    Err(classify_s3_error(
                        "HeadObject",
                        &self.inner.bucket,
                        Some(valid),
                        err,
                    ))
                }
            }
        }
    }

    async fn put_object_no_overwrite(&self, key: &str, body: Bytes) -> Result<()> {
        let content_len = i64::try_from(body.len()).map_err(|_| {
            CfmsError::Backup(format!(
                "S3 object '{key}' size {} exceeds i64 limit",
                body.len()
            ))
        })?;

        if !self.inner.if_none_match_unsupported.load(Ordering::Relaxed) {
            let res = self
                .inner
                .client
                .put_object()
                .bucket(&self.inner.bucket)
                .key(key)
                .content_length(content_len)
                .if_none_match("*")
                .body(ByteStream::from(body.clone()))
                .send()
                .await;

            match res {
                Ok(_) => return Ok(()),
                Err(err) if is_precondition_failed_error(&err) => {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Refusing to overwrite pre-existing S3 object '{key}'"
                    )));
                }
                Err(err) if is_not_implemented_error(&err) => {
                    self.inner
                        .if_none_match_unsupported
                        .store(true, Ordering::Relaxed);
                    self.record_warning_once(
                        "S3 endpoint does not support If-None-Match conditional writes (HTTP 501); falling back to HeadObject collision check + overwrite-guarded retry."
                            .to_string(),
                    );
                }
                Err(err) => {
                    return Err(classify_s3_error(
                        "PutObject",
                        &self.inner.bucket,
                        Some(key),
                        err,
                    ));
                }
            }
        }

        if self.head_object_exists(key).await? {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Refusing to overwrite pre-existing S3 object '{key}'"
            )));
        }

        self.inner
            .client
            .put_object()
            .bucket(&self.inner.bucket)
            .key(key)
            .content_length(content_len)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|err| classify_s3_error("PutObject", &self.inner.bucket, Some(key), err))?;
        Ok(())
    }

    async fn complete_multipart_no_overwrite(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<()> {
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();

        if !self.inner.if_none_match_unsupported.load(Ordering::Relaxed) {
            let res = self
                .inner
                .client
                .complete_multipart_upload()
                .bucket(&self.inner.bucket)
                .key(key)
                .upload_id(upload_id)
                .multipart_upload(completed.clone())
                .if_none_match("*")
                .send()
                .await;

            match res {
                Ok(_) => return Ok(()),
                Err(err) if is_precondition_failed_error(&err) => {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Refusing to overwrite pre-existing S3 object '{key}'"
                    )));
                }
                Err(err) if is_not_implemented_error(&err) => {
                    self.inner
                        .if_none_match_unsupported
                        .store(true, Ordering::Relaxed);
                    self.record_warning_once(
                        "S3 endpoint does not support If-None-Match on CompleteMultipartUpload (HTTP 501); falling back to HeadObject collision check + retry."
                            .to_string(),
                    );
                }
                Err(err) => {
                    return Err(classify_s3_error(
                        "CompleteMultipartUpload",
                        &self.inner.bucket,
                        Some(key),
                        err,
                    ));
                }
            }
        }

        if self.head_object_exists(key).await? {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Refusing to overwrite pre-existing S3 object '{key}'"
            )));
        }

        self.inner
            .client
            .complete_multipart_upload()
            .bucket(&self.inner.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|err| {
                classify_s3_error(
                    "CompleteMultipartUpload",
                    &self.inner.bucket,
                    Some(key),
                    err,
                )
            })?;
        Ok(())
    }

    async fn abort_multipart_best_effort(&self, key: &str, upload_id: &str) -> Result<()> {
        let res = self
            .inner
            .client
            .abort_multipart_upload()
            .bucket(&self.inner.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await;

        match res {
            Ok(_) => Ok(()),
            Err(err) if is_missing_upload_or_object_error(&err) => Ok(()),
            Err(err) => Err(classify_s3_error(
                "AbortMultipartUpload",
                &self.inner.bucket,
                Some(key),
                err,
            )),
        }
    }

    async fn delete_objects_single_fallback(&self, keys: &[String], outcome: &mut RollbackOutcome) {
        let concurrency = self.inner.transfer_concurrency;
        let mut in_flight = FuturesUnordered::new();
        let mut iter = keys.iter();

        loop {
            while in_flight.len() < concurrency {
                let Some(key) = iter.next() else {
                    break;
                };
                let client = self.inner.client.clone();
                let bucket = self.inner.bucket.clone();
                let key_owned = key.clone();
                in_flight.push(async move {
                    let res = client
                        .delete_object()
                        .bucket(&bucket)
                        .key(&key_owned)
                        .send()
                        .await;
                    (key_owned, bucket, res)
                });
            }

            let Some((key, bucket, res)) = in_flight.next().await else {
                break;
            };
            match res {
                Ok(_) => outcome.deleted_objects += 1,
                Err(err) if is_object_not_found_error(&err) => outcome.deleted_objects += 1,
                Err(err) => {
                    outcome.errors.push(
                        classify_s3_error("DeleteObject", &bucket, Some(&key), err).to_string(),
                    );
                }
            }
        }
    }
}

impl StorageBackend for S3Storage {
    fn kind(&self) -> &'static str {
        "s3"
    }

    fn target_description(&self) -> String {
        match &self.inner.endpoint_url {
            Some(ep) => format!("s3://{} ({ep})", self.inner.bucket),
            None => format!("s3://{} ({})", self.inner.bucket, self.inner.region),
        }
    }

    fn recommended_concurrency(&self) -> usize {
        self.inner.transfer_concurrency
    }

    fn collected_warnings(&self) -> Vec<String> {
        self.inner
            .warnings
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    fn preflight(&self) -> BoxFuture<'_, Result<()>> {
        let storage = self.clone();
        Box::pin(async move {
            storage
                .inner
                .client
                .head_bucket()
                .bucket(&storage.inner.bucket)
                .send()
                .await
                .map_err(|err| classify_s3_error("HeadBucket", &storage.inner.bucket, None, err))?;
            Ok(())
        })
    }

    fn open_read_optional(
        &self,
        relative_path: &str,
    ) -> BoxFuture<'_, Result<Option<StorageByteStream>>> {
        let storage = self.clone();
        let rel = relative_path.to_string();
        Box::pin(async move {
            let valid = validate_storage_relative_path(&rel)?.to_string();
            let res = storage
                .inner
                .client
                .get_object()
                .bucket(&storage.inner.bucket)
                .key(&valid)
                .send()
                .await;

            match res {
                Ok(output) => {
                    let key_for_err = valid;
                    let bucket_for_err = storage.inner.bucket.clone();
                    let s: StorageByteStream = Box::pin(stream::unfold(
                        (output.body, false),
                        move |(mut body, errored)| {
                            let key_for_err = key_for_err.clone();
                            let bucket_for_err = bucket_for_err.clone();
                            async move {
                                if errored {
                                    return None;
                                }
                                match body.next().await {
                                    Some(Ok(chunk)) => Some((Ok(chunk), (body, false))),
                                    Some(Err(err)) => Some((
                                        Err(CfmsError::Backup(format!(
                                            "S3 GetObject stream error for 's3://{bucket_for_err}/{key_for_err}': {err}"
                                        ))),
                                        (body, true),
                                    )),
                                    None => None,
                                }
                            }
                        },
                    ));
                    Ok(Some(s))
                }
                Err(err) => {
                    if is_object_not_found_error(&err) {
                        Ok(None)
                    } else {
                        Err(classify_s3_error(
                            "GetObject",
                            &storage.inner.bucket,
                            Some(&valid),
                            err,
                        ))
                    }
                }
            }
        })
    }

    fn check_paths_absent(&self, relative_paths: &[String]) -> BoxFuture<'_, Result<()>> {
        let storage = self.clone();
        let mut unique_paths = Vec::with_capacity(relative_paths.len());
        let mut seen = HashSet::with_capacity(relative_paths.len());
        for path in relative_paths {
            if seen.insert(path.clone()) {
                unique_paths.push(path.clone());
            }
        }

        Box::pin(async move {
            for p in &unique_paths {
                validate_storage_relative_path(p)?;
            }

            let concurrency = storage.inner.transfer_concurrency;
            let mut in_flight = FuturesUnordered::new();
            let mut iter = unique_paths.into_iter();

            loop {
                while in_flight.len() < concurrency {
                    let Some(key) = iter.next() else {
                        break;
                    };
                    let st = storage.clone();
                    in_flight.push(async move {
                        let exists = st.head_object_exists(&key).await?;
                        Ok::<(String, bool), CfmsError>((key, exists))
                    });
                }

                let Some(next_res) = in_flight.next().await else {
                    break;
                };
                let (key, exists) = next_res?;
                if exists {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Refusing to overwrite pre-existing storage object '{key}'"
                    )));
                }
            }
            Ok(())
        })
    }

    fn begin_staged_write(
        &self,
        relative_path: &str,
        size_hint: Option<u64>,
        tracker: Arc<RollbackTracker>,
    ) -> BoxFuture<'_, Result<Box<dyn StagedStorageWriter>>> {
        let storage = self.clone();
        let rel = relative_path.to_string();
        Box::pin(async move {
            let valid = validate_storage_relative_path(&rel)?.to_string();
            let part_size = compute_part_size(size_hint)?;
            let boxed: Box<dyn StagedStorageWriter> = Box::new(S3StagedWriter {
                storage,
                key: valid,
                part_size,
                tracker,
                buffer: Vec::new(),
                permits: VecDeque::new(),
                multipart: None,
            });
            Ok(boxed)
        })
    }

    fn copy_within<'a>(
        &'a self,
        src_relative_path: &str,
        dst_relative_path: &str,
        tracker: &'a RollbackTracker,
    ) -> BoxFuture<'a, Result<u64>> {
        let storage = self.clone();
        let src = src_relative_path.to_string();
        let dst = dst_relative_path.to_string();
        let tracker_handle = tracker.clone_paths_handle();
        Box::pin(async move {
            let valid_src = validate_storage_relative_path(&src)?;
            let valid_dst = validate_storage_relative_path(&dst)?;
            let copy_source = format!(
                "{}/{}",
                storage.inner.bucket,
                encode_copy_source_key(valid_src)
            );

            let head = storage
                .inner
                .client
                .head_object()
                .bucket(&storage.inner.bucket)
                .key(valid_src)
                .send()
                .await
                .map_err(|err| {
                    classify_s3_error("HeadObject", &storage.inner.bucket, Some(valid_src), err)
                })?;
            let size_bytes = head
                .content_length()
                .and_then(|n| u64::try_from(n).ok())
                .unwrap_or(0);

            if !storage
                .inner
                .if_none_match_unsupported
                .load(Ordering::Relaxed)
            {
                let res = storage
                    .inner
                    .client
                    .copy_object()
                    .bucket(&storage.inner.bucket)
                    .key(valid_dst)
                    .copy_source(&copy_source)
                    .if_none_match("*")
                    .send()
                    .await;

                match res {
                    Ok(_) => {
                        tracker_handle.record_written(valid_dst.to_string()).await;
                        return Ok(size_bytes);
                    }
                    Err(err) if is_precondition_failed_error(&err) => {
                        return Err(CfmsError::ArchiveIntegrity(format!(
                            "Refusing to overwrite pre-existing S3 object '{valid_dst}'"
                        )));
                    }
                    Err(err) if is_not_implemented_error(&err) => {
                        storage
                            .inner
                            .if_none_match_unsupported
                            .store(true, Ordering::Relaxed);
                        storage.record_warning_once(
                            "S3 endpoint does not support If-None-Match on CopyObject (HTTP 501); falling back to HeadObject collision check + retry."
                                .to_string(),
                        );
                    }
                    Err(err) => {
                        return Err(classify_s3_error(
                            "CopyObject",
                            &storage.inner.bucket,
                            Some(valid_dst),
                            err,
                        ));
                    }
                }
            }

            if storage.head_object_exists(valid_dst).await? {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Refusing to overwrite pre-existing S3 object '{valid_dst}'"
                )));
            }

            storage
                .inner
                .client
                .copy_object()
                .bucket(&storage.inner.bucket)
                .key(valid_dst)
                .copy_source(&copy_source)
                .send()
                .await
                .map_err(|err| {
                    classify_s3_error("CopyObject", &storage.inner.bucket, Some(valid_dst), err)
                })?;

            tracker_handle.record_written(valid_dst.to_string()).await;
            Ok(size_bytes)
        })
    }

    fn rollback_written<'a>(&'a self, tracker: &'a RollbackTracker) -> BoxFuture<'a, RollbackOutcome> {
        let storage = self.clone();
        let snapshot = tracker.snapshot_for_rollback();
        Box::pin(async move {
            let (written_keys, active_multiparts) = snapshot.await;
            let mut outcome = RollbackOutcome::default();

            // 1. Abort all uncommitted multipart uploads in parallel.
            let mut abort_pool = FuturesUnordered::new();
            let mut mp_iter = active_multiparts.into_iter();
            loop {
                while abort_pool.len() < storage.inner.transfer_concurrency {
                    let Some((key, upload_id)) = mp_iter.next() else {
                        break;
                    };
                    let st = storage.clone();
                    abort_pool.push(async move {
                        let res = st.abort_multipart_best_effort(&key, &upload_id).await;
                        (key, upload_id, res)
                    });
                }
                let Some((key, upload_id, res)) = abort_pool.next().await else {
                    break;
                };
                match res {
                    Ok(()) => outcome.aborted_multiparts += 1,
                    Err(e) => outcome
                        .errors
                        .push(format!("abort multipart '{key}' ({upload_id}): {e}")),
                }
            }

            // 2. Delete newly created objects in quiet batches of up to 1,000 keys.
            for batch in written_keys.chunks(MAX_DELETE_OBJECTS_BATCH) {
                if storage
                    .inner
                    .delete_objects_unsupported
                    .load(Ordering::Relaxed)
                {
                    storage
                        .delete_objects_single_fallback(batch, &mut outcome)
                        .await;
                    continue;
                }

                let mut identifiers = Vec::with_capacity(batch.len());
                for key in batch {
                    match ObjectIdentifier::builder().key(key).build() {
                        Ok(id) => identifiers.push(id),
                        Err(e) => outcome
                            .errors
                            .push(format!("build DeleteObjects identifier '{key}': {e}")),
                    }
                }
                if identifiers.is_empty() {
                    continue;
                }

                let delete_spec = match Delete::builder()
                    .set_objects(Some(identifiers))
                    .quiet(true)
                    .build()
                {
                    Ok(d) => d,
                    Err(e) => {
                        outcome.errors.push(format!("build Delete payload: {e}"));
                        continue;
                    }
                };

                let res = storage
                    .inner
                    .client
                    .delete_objects()
                    .bucket(&storage.inner.bucket)
                    .delete(delete_spec)
                    .send()
                    .await;

                match res {
                    Ok(resp) => {
                        let batch_errors = resp.errors();
                        let failed_count = batch_errors.len();
                        outcome.deleted_objects += batch.len().saturating_sub(failed_count);
                        for del_err in batch_errors {
                            let key = del_err.key().unwrap_or("<unknown>");
                            let code = del_err.code().unwrap_or("Error");
                            let msg = del_err.message().unwrap_or("");
                            outcome
                                .errors
                                .push(format!("DeleteObjects '{key}': {code} ({msg})"));
                        }
                    }
                    Err(err) if is_not_implemented_error(&err) => {
                        storage
                            .inner
                            .delete_objects_unsupported
                            .store(true, Ordering::Relaxed);
                        storage
                            .delete_objects_single_fallback(batch, &mut outcome)
                            .await;
                    }
                    Err(err) => {
                        outcome.errors.push(
                            classify_s3_error("DeleteObjects", &storage.inner.bucket, None, err)
                                .to_string(),
                        );
                    }
                }
            }

            outcome
        })
    }
}

struct ActiveMultipartState {
    upload_id: String,
    next_part_number: i32,
    completed_parts: Vec<CompletedPart>,
    in_flight: JoinSet<Result<CompletedPart>>,
}

struct S3StagedWriter {
    storage: S3Storage,
    key: String,
    part_size: usize,
    tracker: Arc<RollbackTracker>,
    buffer: Vec<u8>,
    permits: VecDeque<(usize, OwnedSemaphorePermit)>,
    multipart: Option<ActiveMultipartState>,
}

impl S3StagedWriter {
    async fn acquire_chunk_permit(&mut self, byte_len: usize) -> Result<()> {
        if byte_len == 0 {
            return Ok(());
        }
        let permit_count = bytes_to_kib_permits(byte_len);
        let permit = self
            .storage
            .inner
            .buffer_semaphore
            .clone()
            .acquire_many_owned(permit_count)
            .await
            .map_err(|_| CfmsError::Backup("S3 buffer semaphore closed unexpectedly".to_string()))?;
        self.permits.push_back((byte_len, permit));
        Ok(())
    }

    fn take_permits_for_bytes(&mut self, mut bytes_needed: usize) -> Vec<OwnedSemaphorePermit> {
        let mut taken = Vec::new();
        while bytes_needed > 0 {
            let Some((front_bytes, front_permit)) = self.permits.pop_front() else {
                break;
            };
            if front_bytes > bytes_needed {
                let remaining = front_bytes - bytes_needed;
                self.permits.push_front((remaining, front_permit));
                break;
            }
            bytes_needed -= front_bytes;
            taken.push(front_permit);
        }
        taken
    }

    async fn ensure_multipart_initiated(&mut self) -> Result<()> {
        if self.multipart.is_some() {
            return Ok(());
        }
        let resp = self
            .storage
            .inner
            .client
            .create_multipart_upload()
            .bucket(&self.storage.inner.bucket)
            .key(&self.key)
            .send()
            .await
            .map_err(|err| {
                classify_s3_error(
                    "CreateMultipartUpload",
                    &self.storage.inner.bucket,
                    Some(&self.key),
                    err,
                )
            })?;

        let upload_id = resp
            .upload_id()
            .map(ToString::to_string)
            .ok_or_else(|| {
                CfmsError::Backup(format!(
                    "S3 CreateMultipartUpload for '{}' returned no UploadId",
                    self.key
                ))
            })?;

        self.tracker
            .register_multipart(self.key.clone(), upload_id.clone())
            .await;

        self.multipart = Some(ActiveMultipartState {
            upload_id,
            next_part_number: 1,
            completed_parts: Vec::new(),
            in_flight: JoinSet::new(),
        });
        Ok(())
    }

    async fn spawn_part_upload(
        &mut self,
        part_bytes: Bytes,
        part_permits: Vec<OwnedSemaphorePermit>,
    ) -> Result<()> {
        self.ensure_multipart_initiated().await?;
        let mp = self.multipart.as_mut().expect("multipart initialized");

        while mp.in_flight.len() >= MAX_MULTIPART_CONCURRENT_PARTS {
            match mp.in_flight.join_next().await {
                Some(Ok(Ok(part))) => mp.completed_parts.push(part),
                Some(Ok(Err(e))) => return Err(e),
                Some(Err(join_err)) => {
                    return Err(CfmsError::Backup(format!(
                        "S3 UploadPart task panicked for '{}': {join_err}",
                        self.key
                    )));
                }
                None => break,
            }
        }

        let part_number = mp.next_part_number;
        mp.next_part_number += 1;
        if part_number as u64 > MAX_S3_PARTS {
            return Err(CfmsError::Backup(format!(
                "Object '{}' exceeds S3 limit of {MAX_S3_PARTS} multipart parts",
                self.key
            )));
        }

        let client = self.storage.inner.client.clone();
        let bucket = self.storage.inner.bucket.clone();
        let key = self.key.clone();
        let upload_id = mp.upload_id.clone();
        let content_len = i64::try_from(part_bytes.len()).map_err(|_| {
            CfmsError::Backup(format!(
                "S3 part size {} exceeds i64 limit",
                part_bytes.len()
            ))
        })?;

        mp.in_flight.spawn(async move {
            let _permits = part_permits;
            let resp = client
                .upload_part()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .content_length(content_len)
                .body(ByteStream::from(part_bytes))
                .send()
                .await
                .map_err(|err| classify_s3_error("UploadPart", &bucket, Some(&key), err))?;

            let e_tag = resp.e_tag().ok_or_else(|| {
                CfmsError::Backup(format!(
                    "S3 UploadPart {part_number} for '{key}' returned no ETag"
                ))
            })?;
            Ok(CompletedPart::builder()
                .part_number(part_number)
                .e_tag(e_tag)
                .build())
        });
        Ok(())
    }

    async fn flush_full_parts(&mut self) -> Result<()> {
        while self.buffer.len() >= self.part_size {
            let chunk = if self.buffer.len() == self.part_size {
                Bytes::from(std::mem::take(&mut self.buffer))
            } else {
                let tail = self.buffer.split_off(self.part_size);
                let head = std::mem::replace(&mut self.buffer, tail);
                Bytes::from(head)
            };
            let permits = self.take_permits_for_bytes(chunk.len());
            self.spawn_part_upload(chunk, permits).await?;
        }
        Ok(())
    }
}

impl StagedStorageWriter for S3StagedWriter {
    fn write_chunk(&mut self, chunk: Bytes) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if chunk.is_empty() {
                return Ok(());
            }
            self.acquire_chunk_permit(chunk.len()).await?;
            self.buffer.extend_from_slice(&chunk);
            self.flush_full_parts().await
        })
    }

    fn finish(mut self: Box<Self>) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            if self.multipart.is_none() {
                let _permits: VecDeque<(usize, OwnedSemaphorePermit)> =
                    std::mem::take(&mut self.permits);
                let body = Bytes::from(std::mem::take(&mut self.buffer));
                self.storage
                    .put_object_no_overwrite(&self.key, body)
                    .await?;
                self.tracker.record_written(self.key).await;
                return Ok(());
            }

            if !self.buffer.is_empty() {
                let tail_bytes = Bytes::from(std::mem::take(&mut self.buffer));
                let tail_permits = self.take_permits_for_bytes(tail_bytes.len());
                if let Err(err) = self.spawn_part_upload(tail_bytes, tail_permits).await {
                    if let Some(ref mut mp) = self.multipart {
                        mp.in_flight.abort_all();
                        let _ = self
                            .storage
                            .abort_multipart_best_effort(&self.key, &mp.upload_id)
                            .await;
                        self.tracker.clear_multipart(&self.key).await;
                    }
                    return Err(err);
                }
            }

            let mut mp = self.multipart.take().expect("multipart active");
            let upload_id = mp.upload_id.clone();

            while let Some(res) = mp.in_flight.join_next().await {
                match res {
                    Ok(Ok(part)) => mp.completed_parts.push(part),
                    Ok(Err(err)) => {
                        mp.in_flight.abort_all();
                        let _ = self
                            .storage
                            .abort_multipart_best_effort(&self.key, &upload_id)
                            .await;
                        self.tracker.clear_multipart(&self.key).await;
                        return Err(err);
                    }
                    Err(join_err) => {
                        mp.in_flight.abort_all();
                        let _ = self
                            .storage
                            .abort_multipart_best_effort(&self.key, &upload_id)
                            .await;
                        self.tracker.clear_multipart(&self.key).await;
                        return Err(CfmsError::Backup(format!(
                            "S3 UploadPart task panicked for '{}': {join_err}",
                            self.key
                        )));
                    }
                }
            }

            mp.completed_parts
                .sort_by_key(|part| part.part_number().unwrap_or(0));

            let complete_res = self
                .storage
                .complete_multipart_no_overwrite(&self.key, &upload_id, mp.completed_parts)
                .await;

            match complete_res {
                Ok(()) => {
                    self.tracker.clear_multipart(&self.key).await;
                    self.tracker.record_written(self.key).await;
                    Ok(())
                }
                Err(err) => {
                    let _ = self
                        .storage
                        .abort_multipart_best_effort(&self.key, &upload_id)
                        .await;
                    self.tracker.clear_multipart(&self.key).await;
                    Err(err)
                }
            }
        })
    }

    fn abort(mut self: Box<Self>) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            if let Some(mut mp) = self.multipart.take() {
                mp.in_flight.abort_all();
                let res = self
                    .storage
                    .abort_multipart_best_effort(&self.key, &mp.upload_id)
                    .await;
                self.tracker.clear_multipart(&self.key).await;
                return res;
            }
            Ok(())
        })
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn bytes_to_kib_permits(byte_len: usize) -> u32 {
    let kib = byte_len.div_ceil(1024).clamp(1, MAX_GLOBAL_S3_BUFFER_PERMITS);
    u32::try_from(kib).unwrap_or(u32::MAX)
}

fn compute_part_size(size_hint: Option<u64>) -> Result<usize> {
    let Some(total_bytes) = size_hint else {
        return Ok(DEFAULT_S3_PART_BYTES);
    };
    let min_for_limit = total_bytes.div_ceil(MAX_S3_PARTS);
    if min_for_limit > MAX_S3_PART_BYTES {
        return Err(CfmsError::Backup(format!(
            "Object size {total_bytes} bytes exceeds S3 multipart upload limit"
        )));
    }
    let aligned_mib = min_for_limit.div_ceil(1024 * 1024) * (1024 * 1024);
    let chosen = aligned_mib
        .max(DEFAULT_S3_PART_BYTES as u64)
        .max(MIN_S3_PART_BYTES as u64);
    usize::try_from(chosen).map_err(|_| {
        CfmsError::Backup(format!(
            "Required S3 part size {chosen} exceeds platform pointer size"
        ))
    })
}

/// Resolve `force_path_style` matching `botocore`'s S3 addressing semantics verified against
/// `D:\projects\cfms_on_websocket`.
#[must_use]
pub(crate) fn resolve_force_path_style(
    style: S3AddressingStyle,
    endpoint_url: Option<&str>,
    bucket: &str,
) -> bool {
    match style {
        S3AddressingStyle::Path => true,
        S3AddressingStyle::Virtual => false,
        S3AddressingStyle::Auto => match endpoint_url {
            Some(raw) => {
                let is_accelerate = url::Url::parse(raw)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                    .is_some_and(|host| {
                        host == "s3-accelerate.amazonaws.com"
                            || host == "s3-accelerate.dualstack.amazonaws.com"
                            || (host.starts_with("s3-accelerate.")
                                && host.ends_with(".amazonaws.com"))
                    });
                !is_accelerate
            }
            None => bucket.contains('.') || !is_dns_compatible_bucket_name(bucket),
        },
    }
}

fn is_dns_compatible_bucket_name(bucket: &str) -> bool {
    let len = bucket.len();
    if !(3..=63).contains(&len) {
        return false;
    }
    if bucket.split('.').any(|label| {
        label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) {
        return false;
    }
    bucket.parse::<std::net::Ipv4Addr>().is_err()
}

fn encode_copy_source_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for byte in key.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(*byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(&mut out, "%{other:02X}");
            }
        }
    }
    out
}

fn is_object_not_found_error<E: ProvideErrorMetadata>(err: &SdkError<E>) -> bool {
    let SdkError::ServiceError(ctx) = err else {
        return false;
    };
    let code = ctx.err().code();
    if code == Some("NoSuchBucket") {
        return false;
    }
    if matches!(code, Some("NoSuchKey" | "NotFound" | "404")) {
        return true;
    }
    ctx.raw().status().as_u16() == 404
}

fn is_missing_upload_or_object_error<E: ProvideErrorMetadata>(err: &SdkError<E>) -> bool {
    if is_object_not_found_error(err) {
        return true;
    }
    let SdkError::ServiceError(ctx) = err else {
        return false;
    };
    ctx.err().code() == Some("NoSuchUpload")
}

fn is_precondition_failed_error<E: ProvideErrorMetadata>(err: &SdkError<E>) -> bool {
    let SdkError::ServiceError(ctx) = err else {
        return false;
    };
    ctx.raw().status().as_u16() == 412 || ctx.err().code() == Some("PreconditionFailed")
}

fn is_not_implemented_error<E: ProvideErrorMetadata>(err: &SdkError<E>) -> bool {
    let SdkError::ServiceError(ctx) = err else {
        return false;
    };
    ctx.raw().status().as_u16() == 501 || ctx.err().code() == Some("NotImplemented")
}

fn classify_s3_error<E>(
    operation: &str,
    bucket: &str,
    key: Option<&str>,
    err: SdkError<E>,
) -> CfmsError
where
    E: ProvideErrorMetadata + std::fmt::Debug + std::error::Error + Send + Sync + 'static,
{
    let target = match key {
        Some(k) => format!("s3://{bucket}/{k}"),
        None => format!("s3://{bucket}"),
    };

    if let SdkError::ServiceError(ctx) = &err {
        let status = ctx.raw().status().as_u16();
        let raw_code = ctx.err().code().unwrap_or("");
        let msg = ctx.err().message().unwrap_or("");
        let effective_code = if raw_code.is_empty() {
            match status {
                401 => "Unauthorized",
                403 => "AccessDenied",
                404 => "NotFound",
                _ => "",
            }
        } else {
            raw_code
        };

        if raw_code == "NoSuchBucket" {
            return CfmsError::Config(format!(
                "S3 {operation} failed for '{target}': bucket '{bucket}' does not exist (NoSuchBucket)"
            ));
        }
        if matches!(
            raw_code,
            "AccessDenied"
                | "InvalidAccessKeyId"
                | "SignatureDoesNotMatch"
                | "ExpiredToken"
                | "InvalidToken"
                | "AuthorizationHeaderMalformed"
                | "InvalidRegionName"
        ) || matches!(status, 401 | 403)
        {
            let detail = if msg.is_empty() {
                format!("HTTP {status} {effective_code}")
            } else {
                format!("HTTP {status} {effective_code}: {msg}")
            };
            return CfmsError::Config(format!(
                "S3 {operation} authentication/permission failed for '{target}': {detail}"
            ));
        }
        if status == 404 {
            return CfmsError::Config(format!(
                "S3 {operation} target not found for '{target}' (HTTP 404 {effective_code})"
            ));
        }
    }

    CfmsError::Backup(format!(
        "S3 {operation} failed for '{target}': {}",
        DisplayErrorContext(&err)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn botocore_addressing_style_parity_matrix() {
        // Explicit path / virtual styles always win regardless of endpoint.
        assert!(resolve_force_path_style(S3AddressingStyle::Path, None, "cfms"));
        assert!(resolve_force_path_style(
            S3AddressingStyle::Path,
            Some("https://s3.us-east-1.amazonaws.com"),
            "cfms"
        ));
        assert!(!resolve_force_path_style(
            S3AddressingStyle::Virtual,
            Some("http://127.0.0.1:9000"),
            "cfms"
        ));

        // Auto + no endpoint: AWS standard virtual-hosted unless dotted/non-DNS bucket.
        assert!(!resolve_force_path_style(S3AddressingStyle::Auto, None, "cfms-assets"));
        assert!(resolve_force_path_style(S3AddressingStyle::Auto, None, "cfms.assets"));
        assert!(resolve_force_path_style(S3AddressingStyle::Auto, None, "192.168.1.1"));

        // Auto + custom endpoint: botocore defaults to path style (MinIO, R2, Ceph, RustFS)
        // except AWS S3 Accelerate.
        assert!(resolve_force_path_style(
            S3AddressingStyle::Auto,
            Some("http://127.0.0.1:9000"),
            "cfms-assets"
        ));
        assert!(resolve_force_path_style(
            S3AddressingStyle::Auto,
            Some("https://acct.r2.cloudflarestorage.com"),
            "cfms-assets"
        ));
        assert!(!resolve_force_path_style(
            S3AddressingStyle::Auto,
            Some("https://s3-accelerate.amazonaws.com"),
            "cfms-assets"
        ));
        assert!(!resolve_force_path_style(
            S3AddressingStyle::Auto,
            Some("https://s3-accelerate.dualstack.amazonaws.com"),
            "cfms-assets"
        ));
    }

    #[test]
    fn encode_copy_source_preserves_slashes_and_escapes_special_bytes() {
        assert_eq!(
            encode_copy_source_key("content/files/2026/11/blob name+1%.bin"),
            "content/files/2026/11/blob%20name%2B1%25.bin"
        );
    }

    #[test]
    fn compute_part_size_respects_bounds_and_scales_above_80gib() {
        assert_eq!(compute_part_size(None).unwrap(), DEFAULT_S3_PART_BYTES);
        assert_eq!(compute_part_size(Some(1024)).unwrap(), DEFAULT_S3_PART_BYTES);
        // 100 GiB requires ceil(100 GiB / 10_000) -> ~11 MiB aligned part size
        let hundred_gib = 100u64 * 1024 * 1024 * 1024;
        assert_eq!(compute_part_size(Some(hundred_gib)).unwrap(), 11 * 1024 * 1024);
    }
}
