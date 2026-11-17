# OMNI Backend Architecture & REST/WebSocket API

## 1. Overview
The OMNI Backend is an asynchronous server built on Tokio and Axum. It serves both the local REST/WebSocket interfaces for the desktop and browser GUIs, and supports direct in-process calling for the CLI and TUI.

## 2. API Endpoints

### 2.1 System & Registry
- `GET /api/v1/health`
  Returns health status, version, uptime, and system capability flags.
- `GET /api/v1/operations`
  Returns the complete catalog of registered operations and their manifests.
- `GET /api/v1/operations/{id}`
  Retrieves detailed manifest, JSON schema, and usage examples for a specific operation.
- `GET /api/v1/operations/search?q={query}&category={category}`
  Fuzzy searches operations by keyword, tag, or category.

### 2.2 Execution & Jobs
- `POST /api/v1/execute`
  Direct synchronous execution of a single operation with inline payload.
- `POST /api/v1/jobs`
  Submits an asynchronous job for background processing. Returns `job_id`.
- `GET /api/v1/jobs/{job_id}`
  Fetches status, execution metrics, resource utilization, and result artifacts for a job.
- `DELETE /api/v1/jobs/{job_id}`
  Cancels a running or queued job.
- `GET /api/v1/jobs`
  Lists historical and active jobs with pagination.

### 2.3 Pipelines
- `POST /api/v1/pipelines/validate`
  Validates a pipeline DAG for cycles, type compatibility, and schema conformance.
- `POST /api/v1/pipelines/execute`
  Submits a pipeline definition for asynchronous execution.
- `GET /api/v1/pipelines`
  Retrieves saved user pipelines from SQLite persistence.
- `POST /api/v1/pipelines`
  Saves a new pipeline definition.

### 2.4 WebSocket Real-Time Progress
- `WS /api/v1/ws/jobs/{job_id}`
  Streams real-time execution events:
  - `JobStarted { job_id, timestamp }`
  - `JobProgress { job_id, stage, percent, bytes_processed, message }`
  - `JobCompleted { job_id, duration_ms, output_metadata }`
  - `JobFailed { job_id, error_code, error_message }`
  - `JobCancelled { job_id }`

## 3. Persistence Schema (SQLite)
The backend uses SQLite (`omni.db`) for lightweight, robust local persistence:
- `jobs`: Stores job metadata, parameters, start/end timestamps, status, and error logs.
- `pipelines`: Stores user-authored and imported pipeline DAG configurations.
- `settings`: Key-value store for user preferences, UI themes, and rate limits.
- `audit_log`: Operation execution logs with automatic secret redaction.
