use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

pub struct SystemTraceOp;

#[derive(Debug, Default)]
struct SyscallStat {
    count: usize,
    errors: usize,
    total_time_us: f64,
    times_us: Vec<f64>,
}

#[async_trait]
impl Operation for SystemTraceOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "system.trace",
            "Syscall & Process Trace Analyzer",
            "Parses strace and eBPF logs, computing syscall latency percentiles, error rates, and detecting file descriptor leaks",
            OperationCategory::SystemDiagnostics,
        )
        .with_types(vec![DataType::Text], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let text = input.into_text().unwrap_or_default();
        let mut stats: HashMap<String, SyscallStat> = HashMap::new();
        let mut open_fds: HashSet<i32> = HashSet::new();
        let mut leaked_fds: Vec<i32> = Vec::new();
        let mut total_lines = 0;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('+') || trimmed.starts_with('-') {
                continue;
            }
            total_lines += 1;

            // Extract syscall name: before first '('
            if let Some(open_paren) = trimmed.find('(') {
                let call_name = trimmed[..open_paren].trim().to_string();

                // Extract duration if present at end <0.000045>
                let duration_us = if let (Some(start_angle), Some(end_angle)) = (trimmed.rfind('<'), trimmed.rfind('>')) {
                    if start_angle < end_angle {
                        trimmed[start_angle + 1..end_angle].parse::<f64>().unwrap_or(0.0) * 1_000_000.0
                    } else { 0.0 }
                } else { 0.0 };

                // Extract return value: after '='
                let is_error = trimmed.contains("= -1");

                // FD tracking: open, openat, socket vs close
                if (call_name == "open" || call_name == "openat" || call_name == "socket") && !is_error {
                    if let Some(eq_idx) = trimmed.find('=') {
                        let ret_part = trimmed[eq_idx + 1..].trim();
                        let fd_str = ret_part.split_whitespace().next().unwrap_or("");
                        if let Ok(fd) = fd_str.parse::<i32>() {
                            if fd >= 0 {
                                open_fds.insert(fd);
                            }
                        }
                    }
                } else if call_name == "close" {
                    if let Some(open_p) = trimmed.find('(') {
                        let arg_part = &trimmed[open_p + 1..];
                        if let Some(close_p) = arg_part.find(')') {
                            let fd_str = arg_part[..close_p].trim();
                            if let Ok(fd) = fd_str.parse::<i32>() {
                                open_fds.remove(&fd);
                            }
                        }
                    }
                }

                let entry = stats.entry(call_name).or_default();
                entry.count += 1;
                if is_error {
                    entry.errors += 1;
                }
                entry.total_time_us += duration_us;
                entry.times_us.push(duration_us);
            }
        }

        if total_lines == 0 {
            return Err(OmniError::InvalidInput("No valid syscall trace lines found in input".into()));
        }

        for &fd in &open_fds {
            leaked_fds.push(fd);
        }
        leaked_fds.sort_unstable();

        let mut syscall_summary = Vec::new();
        for (name, mut s) in stats {
            s.times_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let p50 = s.times_us[s.times_us.len() / 2];
            let p95_idx = ((s.times_us.len() as f64) * 0.95) as usize;
            let p95 = s.times_us[p95_idx.min(s.times_us.len() - 1)];

            syscall_summary.push(json!({
                "syscall": name,
                "calls": s.count,
                "errors": s.errors,
                "avg_latency_us": (s.total_time_us / s.count as f64 * 100.0).round() / 100.0,
                "p50_latency_us": (p50 * 100.0).round() / 100.0,
                "p95_latency_us": (p95 * 100.0).round() / 100.0,
            }));
        }

        syscall_summary.sort_by(|a, b| {
            let ca = a["calls"].as_u64().unwrap_or(0);
            let cb = b["calls"].as_u64().unwrap_or(0);
            cb.cmp(&ca)
        });

        Ok(DataPayload::json(json!({
            "total_trace_lines": total_lines,
            "unique_syscalls": syscall_summary.len(),
            "potential_fd_leaks": leaked_fds,
            "has_fd_leaks": !leaked_fds.is_empty(),
            "syscalls": syscall_summary,
        })))
    }
}
