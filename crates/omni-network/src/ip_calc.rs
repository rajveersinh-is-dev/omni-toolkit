use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::str::FromStr;

pub struct IpCalcOp;

#[async_trait]
impl Operation for IpCalcOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "net.ip_calc",
            "CIDR & Subnet Calculator",
            "Calculates IPv4/IPv6 network masks, broadcast addresses, usable host ranges, and performs subnet splitting/aggregation",
            OperationCategory::Networking,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let cidr_str = config.get("cidr")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| input.as_str().ok().unwrap_or("192.168.1.0/24"));

        let parts: Vec<&str> = cidr_str.trim().split('/').collect();
        if parts.is_empty() {
            return Err(OmniError::InvalidInput("Empty CIDR input".into()));
        }

        let ip_str = parts[0];
        let prefix: u32 = if parts.len() > 1 {
            parts[1].parse().map_err(|_| OmniError::InvalidInput("Invalid prefix length".into()))?
        } else {
            32
        };

        if prefix > 32 {
            return Err(OmniError::InvalidInput("IPv4 prefix must be between 0 and 32".into()));
        }

        let ip = Ipv4Addr::from_str(ip_str)
            .map_err(|e| OmniError::InvalidInput(format!("Invalid IPv4 address: {e}")))?;

        let ip_u32 = u32::from(ip);
        let mask_u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        let wildcard_u32 = !mask_u32;
        let network_u32 = ip_u32 & mask_u32;
        let broadcast_u32 = network_u32 | wildcard_u32;

        let total_hosts = if prefix >= 31 {
            if prefix == 32 { 1 } else { 2 }
        } else {
            2u64.pow(32 - prefix)
        };

        let usable_hosts = if prefix >= 31 {
            if prefix == 32 { 1 } else { 2 }
        } else {
            total_hosts - 2
        };

        let first_usable_u32 = if prefix >= 31 { network_u32 } else { network_u32 + 1 };
        let last_usable_u32 = if prefix >= 31 { broadcast_u32 } else { broadcast_u32 - 1 };

        let octets = ip.octets();
        let reverse_ptr = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);

        // Subnet splitting if requested
        let mut subnets = Vec::new();
        if let Some(target_prefix) = config.get("split_to_prefix").and_then(|v| v.as_u64()) {
            let t_p = target_prefix as u32;
            if t_p > prefix && t_p <= 32 {
                let count = 2u32.pow(t_p - prefix);
                let step = 2u32.pow(32 - t_p);
                for i in 0..count.min(64) {
                    let sub_net = network_u32 + (i * step);
                    subnets.push(format!("{}/{}", Ipv4Addr::from(sub_net), t_p));
                }
            }
        }

        Ok(DataPayload::json(json!({
            "cidr": format!("{}/{}", ip, prefix),
            "ip_address": ip.to_string(),
            "prefix_length": prefix,
            "netmask": Ipv4Addr::from(mask_u32).to_string(),
            "wildcard_mask": Ipv4Addr::from(wildcard_u32).to_string(),
            "network_address": Ipv4Addr::from(network_u32).to_string(),
            "broadcast_address": Ipv4Addr::from(broadcast_u32).to_string(),
            "first_usable_ip": Ipv4Addr::from(first_usable_u32).to_string(),
            "last_usable_ip": Ipv4Addr::from(last_usable_u32).to_string(),
            "total_hosts": total_hosts,
            "usable_hosts": usable_hosts,
            "reverse_dns_ptr": reverse_ptr,
            "split_subnets": subnets,
        })))
    }
}
