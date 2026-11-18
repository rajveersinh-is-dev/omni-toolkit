use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, VecDeque};

#[derive(Debug, Clone)]
struct GraphNode {
    id: String,
    label: String,
    shape: NodeShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeShape {
    Rect,
    Rounded,
    Diamond,
}

#[derive(Debug, Clone)]
struct GraphEdge {
    from: String,
    to: String,
    label: Option<String>,
}

#[derive(Debug, Clone)]
struct ParsedGraph {
    direction: String, // "TD" or "LR"
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
}

fn parse_node_token(raw: &str) -> (String, Option<String>, NodeShape) {
    let s = raw.trim().trim_end_matches(';');
    if let Some(idx) = s.find('[') {
        if let Some(end) = s.rfind(']') {
            let id = s[..idx].trim().to_string();
            let lbl = s[idx + 1..end].trim().trim_matches('"').to_string();
            return (id, Some(lbl), NodeShape::Rect);
        }
    }
    if let Some(idx) = s.find('{') {
        if let Some(end) = s.rfind('}') {
            let id = s[..idx].trim().to_string();
            let lbl = s[idx + 1..end].trim().trim_matches('"').to_string();
            return (id, Some(lbl), NodeShape::Diamond);
        }
    }
    if let Some(idx) = s.find('(') {
        if let Some(end) = s.rfind(')') {
            let id = s[..idx].trim().to_string();
            let lbl = s[idx + 1..end].trim().trim_matches('"').to_string();
            return (id, Some(lbl), NodeShape::Rounded);
        }
    }
    (s.trim_matches('"').to_string(), None, NodeShape::Rect)
}

fn parse_mermaid_or_dot(source: &str, diagram_type: &str) -> OmniResult<ParsedGraph> {
    let mut direction = "LR".to_string();
    let mut node_map: BTreeMap<String, GraphNode> = BTreeMap::new();
    let mut node_order: Vec<String> = Vec::new();
    let mut edges: Vec<GraphEdge> = Vec::new();

    let mut ensure_node = |raw: &str| -> String {
        let (id, label_opt, shape) = parse_node_token(raw);
        if id.is_empty() {
            return id;
        }
        if let Some(existing) = node_map.get_mut(&id) {
            if let Some(lbl) = label_opt {
                existing.label = lbl;
                existing.shape = shape;
            }
        } else {
            node_order.push(id.clone());
            node_map.insert(
                id.clone(),
                GraphNode {
                    id: id.clone(),
                    label: label_opt.unwrap_or_else(|| id.clone()),
                    shape,
                },
            );
        }
        id
    };

    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with("%%")
            || line.starts_with("//")
            || line.starts_with('#')
            || line == "{"
            || line == "}"
        {
            continue;
        }

        let lower = line.to_lowercase();
        if lower.starts_with("graph ") || lower.starts_with("flowchart ") {
            if lower.contains("td") || lower.contains("tb") {
                direction = "TD".to_string();
            } else {
                direction = "LR".to_string();
            }
            continue;
        }
        if lower.starts_with("digraph") || lower.starts_with("strict digraph") {
            direction = "TD".to_string();
            continue;
        }
        if lower.starts_with("rankdir") {
            if lower.contains("lr") {
                direction = "LR".to_string();
            } else {
                direction = "TD".to_string();
            }
            continue;
        }

        // Split Mermaid / DOT edge connectors (supports chained A --> B --> C)
        if line.contains("-->") {
            let segments: Vec<&str> = line.split("-->").collect();
            for win in segments.windows(2) {
                let lhs = win[0].trim();
                let rhs_raw = win[1].trim();
                let (rhs, edge_label) = if let Some(rest) = rhs_raw.strip_prefix('|') {
                    if let Some((lbl, target)) = rest.split_once('|') {
                        (target.trim(), Some(lbl.trim().to_string()))
                    } else {
                        (rhs_raw, None)
                    }
                } else {
                    (rhs_raw, None)
                };
                // Strip leading edge label if lhs came from a previous labeled segment
                let lhs_clean = if let Some(rest) = lhs.strip_prefix('|') {
                    rest.split_once('|').map(|(_, t)| t.trim()).unwrap_or(lhs)
                } else {
                    lhs
                };
                let from_id = ensure_node(lhs_clean);
                let to_id = ensure_node(rhs);
                if !from_id.is_empty() && !to_id.is_empty() {
                    edges.push(GraphEdge {
                        from: from_id,
                        to: to_id,
                        label: edge_label,
                    });
                }
            }
        } else if let Some((lhs, rhs)) = line.split_once("->") {
            // Graphviz DOT edge: A -> B [label="foo"];
            let cleaned_rhs = rhs.trim().trim_end_matches(';');
            let (target, edge_label) = if let Some((t, attr)) = cleaned_rhs.split_once('[') {
                let lbl = attr
                    .split("label=")
                    .nth(1)
                    .map(|s| s.trim().trim_end_matches(']').trim_matches('"').to_string());
                (t.trim(), lbl)
            } else {
                (cleaned_rhs, None)
            };
            let from_id = ensure_node(lhs);
            let to_id = ensure_node(target);
            if !from_id.is_empty() && !to_id.is_empty() {
                edges.push(GraphEdge {
                    from: from_id,
                    to: to_id,
                    label: edge_label,
                });
            }
        } else if let Some((lhs, rhs)) = line.split_once("---") {
            let from_id = ensure_node(lhs);
            let to_id = ensure_node(rhs);
            if !from_id.is_empty() && !to_id.is_empty() {
                edges.push(GraphEdge {
                    from: from_id,
                    to: to_id,
                    label: None,
                });
            }
        } else if diagram_type == "mermaid" || diagram_type == "dot" || diagram_type == "graphviz" {
            // Standalone node declaration like A[Start]
            if line.contains('[') || line.contains('(') || line.contains('{') {
                let _ = ensure_node(line);
            }
        }
    }

    if node_order.is_empty() {
        return Err(OmniError::InvalidInput(format!(
            "No valid {} diagram nodes or edges parsed from source",
            diagram_type
        )));
    }

    let nodes = node_order
        .into_iter()
        .filter_map(|id| node_map.remove(&id))
        .collect();

    Ok(ParsedGraph {
        direction,
        nodes,
        edges,
    })
}

fn render_graph_svg(graph: &ParsedGraph, diagram_type: &str) -> String {
    // Compute topological layer (rank) for each node using longest-path BFS
    let mut in_deg: HashMap<&str, usize> = HashMap::new();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for n in &graph.nodes {
        in_deg.insert(n.id.as_str(), 0);
        adj.insert(n.id.as_str(), Vec::new());
    }
    for e in &graph.edges {
        if let Some(d) = in_deg.get_mut(e.to.as_str()) {
            *d += 1;
        }
        if let Some(list) = adj.get_mut(e.from.as_str()) {
            list.push(e.to.as_str());
        }
    }

    let mut rank: HashMap<&str, usize> = HashMap::new();
    let mut q: VecDeque<&str> = VecDeque::new();
    for n in &graph.nodes {
        if in_deg.get(n.id.as_str()).copied().unwrap_or(0) == 0 {
            rank.insert(n.id.as_str(), 0);
            q.push_back(n.id.as_str());
        }
    }
    // Handle cyclic diagrams gracefully by seeding remaining nodes at rank 0
    if q.is_empty() {
        if let Some(first) = graph.nodes.first() {
            rank.insert(first.id.as_str(), 0);
            q.push_back(first.id.as_str());
        }
    }

    let mut visited_steps = 0usize;
    let max_steps = graph.nodes.len().saturating_mul(graph.edges.len().max(1)) + 16;
    while let Some(u) = q.pop_front() {
        visited_steps += 1;
        if visited_steps > max_steps {
            break;
        }
        let u_rank = rank.get(u).copied().unwrap_or(0);
        if let Some(neighbors) = adj.get(u) {
            for &v in neighbors {
                let next_rank = u_rank + 1;
                let entry = rank.entry(v).or_insert(0);
                if next_rank > *entry && next_rank <= graph.nodes.len() {
                    *entry = next_rank;
                    q.push_back(v);
                }
            }
        }
    }

    let mut layers: BTreeMap<usize, Vec<&GraphNode>> = BTreeMap::new();
    for n in &graph.nodes {
        let r = rank.get(n.id.as_str()).copied().unwrap_or(0);
        layers.entry(r).or_default().push(n);
    }

    let node_w = 160.0f64;
    let node_h = 52.0f64;
    let gap_x = 80.0f64;
    let gap_y = 64.0f64;
    let margin = 48.0f64;

    let mut positions: HashMap<&str, (f64, f64)> = HashMap::new();
    let mut max_x = 400.0f64;
    let mut max_y = 220.0f64;

    for (layer_idx, nodes_in_layer) in &layers {
        for (slot_idx, node) in nodes_in_layer.iter().enumerate() {
            let (x, y) = if graph.direction == "TD" {
                let x = margin + (slot_idx as f64) * (node_w + gap_x);
                let y = margin + 32.0 + (*layer_idx as f64) * (node_h + gap_y);
                (x, y)
            } else {
                let x = margin + (*layer_idx as f64) * (node_w + gap_x);
                let y = margin + 32.0 + (slot_idx as f64) * (node_h + gap_y);
                (x, y)
            };
            positions.insert(node.id.as_str(), (x, y));
            max_x = max_x.max(x + node_w + margin);
            max_y = max_y.max(y + node_h + margin);
        }
    }

    let mut svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {:.0} {:.0}" width="100%" height="{:.0}">
  <style>
    .node {{ fill: #21262d; stroke: #58a6ff; stroke-width: 2px; }}
    .node-text {{ fill: #f0f6fc; font-family: system-ui, -apple-system, sans-serif; font-size: 13px; text-anchor: middle; dominant-baseline: middle; }}
    .edge {{ stroke: #8b949e; stroke-width: 2px; fill: none; marker-end: url(#arrow); }}
    .edge-label {{ fill: #c9d1d9; font-family: monospace; font-size: 11px; text-anchor: middle; }}
    .title {{ fill: #58a6ff; font-family: system-ui, sans-serif; font-size: 14px; font-weight: bold; }}
  </style>
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#8b949e"/>
    </marker>
  </defs>
  <rect width="{:.0}" height="{:.0}" fill="#0f1117" rx="8"/>
  <text x="24" y="28" class="title">{} ({} nodes, {} edges)</text>
"##,
        max_x,
        max_y,
        max_y,
        max_x,
        max_y,
        html_escape::encode_text(diagram_type),
        graph.nodes.len(),
        graph.edges.len()
    );

    // Draw edges
    for edge in &graph.edges {
        if let (Some(&(x1, y1)), Some(&(x2, y2))) = (
            positions.get(edge.from.as_str()),
            positions.get(edge.to.as_str()),
        ) {
            let (sx, sy, ex, ey) = if graph.direction == "TD" {
                (x1 + node_w / 2.0, y1 + node_h, x2 + node_w / 2.0, y2)
            } else {
                (x1 + node_w, y1 + node_h / 2.0, x2, y2 + node_h / 2.0)
            };
            svg.push_str(&format!(
                "  <line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" class=\"edge\"/>\n",
                sx, sy, ex, ey
            ));
            if let Some(ref lbl) = edge.label {
                let mx = (sx + ex) / 2.0;
                let my = (sy + ey) / 2.0 - 6.0;
                svg.push_str(&format!(
                    "  <text x=\"{:.1}\" y=\"{:.1}\" class=\"edge-label\">{}</text>\n",
                    mx,
                    my,
                    html_escape::encode_text(lbl)
                ));
            }
        }
    }

    // Draw nodes
    for node in &graph.nodes {
        if let Some(&(x, y)) = positions.get(node.id.as_str()) {
            let cx = x + node_w / 2.0;
            let cy = y + node_h / 2.0;
            match node.shape {
                NodeShape::Diamond => {
                    let pts = format!(
                        "{:.1},{:.1} {:.1},{:.1} {:.1},{:.1} {:.1},{:.1}",
                        cx,
                        y,
                        x + node_w,
                        cy,
                        cx,
                        y + node_h,
                        x,
                        cy
                    );
                    svg.push_str(&format!(
                        "  <polygon points=\"{}\" class=\"node\"/>\n",
                        pts
                    ));
                }
                NodeShape::Rounded => {
                    svg.push_str(&format!(
                        "  <rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" rx=\"20\" class=\"node\"/>\n",
                        x, y, node_w, node_h
                    ));
                }
                NodeShape::Rect => {
                    svg.push_str(&format!(
                        "  <rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" rx=\"6\" class=\"node\"/>\n",
                        x, y, node_w, node_h
                    ));
                }
            }
            svg.push_str(&format!(
                "  <text x=\"{:.1}\" y=\"{:.1}\" class=\"node-text\">{}</text>\n",
                cx,
                cy,
                html_escape::encode_text(&node.label)
            ));
        }
    }

    svg.push_str("</svg>");
    svg
}

pub struct DiagramCompilerOp;

#[async_trait]
impl Operation for DiagramCompilerOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "doc.diagram_compiler",
            "Diagram-as-Code Compiler (Mermaid / DOT)",
            "Parses Mermaid flowcharts and Graphviz DOT digraphs and renders layered vector SVG diagrams",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Text], vec![DataType::Text])
        .with_status(FeatureStatus::Verified)
        .with_limitations(vec![
            "Supports Mermaid graph/flowchart syntax and Graphviz DOT directed edges; sequence/Gantt/PlantUML/D2/Vega-Lite are not supported by the built-in offline renderer".into(),
        ])
        .with_tags(vec!["diagram".into(), "mermaid".into(), "dot".into(), "svg".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let diagram_type = config
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("mermaid");
        let source = input.into_text()?;
        let parsed = parse_mermaid_or_dot(&source, diagram_type)?;
        let svg = render_graph_svg(&parsed, diagram_type);
        Ok(DataPayload::text(svg))
    }
}
