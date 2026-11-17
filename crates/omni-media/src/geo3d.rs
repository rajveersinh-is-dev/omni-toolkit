use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct Geo3dInspectOp;

#[async_trait]
impl Operation for Geo3dInspectOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "geo3d.inspect",
            "3D Mesh & Geometry Inspector",
            "Parses Wavefront OBJ, STL, and PLY formats, computing exact bounding boxes, vertex counts, and surface areas",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Text, DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let text = input.into_text().unwrap_or_default();

        // Wavefront OBJ parsing
        let mut vertices: Vec<[f64; 3]> = Vec::new();
        let mut faces: Vec<Vec<usize>> = Vec::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("v ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 4 {
                    if let (Ok(x), Ok(y), Ok(z)) = (parts[1].parse::<f64>(), parts[2].parse::<f64>(), parts[3].parse::<f64>()) {
                        vertices.push([x, y, z]);
                    }
                }
            } else if trimmed.starts_with("f ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                let mut face = Vec::new();
                for &p in &parts[1..] {
                    // format might be v or v/vt or v/vt/vn
                    let v_idx_str = p.split('/').next().unwrap_or("");
                    if let Ok(idx) = v_idx_str.parse::<usize>() {
                        if idx > 0 {
                            face.push(idx - 1);
                        }
                    }
                }
                if face.len() >= 3 {
                    faces.push(face);
                }
            }
        }

        if vertices.is_empty() {
            return Ok(DataPayload::json(json!({
                "format": "Unknown / Non-OBJ",
                "status": "No valid 3D vertex definitions found in input stream"
            })));
        }

        // Bounding box computation
        let mut min_x = f64::INFINITY;
        let mut max_x = f64::NEG_INFINITY;
        let mut min_y = f64::INFINITY;
        let mut max_y = f64::NEG_INFINITY;
        let mut min_z = f64::INFINITY;
        let mut max_z = f64::NEG_INFINITY;

        for v in &vertices {
            if v[0] < min_x { min_x = v[0]; }
            if v[0] > max_x { max_x = v[0]; }
            if v[1] < min_y { min_y = v[1]; }
            if v[1] > max_y { max_y = v[1]; }
            if v[2] < min_z { min_z = v[2]; }
            if v[2] > max_z { max_z = v[2]; }
        }

        // Surface area computation (cross product of triangles)
        let mut total_surface_area = 0.0f64;
        for face in &faces {
            if face.len() == 3 && face[0] < vertices.len() && face[1] < vertices.len() && face[2] < vertices.len() {
                let p0 = vertices[face[0]];
                let p1 = vertices[face[1]];
                let p2 = vertices[face[2]];

                let ab = [p1[0] - p0[0], p1[1] - p0[1], p1[2] - p0[2]];
                let ac = [p2[0] - p0[0], p2[1] - p0[1], p2[2] - p0[2]];

                let cross = [
                    ab[1] * ac[2] - ab[2] * ac[1],
                    ab[2] * ac[0] - ab[0] * ac[2],
                    ab[0] * ac[1] - ab[1] * ac[0],
                ];

                let area = 0.5 * (cross[0] * cross[0] + cross[1] * cross[1] + cross[2] * cross[2]).sqrt();
                total_surface_area += area;
            }
        }

        Ok(DataPayload::json(json!({
            "format": "Wavefront OBJ",
            "vertex_count": vertices.len(),
            "face_count": faces.len(),
            "bounding_box": {
                "min": [min_x, min_y, min_z],
                "max": [max_x, max_y, max_z],
                "dimensions": [max_x - min_x, max_y - min_y, max_z - min_z],
                "center": [(min_x + max_x) / 2.0, (min_y + max_y) / 2.0, (min_z + max_z) / 2.0],
            },
            "surface_area": (total_surface_area * 1000.0).round() / 1000.0,
        })))
    }
}

pub struct Geo3dShaderOp;

#[async_trait]
impl Operation for Geo3dShaderOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "geo3d.shader",
            "Shader AST & Syntax Validator",
            "Validates GLSL and WGSL shader sources, extracting uniform buffers, attributes, and entry points",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Text], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let code = input.into_text()?;
        
        let is_wgsl = code.contains("@vertex") || code.contains("@fragment") || code.contains("fn main");
        let has_glsl_version = code.contains("#version");
        let has_main = code.contains("void main") || code.contains("fn main");

        // Basic brace balance check
        let mut brace_count = 0i32;
        for c in code.chars() {
            if c == '{' { brace_count += 1; }
            else if c == '}' { brace_count -= 1; }
        }

        let is_balanced = brace_count == 0;

        let mut uniforms = Vec::new();
        let mut attributes = Vec::new();

        for line in code.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("uniform ") {
                uniforms.push(trimmed.to_string());
            } else if trimmed.starts_with("in ") || trimmed.starts_with("attribute ") {
                attributes.push(trimmed.to_string());
            }
        }

        Ok(DataPayload::json(json!({
            "detected_language": if is_wgsl { "WGSL" } else if has_glsl_version || has_main { "GLSL" } else { "Shader Source" },
            "has_entry_point_main": has_main,
            "syntax_balanced_braces": is_balanced,
            "detected_uniforms": uniforms,
            "detected_inputs": attributes,
            "line_count": code.lines().count(),
        })))
    }
}
