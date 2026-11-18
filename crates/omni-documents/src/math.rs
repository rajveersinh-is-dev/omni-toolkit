use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;

#[derive(Debug, Clone)]
enum MathNode {
    Symbol(String),
    Number(String),
    Operator(String),
    Group(Vec<MathNode>),
    Frac(Box<MathNode>, Box<MathNode>),
    Sqrt(Box<MathNode>),
    Sup(Box<MathNode>, Box<MathNode>),
    Sub(Box<MathNode>, Box<MathNode>),
}

fn latex_symbol_to_unicode(cmd: &str) -> Option<&'static str> {
    match cmd {
        "alpha" => Some("α"),
        "beta" => Some("β"),
        "gamma" => Some("γ"),
        "delta" => Some("δ"),
        "epsilon" => Some("ε"),
        "theta" => Some("θ"),
        "lambda" => Some("λ"),
        "mu" => Some("μ"),
        "pi" => Some("π"),
        "rho" => Some("ρ"),
        "sigma" => Some("σ"),
        "tau" => Some("τ"),
        "phi" => Some("φ"),
        "omega" => Some("ω"),
        "Gamma" => Some("Γ"),
        "Delta" => Some("Δ"),
        "Theta" => Some("Θ"),
        "Lambda" => Some("Λ"),
        "Pi" => Some("Π"),
        "Sigma" => Some("Σ"),
        "Omega" => Some("Ω"),
        "sum" => Some("∑"),
        "prod" => Some("∏"),
        "int" => Some("∫"),
        "infty" => Some("∞"),
        "pm" => Some("±"),
        "times" => Some("×"),
        "cdot" => Some("·"),
        "div" => Some("÷"),
        "neq" => Some("≠"),
        "leq" | "le" => Some("≤"),
        "geq" | "ge" => Some("≥"),
        "approx" => Some("≈"),
        "equiv" => Some("≡"),
        "partial" => Some("∂"),
        "nabla" => Some("∇"),
        "forall" => Some("∀"),
        "exists" => Some("∃"),
        "in" => Some("∈"),
        "to" | "rightarrow" => Some("→"),
        "leftarrow" => Some("←"),
        "Rightarrow" => Some("⇒"),
        _ => None,
    }
}

struct MathParser<'a> {
    chars: Vec<char>,
    pos: usize,
    _marker: std::marker::PhantomData<&'a str>,
}

impl<'a> MathParser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            chars: src.chars().collect(),
            pos: 0,
            _marker: std::marker::PhantomData,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.pos += 1;
        }
    }

    fn parse_seq(&mut self, stop_at_brace: bool) -> Vec<MathNode> {
        let mut nodes = Vec::new();
        while let Some(c) = self.peek() {
            if stop_at_brace && c == '}' {
                self.pos += 1;
                break;
            }
            if c.is_whitespace() {
                self.pos += 1;
                continue;
            }
            if c == '^' || c == '_' {
                self.pos += 1;
                let base = nodes
                    .pop()
                    .unwrap_or_else(|| MathNode::Symbol(String::new()));
                let arg = self.parse_atom();
                if c == '^' {
                    nodes.push(MathNode::Sup(Box::new(base), Box::new(arg)));
                } else {
                    nodes.push(MathNode::Sub(Box::new(base), Box::new(arg)));
                }
                continue;
            }
            nodes.push(self.parse_atom());
        }
        nodes
    }

    fn parse_atom(&mut self) -> MathNode {
        self.skip_ws();
        let Some(c) = self.peek() else {
            return MathNode::Symbol(String::new());
        };

        if c == '{' {
            self.pos += 1;
            let seq = self.parse_seq(true);
            return MathNode::Group(seq);
        }

        if c == '\\' {
            self.pos += 1;
            let mut cmd = String::new();
            while let Some(ch) = self.peek() {
                if ch.is_ascii_alphabetic() {
                    cmd.push(ch);
                    self.pos += 1;
                } else {
                    break;
                }
            }
            return match cmd.as_str() {
                "frac" => {
                    let num = self.parse_atom();
                    let den = self.parse_atom();
                    MathNode::Frac(Box::new(num), Box::new(den))
                }
                "sqrt" => {
                    let inner = self.parse_atom();
                    MathNode::Sqrt(Box::new(inner))
                }
                other => {
                    if let Some(sym) = latex_symbol_to_unicode(other) {
                        MathNode::Operator(sym.to_string())
                    } else {
                        MathNode::Symbol(other.to_string())
                    }
                }
            };
        }

        if c.is_ascii_digit() {
            let mut num = String::new();
            while let Some(ch) = self.peek() {
                if ch.is_ascii_digit() || ch == '.' {
                    num.push(ch);
                    self.pos += 1;
                } else {
                    break;
                }
            }
            return MathNode::Number(num);
        }

        self.pos += 1;
        if "+-*/=<>()[]|,".contains(c) {
            MathNode::Operator(c.to_string())
        } else {
            MathNode::Symbol(c.to_string())
        }
    }
}

fn render_mathml(node: &MathNode) -> String {
    match node {
        MathNode::Symbol(s) => format!("<mi>{}</mi>", html_escape::encode_text(s)),
        MathNode::Number(n) => format!("<mn>{}</mn>", html_escape::encode_text(n)),
        MathNode::Operator(o) => format!("<mo>{}</mo>", html_escape::encode_text(o)),
        MathNode::Group(items) => {
            let inner: String = items.iter().map(render_mathml).collect();
            format!("<mrow>{inner}</mrow>")
        }
        MathNode::Frac(n, d) => format!("<mfrac>{}{}</mfrac>", render_mathml(n), render_mathml(d)),
        MathNode::Sqrt(inner) => format!("<msqrt>{}</msqrt>", render_mathml(inner)),
        MathNode::Sup(b, s) => format!("<msup>{}{}</msup>", render_mathml(b), render_mathml(s)),
        MathNode::Sub(b, s) => format!("<msub>{}{}</msub>", render_mathml(b), render_mathml(s)),
    }
}

fn measure_width(node: &MathNode, font_size: f64) -> f64 {
    match node {
        MathNode::Symbol(s) | MathNode::Number(s) => (s.chars().count() as f64) * font_size * 0.62,
        MathNode::Operator(o) => (o.chars().count() as f64) * font_size * 0.78,
        MathNode::Group(items) => items.iter().map(|n| measure_width(n, font_size) + 2.0).sum(),
        MathNode::Frac(n, d) => {
            measure_width(n, font_size * 0.85).max(measure_width(d, font_size * 0.85)) + 14.0
        }
        MathNode::Sqrt(inner) => measure_width(inner, font_size) + 18.0,
        MathNode::Sup(b, s) | MathNode::Sub(b, s) => {
            measure_width(b, font_size) + measure_width(s, font_size * 0.68) + 2.0
        }
    }
}

fn render_svg_node(node: &MathNode, x: f64, y: f64, font_size: f64, out: &mut String) -> f64 {
    match node {
        MathNode::Symbol(s) => {
            let w = measure_width(node, font_size);
            out.push_str(&format!(
                "  <text x=\"{:.1}\" y=\"{:.1}\" font-size=\"{:.1}\" font-style=\"italic\" class=\"math-sym\">{}</text>\n",
                x, y, font_size, html_escape::encode_text(s)
            ));
            w
        }
        MathNode::Number(n) => {
            let w = measure_width(node, font_size);
            out.push_str(&format!(
                "  <text x=\"{:.1}\" y=\"{:.1}\" font-size=\"{:.1}\" class=\"math-num\">{}</text>\n",
                x, y, font_size, html_escape::encode_text(n)
            ));
            w
        }
        MathNode::Operator(o) => {
            let w = measure_width(node, font_size);
            out.push_str(&format!(
                "  <text x=\"{:.1}\" y=\"{:.1}\" font-size=\"{:.1}\" class=\"math-op\">{}</text>\n",
                x + 2.0,
                y,
                font_size,
                html_escape::encode_text(o)
            ));
            w + 2.0
        }
        MathNode::Group(items) => {
            let mut cx = x;
            for item in items {
                cx += render_svg_node(item, cx, y, font_size, out) + 2.0;
            }
            cx - x
        }
        MathNode::Frac(num, den) => {
            let sub_fs = font_size * 0.82;
            let nw = measure_width(num, sub_fs);
            let dw = measure_width(den, sub_fs);
            let bar_w = nw.max(dw) + 12.0;
            let num_x = x + (bar_w - nw) / 2.0;
            let den_x = x + (bar_w - dw) / 2.0;
            render_svg_node(num, num_x, y - font_size * 0.55, sub_fs, out);
            out.push_str(&format!(
                "  <line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"#f0f6fc\" stroke-width=\"1.5\"/>\n",
                x + 2.0,
                y - font_size * 0.25,
                x + bar_w - 2.0,
                y - font_size * 0.25
            ));
            render_svg_node(den, den_x, y + font_size * 0.72, sub_fs, out);
            bar_w
        }
        MathNode::Sqrt(inner) => {
            let iw = measure_width(inner, font_size);
            out.push_str(&format!(
                "  <polyline points=\"{:.1},{:.1} {:.1},{:.1} {:.1},{:.1} {:.1},{:.1}\" fill=\"none\" stroke=\"#f0f6fc\" stroke-width=\"1.5\"/>\n",
                x,
                y - font_size * 0.2,
                x + 5.0,
                y + 2.0,
                x + 11.0,
                y - font_size * 0.9,
                x + 15.0 + iw,
                y - font_size * 0.9
            ));
            render_svg_node(inner, x + 14.0, y, font_size, out);
            iw + 18.0
        }
        MathNode::Sup(base, sup) => {
            let bw = render_svg_node(base, x, y, font_size, out);
            let sw = render_svg_node(sup, x + bw + 1.0, y - font_size * 0.45, font_size * 0.65, out);
            bw + sw + 2.0
        }
        MathNode::Sub(base, sub) => {
            let bw = render_svg_node(base, x, y, font_size, out);
            let sw = render_svg_node(sub, x + bw + 1.0, y + font_size * 0.25, font_size * 0.65, out);
            bw + sw + 2.0
        }
    }
}

pub struct MathTypesetOp;

#[async_trait]
impl Operation for MathTypesetOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "doc.math_typeset",
            "Mathematical Typesetting (LaTeX subset -> SVG / MathML)",
            "Parses LaTeX math expressions (fractions, roots, super/subscripts, Greek symbols, operators) into MathML or positioned SVG",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Text], vec![DataType::Text])
        .with_status(FeatureStatus::Verified)
        .with_limitations(vec![
            "Supports a practical LaTeX math subset (\\frac, \\sqrt, ^, _, Greek letters, common operators); full TeX macro expansion and matrices are not supported".into(),
        ])
        .with_tags(vec!["math".into(), "latex".into(), "mathml".into(), "svg".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let math_text = input.into_text()?;
        if math_text.trim().is_empty() {
            return Err(OmniError::InvalidInput(
                "Math expression input must not be empty".into(),
            ));
        }

        let format = config.get("format").and_then(|v| v.as_str()).unwrap_or("svg");
        let mut parser = MathParser::new(&math_text);
        let ast = MathNode::Group(parser.parse_seq(false));

        if format == "mathml" {
            let inner = render_mathml(&ast);
            let mathml = format!(
                "<math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"block\">{}</math>",
                inner
            );
            Ok(DataPayload::text(mathml))
        } else {
            let font_size = 24.0;
            let content_w = measure_width(&ast, font_size);
            let svg_w = (content_w + 80.0).max(240.0);
            let svg_h = 104.0;
            let mut body = String::new();
            render_svg_node(&ast, 36.0, 58.0, font_size, &mut body);

            let svg = format!(
                r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {:.0} {:.0}" width="100%" height="{:.0}">
  <style>
    .math-sym, .math-num, .math-op {{ font-family: 'Cambria Math', 'Times New Roman', serif; fill: #f0f6fc; }}
    .bg {{ fill: #161b22; rx: 8px; }}
  </style>
  <rect width="{:.0}" height="{:.0}" class="bg"/>
{}</svg>"##,
                svg_w, svg_h, svg_h, svg_w, svg_h, body
            );
            Ok(DataPayload::text(svg))
        }
    }
}
