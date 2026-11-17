//! `omni-visualization` provides text, terminal, and structured visual formatting
//! utilities for the OMNI engineering platform, including custom hex viewers,
//! dynamic tables (ASCII/Unicode/Markdown), tree renderers, and statistical sparklines.

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// Configuration for hex dump generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexConfig {
    /// Number of bytes displayed per row (typically 16).
    pub bytes_per_row: usize,
    /// Byte grouping count (e.g., 1 byte or 2 bytes grouped together).
    pub group_by: usize,
    /// Whether to render the ASCII representation alongside the hex.
    pub show_ascii: bool,
    /// Whether to display the offset address at the start of each row.
    pub show_offsets: bool,
    /// Whether to format hex digits in uppercase (`0A`) or lowercase (`0a`).
    pub uppercase: bool,
}

impl Default for HexConfig {
    fn default() -> Self {
        Self {
            bytes_per_row: 16,
            group_by: 1,
            show_ascii: true,
            show_offsets: true,
            uppercase: false,
        }
    }
}

/// Formats raw byte data into a clean, human-readable hex dump string.
pub fn render_hex_dump(data: &[u8], config: &HexConfig) -> String {
    if data.is_empty() {
        return "<Empty Buffer (0 bytes)>".to_string();
    }

    let bpr = if config.bytes_per_row == 0 { 16 } else { config.bytes_per_row };
    let group = if config.group_by == 0 { 1 } else { config.group_by };
    let mut out = String::new();

    for (row_idx, chunk) in data.chunks(bpr).enumerate() {
        let offset = row_idx * bpr;

        // 1. Offset column
        if config.show_offsets {
            let _ = write!(out, "{:08x}  ", offset);
        }

        // 2. Hex bytes column
        let mut hex_part = String::new();
        for (i, &b) in chunk.iter().enumerate() {
            if i > 0 && i % group == 0 {
                hex_part.push(' ');
            }
            if config.uppercase {
                let _ = write!(hex_part, "{:02X}", b);
            } else {
                let _ = write!(hex_part, "{:02x}", b);
            }
        }

        // Pad hex column if chunk is shorter than bytes_per_row
        let total_hex_chars = bpr * 2 + (bpr / group).saturating_sub(1);
        let actual_hex_chars = hex_part.len();
        out.push_str(&hex_part);
        if actual_hex_chars < total_hex_chars {
            for _ in 0..(total_hex_chars - actual_hex_chars) {
                out.push(' ');
            }
        }

        // 3. ASCII column
        if config.show_ascii {
            out.push_str("  |");
            for &b in chunk {
                if (0x20..=0x7E).contains(&b) {
                    out.push(b as char);
                } else {
                    out.push('.');
                }
            }
            // Pad remaining ascii space if short chunk
            if chunk.len() < bpr {
                for _ in 0..(bpr - chunk.len()) {
                    out.push(' ');
                }
            }
            out.push('|');
        }

        out.push('\n');
    }

    out
}

/// Text alignment within table cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alignment {
    Left,
    Center,
    Right,
}

/// Table styling variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TableStyle {
    Ascii,
    Unicode,
    Markdown,
}

/// A single column definition for `AsciiTable`.
#[derive(Debug, Clone)]
pub struct TableColumn {
    pub title: String,
    pub align: Alignment,
    pub max_width: Option<usize>,
}

impl TableColumn {
    pub fn new(title: impl Into<String>, align: Alignment) -> Self {
        Self {
            title: title.into(),
            align,
            max_width: None,
        }
    }
}

/// Formatter for multi-column structured tables.
#[derive(Debug, Clone)]
pub struct AsciiTable {
    columns: Vec<TableColumn>,
    rows: Vec<Vec<String>>,
    style: TableStyle,
}

impl AsciiTable {
    pub fn new(columns: Vec<TableColumn>, style: TableStyle) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            style,
        }
    }

    pub fn add_row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    pub fn render(&self) -> String {
        if self.columns.is_empty() {
            return String::new();
        }

        // Calculate column widths
        let mut col_widths: Vec<usize> = self.columns.iter().map(|c| c.title.len()).collect();

        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < col_widths.len() {
                    let len = cell.chars().count();
                    if len > col_widths[i] {
                        col_widths[i] = len;
                    }
                }
            }
        }

        // Enforce max_width if specified
        for (i, col) in self.columns.iter().enumerate() {
            if let Some(max) = col.max_width {
                if col_widths[i] > max {
                    col_widths[i] = max;
                }
            }
        }

        let mut out = String::new();

        // Render based on style
        match self.style {
            TableStyle::Markdown => self.render_markdown(&col_widths, &mut out),
            TableStyle::Ascii => self.render_boxed(&col_widths, false, &mut out),
            TableStyle::Unicode => self.render_boxed(&col_widths, true, &mut out),
        }

        out
    }

    fn render_markdown(&self, widths: &[usize], out: &mut String) {
        // Header
        out.push('|');
        for (i, col) in self.columns.iter().enumerate() {
            let padded = format_cell(&col.title, widths[i], col.align);
            out.push(' ');
            out.push_str(&padded);
            out.push_str(" |");
        }
        out.push('\n');

        // Separator
        out.push('|');
        for (i, col) in self.columns.iter().enumerate() {
            out.push(' ');
            let w = widths[i];
            let dashes = "-".repeat(w.max(3));
            match col.align {
                Alignment::Left => {
                    let _ = write!(out, ":{} |", &dashes[1..]);
                }
                Alignment::Right => {
                    let _ = write!(out, "{}: |", &dashes[..dashes.len() - 1]);
                }
                Alignment::Center => {
                    let _ = write!(out, ":{}: |", &dashes[1..dashes.len() - 1]);
                }
            }
        }
        out.push('\n');

        // Rows
        for row in &self.rows {
            out.push('|');
            for (i, col) in self.columns.iter().enumerate() {
                let cell = row.get(i).map(|s| s.as_str()).unwrap_or("");
                let padded = format_cell(cell, widths[i], col.align);
                out.push(' ');
                out.push_str(&padded);
                out.push_str(" |");
            }
            out.push('\n');
        }
    }

    fn render_boxed(&self, widths: &[usize], unicode: bool, out: &mut String) {
        let (tl, tm, tr, bl, bm, br, ml, mm, mr, h, v) = if unicode {
            ('┌', '┬', '┐', '└', '┴', '┘', '├', '┼', '┤', '─', '│')
        } else {
            ('+', '+', '+', '+', '+', '+', '+', '+', '+', '-', '|')
        };

        // Top border
        out.push(tl);
        for (i, &w) in widths.iter().enumerate() {
            for _ in 0..(w + 2) {
                out.push(h);
            }
            if i + 1 < widths.len() {
                out.push(tm);
            }
        }
        out.push(tr);
        out.push('\n');

        // Header titles
        out.push(v);
        for (i, col) in self.columns.iter().enumerate() {
            out.push(' ');
            out.push_str(&format_cell(&col.title, widths[i], col.align));
            out.push(' ');
            out.push(v);
        }
        out.push('\n');

        // Header separator
        out.push(ml);
        for (i, &w) in widths.iter().enumerate() {
            for _ in 0..(w + 2) {
                out.push(h);
            }
            if i + 1 < widths.len() {
                out.push(mm);
            }
        }
        out.push(mr);
        out.push('\n');

        // Data rows
        for row in &self.rows {
            out.push(v);
            for (i, col) in self.columns.iter().enumerate() {
                let cell = row.get(i).map(|s| s.as_str()).unwrap_or("");
                out.push(' ');
                out.push_str(&format_cell(cell, widths[i], col.align));
                out.push(' ');
                out.push(v);
            }
            out.push('\n');
        }

        // Bottom border
        out.push(bl);
        for (i, &w) in widths.iter().enumerate() {
            for _ in 0..(w + 2) {
                out.push(h);
            }
            if i + 1 < widths.len() {
                out.push(bm);
            }
        }
        out.push(br);
        out.push('\n');
    }
}

fn format_cell(text: &str, width: usize, align: Alignment) -> String {
    let char_count = text.chars().count();
    if char_count >= width {
        return text.chars().take(width).collect();
    }
    let diff = width - char_count;
    match align {
        Alignment::Left => format!("{}{}", text, " ".repeat(diff)),
        Alignment::Right => format!("{}{}", " ".repeat(diff), text),
        Alignment::Center => {
            let left = diff / 2;
            let right = diff - left;
            format!("{}{}{}", " ".repeat(left), text, " ".repeat(right))
        }
    }
}

/// A node in a hierarchical tree structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    pub label: String,
    pub metadata: Option<String>,
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            metadata: None,
            children: Vec::new(),
        }
    }

    pub fn with_metadata(mut self, meta: impl Into<String>) -> Self {
        self.metadata = Some(meta.into());
        self
    }

    pub fn add_child(&mut self, child: TreeNode) {
        self.children.push(child);
    }
}

/// Renders a tree structure with standard branch connectors (`├── `, `└── `).
pub fn render_tree(root: &TreeNode) -> String {
    let mut out = String::new();
    let label = match &root.metadata {
        Some(meta) => format!("{} [{}]", root.label, meta),
        None => root.label.clone(),
    };
    out.push_str(&label);
    out.push('\n');

    render_tree_children(&root.children, "", &mut out);
    out
}

fn render_tree_children(children: &[TreeNode], prefix: &str, out: &mut String) {
    let count = children.len();
    for (i, child) in children.iter().enumerate() {
        let is_last = i + 1 == count;
        let connector = if is_last { "└── " } else { "├── " };
        let meta_str = match &child.metadata {
            Some(m) => format!(" [{}]", m),
            None => String::new(),
        };

        out.push_str(prefix);
        out.push_str(connector);
        out.push_str(&child.label);
        out.push_str(&meta_str);
        out.push('\n');

        let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
        render_tree_children(&child.children, &child_prefix, out);
    }
}

/// Unicode sparkline generator for continuous metrics.
pub fn render_sparkline(values: &[f64]) -> String {
    if values.is_empty() {
        return String::new();
    }

    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);

    let bars = [' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let range = max - min;

    let mut out = String::with_capacity(values.len());
    for &v in values {
        if range.abs() < 1e-12 {
            out.push(bars[bars.len() / 2]);
        } else {
            let norm = ((v - min) / range).clamp(0.0, 1.0);
            let idx = ((norm * (bars.len() - 1) as f64).round() as usize).min(bars.len() - 1);
            out.push(bars[idx]);
        }
    }
    out
}

/// Renders a horizontal ASCII/Unicode bar chart.
pub fn render_bar_chart(items: &[(&str, f64)], bar_max_width: usize) -> String {
    if items.is_empty() {
        return String::new();
    }

    let max_val = items.iter().map(|(_, v)| *v).fold(0.0_f64, f64::max);
    let label_width = items.iter().map(|(l, _)| l.len()).max().unwrap_or(0);

    let mut out = String::new();
    for (label, val) in items {
        let _ = write!(out, "{:width$} | ", label, width = label_width);
        let bar_len = if max_val > 0.0 {
            ((*val / max_val) * bar_max_width as f64).round() as usize
        } else {
            0
        };
        let bar: String = "█".repeat(bar_len);
        let _ = writeln!(out, "{:<w$} {:.2}", bar, val, w = bar_max_width);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_dump_basic() {
        let data = b"Hello, World!\x00\x01\x02";
        let config = HexConfig::default();
        let dump = render_hex_dump(data, &config);
        assert!(dump.contains("00000000"));
        assert!(dump.contains("48 65 6c 6c 6f"));
        assert!(dump.contains("|Hello, World!...|"));
    }

    #[test]
    fn test_table_markdown() {
        let cols = vec![
            TableColumn::new("Tool", Alignment::Left),
            TableColumn::new("Category", Alignment::Center),
            TableColumn::new("Latency", Alignment::Right),
        ];
        let mut table = AsciiTable::new(cols, TableStyle::Markdown);
        table.add_row(vec!["crypto.hash".into(), "Security".into(), "12ms".into()]);
        let rendered = table.render();
        assert!(rendered.contains("| Tool"));
        assert!(rendered.contains("| crypto.hash"));
        assert!(rendered.contains("Security"));
        assert!(rendered.contains("12ms"));
    }

    #[test]
    fn test_tree_rendering() {
        let mut root = TreeNode::new("Project Root");
        let mut src = TreeNode::new("src").with_metadata("directory");
        src.add_child(TreeNode::new("main.rs").with_metadata("file"));
        root.add_child(src);
        root.add_child(TreeNode::new("Cargo.toml").with_metadata("config"));

        let tree = render_tree(&root);
        assert!(tree.contains("Project Root"));
        assert!(tree.contains("├── src [directory]"));
        assert!(tree.contains("│   └── main.rs [file]"));
        assert!(tree.contains("└── Cargo.toml [config]"));
    }

    #[test]
    fn test_sparkline() {
        let values = vec![0.0, 2.5, 5.0, 7.5, 10.0];
        let spark = render_sparkline(&values);
        assert_eq!(spark.chars().count(), 5);
        assert_eq!(spark.chars().next().unwrap(), ' ');
        assert_eq!(spark.chars().last().unwrap(), '█');
    }

    #[test]
    fn test_bar_chart() {
        let items = vec![("read", 10.0), ("write", 25.0), ("sync", 5.0)];
        let chart = render_bar_chart(&items, 20);
        assert!(chart.contains("write | "));
        assert!(chart.contains("25.00"));
    }
}
