use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use omni_core::{DataPayload, ExecutionContext, OperationCategory};
use omni_registry::OperationRegistry;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::io;
use std::sync::{Arc, RwLock};

enum FocusedPane {
    Categories,
    Operations,
    Input,
    Output,
}

struct App {
    categories: Vec<OperationCategory>,
    selected_category_idx: usize,
    operations_list_state: ListState,
    focused_pane: FocusedPane,
    input_text: String,
    output_text: String,
    search_query: String,
    searching: bool,
    registry: Arc<RwLock<OperationRegistry>>,
    should_quit: bool,
}

impl App {
    fn new(registry: Arc<RwLock<OperationRegistry>>) -> Self {
        let categories = vec![
            OperationCategory::Cryptography,
            OperationCategory::Encoders,
            OperationCategory::TextAndCode,
            OperationCategory::DocumentsAndMedia,
            OperationCategory::Networking,
            OperationCategory::BinaryAnalysis,
            OperationCategory::StorageAndFormats,
            OperationCategory::CloudAndDevOps,
            OperationCategory::AiAndTensors,
            OperationCategory::SystemDiagnostics,
        ];
        let mut op_state = ListState::default();
        op_state.select(Some(0));

        Self {
            categories,
            selected_category_idx: 0,
            operations_list_state: op_state,
            focused_pane: FocusedPane::Categories,
            input_text: String::from("Hello OMNI Engineering Multitool"),
            output_text: String::from("Ready for execution. Press Enter or Ctrl+R to run."),
            search_query: String::new(),
            searching: false,
            registry,
            should_quit: false,
        }
    }

    fn current_operations(&self) -> Vec<omni_core::OperationManifest> {
        let reg = self.registry.read().unwrap();
        if self.searching && !self.search_query.is_empty() {
            reg.search(&self.search_query)
        } else {
            let cat = self.categories[self.selected_category_idx];
            reg.filter_by_category(cat)
        }
    }

    async fn execute_selected(&mut self) {
        let ops = self.current_operations();
        if let Some(idx) = self.operations_list_state.selected() {
            if let Some(manifest) = ops.get(idx) {
                let op = {
                    let reg = self.registry.read().unwrap();
                    reg.get(&manifest.id)
                };

                if let Some(op) = op {
                    let ctx = ExecutionContext::new("tui_run");
                    let input = DataPayload::text(self.input_text.clone());
                    match op.execute(input, serde_json::json!({}), &ctx).await {
                        Ok(out) => {
                            self.output_text = match out {
                                DataPayload::Text(s) => s,
                                DataPayload::Bytes(b) => {
                                    format!("Output ({} bytes):\n{}", b.len(), hex::encode(&b))
                                }
                                DataPayload::Json(v) => serde_json::to_string_pretty(&v).unwrap_or_default(),
                                DataPayload::FileRef(p) => format!("File output: {}", p.display()),
                            };
                        }
                        Err(e) => {
                            self.output_text = format!("Execution Error: {}", e);
                        }
                    }
                }
            }
        }
    }
}

fn draw_ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header & search
            Constraint::Min(10),   // Main columns
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    // Header
    let header_text = if app.searching {
        format!(" OMNI Terminal Studio [Search: {}_]", app.search_query)
    } else {
        String::from(" OMNI — Universal Digital Engineering Toolkit (TUI)")
    };
    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("System Status: Online | Local-First")
            .style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(header, chunks[0]);

    // Main Columns: Categories (left 25%), Operations (middle 35%), Input/Output (right 40%)
    let main_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Percentage(40),
        ])
        .split(chunks[1]);

    // 1. Categories
    let cat_items: Vec<ListItem> = app
        .categories
        .iter()
        .enumerate()
        .map(|(i, cat)| {
            let style = if i == app.selected_category_idx {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(format!("{:?}", cat)).style(style)
        })
        .collect();

    let cat_border_style = match app.focused_pane {
        FocusedPane::Categories => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::DarkGray),
    };
    let cat_list = List::new(cat_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Categories [1] ")
                .border_style(cat_border_style),
        );
    f.render_widget(cat_list, main_cols[0]);

    // 2. Operations
    let ops = app.current_operations();
    let op_items: Vec<ListItem> = ops
        .iter()
        .map(|m| {
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(&m.name, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled(&m.id, Style::default().fg(Color::DarkGray)),
                ]),
            ])
        })
        .collect();

    let op_border_style = match app.focused_pane {
        FocusedPane::Operations => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::DarkGray),
    };
    let op_list = List::new(op_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Operations ({}) [2] ", ops.len()))
                .border_style(op_border_style),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(op_list, main_cols[1], &mut app.operations_list_state);

    // 3. Right Pane: Input (Top) and Output (Bottom)
    let io_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(main_cols[2]);

    let input_border = match app.focused_pane {
        FocusedPane::Input => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::DarkGray),
    };
    let input_widget = Paragraph::new(app.input_text.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Input Buffer [3] ")
            .border_style(input_border),
    );
    f.render_widget(input_widget, io_chunks[0]);

    let output_border = match app.focused_pane {
        FocusedPane::Output => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::DarkGray),
    };
    let output_widget = Paragraph::new(app.output_text.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Output Inspector [4] ")
            .border_style(output_border),
    );
    f.render_widget(output_widget, io_chunks[1]);

    // Status Footer
    let footer = Paragraph::new(
        " [Tab] Switch Pane  |  [Up/Down] Navigate  |  [Enter/Ctrl+R] Execute  |  [/] Search  |  [q] Quit",
    )
    .style(Style::default().fg(Color::Yellow))
    .block(Block::default().borders(Borders::ALL).title("Controls"));
    f.render_widget(footer, chunks[2]);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let registry = Arc::new(RwLock::new(OperationRegistry::new()));
    {
        let mut reg = registry.write().unwrap();
        let _ = omni_encoders::register_encoders(&mut reg);
        let _ = omni_crypto::register_crypto(&mut reg);
        let _ = omni_text::register_text(&mut reg);
        let _ = omni_code::register_code(&mut reg);
        let _ = omni_documents::register_documents(&mut reg);
        let _ = omni_pdf::register_pdf(&mut reg);
        let _ = omni_media::register_media(&mut reg);
        let _ = omni_network::register_network(&mut reg);
        let _ = omni_pcap::register_pcap(&mut reg);
        let _ = omni_binary::register_binary(&mut reg);
        let _ = omni_firmware::register_firmware(&mut reg);
        let _ = omni_filesystems::register_filesystems(&mut reg);
        let _ = omni_infrastructure::register_infrastructure(&mut reg);
        let _ = omni_ai::register_ai(&mut reg);
        let _ = omni_system::register_system(&mut reg);
    }
    let mut app = App::new(registry);

    loop {
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if app.searching {
                        match key.code {
                            KeyCode::Esc | KeyCode::Enter => app.searching = false,
                            KeyCode::Backspace => {
                                app.search_query.pop();
                            }
                            KeyCode::Char(c) => {
                                app.search_query.push(c);
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') => app.should_quit = true,
                            KeyCode::Char('/') => {
                                app.searching = true;
                                app.search_query.clear();
                            }
                            KeyCode::Tab => {
                                app.focused_pane = match app.focused_pane {
                                    FocusedPane::Categories => FocusedPane::Operations,
                                    FocusedPane::Operations => FocusedPane::Input,
                                    FocusedPane::Input => FocusedPane::Output,
                                    FocusedPane::Output => FocusedPane::Categories,
                                };
                            }
                            KeyCode::Up => match app.focused_pane {
                                FocusedPane::Categories => {
                                    if app.selected_category_idx > 0 {
                                        app.selected_category_idx -= 1;
                                    }
                                }
                                FocusedPane::Operations => {
                                    let i = match app.operations_list_state.selected() {
                                        Some(i) if i > 0 => i - 1,
                                        _ => 0,
                                    };
                                    app.operations_list_state.select(Some(i));
                                }
                                _ => {}
                            },
                            KeyCode::Down => match app.focused_pane {
                                FocusedPane::Categories => {
                                    if app.selected_category_idx + 1 < app.categories.len() {
                                        app.selected_category_idx += 1;
                                    }
                                }
                                FocusedPane::Operations => {
                                    let len = app.current_operations().len();
                                    let i = match app.operations_list_state.selected() {
                                        Some(i) => {
                                            if i + 1 < len {
                                                i + 1
                                            } else {
                                                i
                                            }
                                        }
                                        None => 0,
                                    };
                                    app.operations_list_state.select(Some(i));
                                }
                                _ => {}
                            },
                            KeyCode::Enter => {
                                app.execute_selected().await;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
