//! `anydb-desktop` — first visual test surface for the anydb platform.
//!
//! iced owns the main thread; the platform `App` runs on a tokio runtime
//! inside one background worker thread (see the bridge in `worker.rs`).

use std::sync::Arc;

use iced::Element;
use iced::time;
use iced::widget::{button, column, row, text, text_input};
use iced::{Subscription, Task};

use worker::{Command, DriverFactory, Event};

mod worker;

fn main() -> iced::Result {
    iced::application(State::new, update, view)
        .title("anydb desktop")
        .subscription(subscription)
        .window_size((1000.0, 700.0))
        .exit_on_close_request(false)
        .run()
}

/// Production driver factory: selects a driver by URL scheme. There is no
/// driver registry in the platform, so the binary is where the concrete
/// drivers are known.
fn production_factory() -> DriverFactory {
    Arc::new(|url: &str| {
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Some(Arc::new(anydb_postgres::PostgresDriver::new()))
        } else if url.starts_with("mongodb://") {
            Some(Arc::new(anydb_mongo::MongoDriver::new()))
        } else {
            None
        }
    })
}

#[derive(Debug, Clone)]
enum Message {
    UrlChanged(String),
    ConnectPressed,
    DisconnectPressed,
    StatusPressed,
    SqlChanged(String),
    ExecutePressed,
    Tick,
    CloseRequested,
}

struct State {
    commands: std::sync::mpsc::Sender<Command>,
    events: std::sync::mpsc::Receiver<Event>,
    _worker: std::thread::JoinHandle<()>,
    url: String,
    sql: String,
    status: String,
    error: Option<String>,
    result: Option<anydb::prelude::TypedStatementResult>,
}

impl State {
    fn new() -> Self {
        let (commands, events, _worker) = worker::spawn(production_factory());
        Self {
            commands,
            events,
            _worker,
            url: "postgres://user:pass@localhost:5432/db".to_owned(),
            sql: "SELECT 1".to_owned(),
            status: "disconnected".to_owned(),
            error: None,
            result: None,
        }
    }

    /// Drains every pending worker event without ever blocking the UI thread.
    fn drain_events(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Connected => {
                    self.status = "connected".to_owned();
                    self.error = None;
                }
                Event::Disconnected => {
                    self.status = "disconnected".to_owned();
                }
                Event::StatusChanged(text) => {
                    self.status = text;
                }
                Event::ExecutionFailed(message) => {
                    self.error = Some(message);
                    self.result = None;
                }
                Event::ResultReady(typed) => {
                    self.error = None;
                    self.result = Some(typed);
                }
            }
        }
    }
}

fn update(state: &mut State, message: Message) -> Task<Message> {
    state.drain_events();
    match message {
        Message::UrlChanged(url) => state.url = url,
        Message::ConnectPressed => {
            let _ = state.commands.send(Command::Connect {
                url: state.url.clone(),
            });
        }
        Message::DisconnectPressed => {
            let _ = state.commands.send(Command::Disconnect);
        }
        Message::StatusPressed => {
            let _ = state.commands.send(Command::Status);
        }
        Message::SqlChanged(sql) => state.sql = sql,
        Message::ExecutePressed => {
            let _ = state.commands.send(Command::Execute {
                sql: state.sql.clone(),
            });
        }
        // The tick only drains events; `drain_events` already ran above.
        Message::Tick => {}
        Message::CloseRequested => {
            // Ordered shutdown: ask the worker to stop, then let iced exit.
            let _ = state.commands.send(Command::Shutdown);
            return iced::exit();
        }
    }
    Task::none()
}

fn subscription(_state: &State) -> Subscription<Message> {
    let tick = time::every(std::time::Duration::from_millis(50)).map(|_| Message::Tick);
    let close = iced::event::listen_with(|event, status, _id| {
        if matches!(
            event,
            iced::Event::Window(iced::window::Event::CloseRequested)
        ) && status == iced::event::Status::Captured
        {
            Some(Message::CloseRequested)
        } else {
            None
        }
    });
    Subscription::batch([tick, close])
}

fn view(state: &State) -> Element<'_, Message> {
    let url_bar = row![
        text_input("target url", &state.url).on_input(Message::UrlChanged),
        button("connect").on_press(Message::ConnectPressed),
        button("disconnect").on_press(Message::DisconnectPressed),
        button("status").on_press(Message::StatusPressed),
        text(&state.status),
    ]
    .spacing(8);

    let editor = column![
        text("SQL"),
        text_input("SELECT 1", &state.sql)
            .on_input(Message::SqlChanged)
            .on_submit(Message::ExecutePressed),
        button("execute").on_press(Message::ExecutePressed),
    ]
    .spacing(8);

    let mut results = column![].spacing(4);
    if let Some(error) = &state.error {
        results = results.push(text(format!("error: {error}")));
    }
    if let Some(result) = &state.result {
        let mut summary = format!(
            "{} row(s) - tag: {} - affected: {}",
            result.rows.len(),
            result.command_tag.as_deref().unwrap_or("-"),
            result
                .affected_rows
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".to_owned()),
        );
        if let Some(message) = &result.message {
            summary.push_str(&format!(" - {message}"));
        }
        results = results.push(text(summary));
        let header: Vec<Element<'_, Message>> = result
            .columns
            .iter()
            .map(|name| text(format!("{name:>8}")).into())
            .collect();
        results = results.push(row(header).spacing(8));
        for row_values in &result.rows {
            let cells: Vec<Element<'_, Message>> = row_values
                .iter()
                .map(|value| {
                    let rendered = match value {
                        Some(typed) => typed.to_string(),
                        None => "NULL".to_owned(),
                    };
                    text(format!("{rendered:>8}")).into()
                })
                .collect();
            results = results.push(row(cells).spacing(8));
        }
    }

    column![url_bar, editor, results]
        .spacing(16)
        .padding(12)
        .into()
}
