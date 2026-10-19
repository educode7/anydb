//! `anydb-desktop` — first visual test surface for the anydb platform.
//!
//! iced owns the main thread; the platform `App` runs on a tokio runtime
//! inside one background worker thread (see the bridge in `worker.rs`).

use iced::Element;
use iced::widget::{button, column, text};

mod worker;

fn main() -> iced::Result {
    iced::application(State::new, update, view)
        .title("anydb desktop")
        .window_size((1000.0, 700.0))
        .run()
}

#[derive(Debug, Clone, Copy)]
enum Message {
    Noop,
}

struct State;

impl State {
    fn new() -> Self {
        Self
    }
}

fn update(_state: &mut State, _message: Message) -> iced::Task<Message> {
    iced::Task::none()
}

fn view(_state: &State) -> Element<'_, Message> {
    column![text("anydb"), button("connect").on_press(Message::Noop)].into()
}
