//! UI/async bridge: iced owns the main thread; the platform `App` runs on a
//! tokio runtime inside ONE background worker thread. The UI sends
//! `Command`s over a std channel and drains `Event`s every frame.
//!
//! T1: module skeleton only; the bridge lands in T2.

// Placeholder so the scaffold compiles; replaced by the real bridge in T2.
