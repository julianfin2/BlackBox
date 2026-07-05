// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if std::env::args().any(|argument| argument == "--service") {
        blackbox_lib::run_service();
    } else {
        blackbox_lib::run();
    }
}
