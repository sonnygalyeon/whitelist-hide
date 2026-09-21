fn main() {
    if let Err(error) = whitelist_hide_controller::watchdog_loop() {
        eprintln!("whitelist-hide watchdog: {error}");
        std::process::exit(1);
    }
}
