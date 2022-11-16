use std::{cell::RefCell, env, sync::atomic::*, sync::Arc, thread, time::*, net::UdpSocket};
use crossbeam_channel::{select, bounded, Sender, Receiver};

/// The `Receiver` gets a `()` once `ms` milliseconds have elapsed, approximately
pub fn timer(ms: u64) -> Receiver<()> { //DUMMY //LEAK This spawns threads; we could/should probably refactor that away
    let (s, r) = bounded(1);
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(ms));
        s.send(());
    });

    r
}