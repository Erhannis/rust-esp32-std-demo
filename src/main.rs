#![allow(unused_imports)]
#![allow(clippy::single_component_path_imports)]
//#![feature(backtrace)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::{cell::RefCell, env, sync::atomic::*, sync::Arc, thread, time::*, net::UdpSocket};

use rand::Rng;

use crossbeam_channel::{select, bounded, Sender, Receiver};

use anyhow::bail;

use embedded_svc::mqtt::client::utils::ConnState;
use log::*;

use url;

use smol;

use embedded_hal::adc::OneShot;
use embedded_hal::blocking::delay::DelayMs;
use embedded_hal::digital::v2::OutputPin;
use embedded_hal::digital::v2::InputPin;

use embedded_svc::eth;
use embedded_svc::eth::{Eth, TransitionalState};
use embedded_svc::httpd::registry::*;
use embedded_svc::httpd::*;
use embedded_svc::io;
use embedded_svc::ipv4;
use embedded_svc::mqtt::client::{Client, Connection, MessageImpl, Publish, QoS};
use embedded_svc::ping::Ping;
use embedded_svc::sys_time::SystemTime;
use embedded_svc::timer::TimerService;
use embedded_svc::timer::*;
use embedded_svc::wifi::*;

use esp_idf_svc::eth::*;
use esp_idf_svc::eventloop::*;
use esp_idf_svc::eventloop::*;
use esp_idf_svc::httpd as idf;
use esp_idf_svc::httpd::ServerRegistry;
use esp_idf_svc::mqtt::client::*;
use esp_idf_svc::netif::*;
use esp_idf_svc::nvs::*;
use esp_idf_svc::ping;
use esp_idf_svc::sntp;
use esp_idf_svc::sysloop::*;
use esp_idf_svc::systime::EspSystemTime;
use esp_idf_svc::timer::*;
use esp_idf_svc::wifi::*;

use esp_idf_hal::adc;
use esp_idf_hal::delay;
use esp_idf_hal::gpio;
use esp_idf_hal::i2c;
use esp_idf_hal::prelude::*;
use esp_idf_hal::spi;

use esp_idf_sys::{self, c_types};
use esp_idf_sys::{esp, EspError};

use display_interface_spi::SPIInterfaceNoCS;

use embedded_graphics::mono_font::{ascii::FONT_10X20, MonoTextStyle};
use embedded_graphics::pixelcolor::*;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::*;
use embedded_graphics::text::*;

use ili9341;
use ssd1306;
use ssd1306::mode::DisplayConfig;
use st7789;

use epd_waveshare::{epd4in2::*, graphics::VarDisplay, prelude::*};

mod csp;

const SSID: &str = env!("RUST_ESP32_STD_DEMO_WIFI_SSID");
const PASS: &str = env!("RUST_ESP32_STD_DEMO_WIFI_PASS");

thread_local! {
    static TLS: RefCell<u32> = RefCell::new(13);
}

fn main() -> Result<()> {
    esp_idf_sys::link_patches();

    test_print();

    test_atomics();

    test_threads();

    test_fs()?;

    test_csp()?;

    //test_csp_heavy();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    // Get backtraces from anyhow; only works for Xtensa arch currently
    // TODO: No longer working with ESP-IDF 4.3.1+
    //#[cfg(target_arch = "xtensa")]
    //env::set_var("RUST_BACKTRACE", "1");

    let peripherals = Peripherals::take().unwrap();
    let pins = peripherals.pins;

    let netif_stack = Arc::new(EspNetifStack::new()?);
    let sys_loop_stack = Arc::new(EspSysLoopStack::new()?);
    let default_nvs = Arc::new(EspDefaultNvs::new()?);

    #[allow(clippy::redundant_clone)]
    #[allow(unused_mut)]
    let mut wifi = wifi(
        netif_stack.clone(),
        sys_loop_stack.clone(),
        default_nvs.clone(),
    )?;

    test_tcp()?;

    test_tcp_bind()?;

    test_broadcast();

    // let _sntp = sntp::EspSntp::new_default()?;
    // info!("SNTP initialized");

    // let (eventloop, _subscription) = test_eventloop()?;

    // let mqtt_client = test_mqtt_client()?;

    // let _timer = test_timer(eventloop, mqtt_client)?;

    // #[cfg(feature = "experimental")]
    // experimental::test()?;

    // enable_napt(&mut wifi)?;

    let mutex = Arc::new((Mutex::new(None), Condvar::new()));

    let httpd = httpd(mutex.clone())?;

    let mut wait = mutex.0.lock().unwrap();

    let mut hall_sensor = peripherals.hall_sensor;

    // Note that this pin is different on different ESP32 versions
    let mut a2 = pins.gpio34.into_analog_atten_11db()?;

    let mut powered_adc1 = adc::PoweredAdc::new(
        peripherals.adc1,
        adc::config::Config::new().calibration(true),
    )?;

    let (pin_hit_out, pin_hit_in) = bounded(1); //DUMMY Erroneously deadlocks if 0
    let b_down = pins.gpio25.into_input().unwrap();
    let b_up = pins.gpio33.into_input().unwrap();
    let b_guess = pins.gpio32.into_input().unwrap();
    thread::spawn(move || { // Pin manager
        let mut state = [true,true,true];
        loop {
            sleep(50); //THINK Is this enough of a delay to catch btn presses?  Is there a built in event handler thing?
            if b_down.is_high().unwrap() {
                state[0] = true;
            } else {
                if state[0] {
                    pin_hit_out.send(0);
                }
                state[0] = false;
            }
            if b_up.is_high().unwrap() {
                state[1] = true;
            } else {
                if state[1] {
                    pin_hit_out.send(1);
                }
                state[1] = false;
            }
            if b_guess.is_high().unwrap() {
                state[2] = true;
            } else {
                if state[2] {
                    pin_hit_out.send(2);
                }
                state[2] = false;
            }
        }
    });

    let (led_out, led_in) = bounded::<&[(bool, u64)]>(1); //DUMMY Erroneously deadlocks if 0
    let mut led = pins.gpio2.into_output().unwrap();
    //let b_led = pins.gpio26.into_input().unwrap();
    thread::spawn(move || { // LED manager
        let mut actions: Vec<(bool, u64)> = vec![];
        loop {
            println!("led: actions {actions:?}");
            let (state, rt) = actions.pop().unwrap_or((false, 60000));
            if state {
                led.set_high().unwrap();
            } else {
                led.set_low().unwrap();
            }
            println!("led: timer {:?}", (state, rt));
            let t = csp::timer(rt);
            select! {
                recv(led_in) -> msg => {
                    let actions_in = msg.unwrap(); //DUMMY Really, I ought to be handling these errors
                    println!("led: got actions {actions_in:?}");
                    actions.clear();
                    actions.append(&mut Vec::from(actions_in));
                },
                recv(t) -> msg => {
                    println!("led: finished phase");
                },
            }
        }
    });

    fn game(pin_hit_in: Receiver<i32>, led_out: Sender<&[(bool, u64)]>) {
        let secret: u64 = rand::thread_rng().gen_range(1..=10);
        println!("secret: {secret}");
        let mut cur: u64 = 1;
        loop {
            let btn = pin_hit_in.recv().unwrap();
            println!("{btn}");
            match btn {
                0 => cur -= 1,
                1 => cur += 1,
                2 => {
                    if cur == secret {
                        println!("you win!");
                        led_out.send(&[(true, 100),(false, 100),(true, 100),(false, 100),(true, 100),(false, 100),(true, 100),(false, 100),(true, 100),(false, 100),]);
                    } else if cur < secret {
                        led_out.send(&[(true, 1000)]);
                    } else if secret < cur {
                        led_out.send(&[(true, 100)]);
                    }
                },
                _ => (),
            }
            println!("btn: {btn} ; cur: {cur} ; secret: {secret}");
        }
    }

    game(pin_hit_in, led_out);

    // #[allow(unused)]
    // let cycles = loop {
    //     if let Some(cycles) = *wait { //THINK I never did understand something about this mutex....
    //         break cycles;
    //     } else {
    //         wait = mutex
    //             .1
    //             .wait_timeout(wait, Duration::from_secs(1))
    //             .unwrap()
    //             .0;

    //         log::info!(
    //             "Hall sensor reading: {}mV",
    //             powered_adc1.read(&mut hall_sensor).unwrap()
    //         );
    //         log::info!(
    //             "A2 sensor reading: {}mV",
    //             powered_adc1.read(&mut a2).unwrap()
    //         );
    //         if d32.is_high()? {
    //             led.set_high();
    //         } else {
    //             led.set_low();
    //         }
    //     }
    // };

    for s in 0..3 {
        info!("Shutting down in {} secs", 3 - s);
        thread::sleep(Duration::from_secs(1));
    }

    drop(httpd);
    info!("Httpd stopped");

    {
        drop(wifi);
        info!("Wifi stopped");
    }

    Ok(())
}

#[allow(clippy::vec_init_then_push)]
fn test_print() {
    // Start simple
    println!("Hello from Rust!");

    // Check collections
    let mut children = vec![];

    children.push("foo");
    children.push("bar");
    println!("More complex print {:?}", children);
}

#[allow(deprecated)]
fn test_atomics() {
    let a = AtomicUsize::new(0);
    let v1 = a.compare_and_swap(0, 1, Ordering::SeqCst);
    let v2 = a.swap(2, Ordering::SeqCst);

    let (r1, r2) = unsafe {
        // don't optimize our atomics out
        let r1 = core::ptr::read_volatile(&v1);
        let r2 = core::ptr::read_volatile(&v2);

        (r1, r2)
    };

    println!("Result: {}, {}", r1, r2);
}

fn test_threads() {
    let mut children = vec![];

    println!("Rust main thread: {:?}", thread::current());

    TLS.with(|tls| {
        println!("Main TLS before change: {}", *tls.borrow());
    });

    TLS.with(|tls| *tls.borrow_mut() = 42);

    TLS.with(|tls| {
        println!("Main TLS after change: {}", *tls.borrow());
    });

    for i in 0..5 {
        // Spin up another thread
        children.push(thread::spawn(move || {
            println!("This is thread number {}, {:?}", i, thread::current());

            TLS.with(|tls| *tls.borrow_mut() = i);

            TLS.with(|tls| {
                println!("Inner TLS: {}", *tls.borrow());
            });
        }));
    }

    println!(
        "About to join the threads. If ESP-IDF was patched successfully, joining will NOT crash"
    );

    for child in children {
        // Wait for the thread to finish. Returns a result.
        let _ = child.join();
    }

    TLS.with(|tls| {
        println!("Main TLS after threads: {}", *tls.borrow());
    });

    thread::sleep(Duration::from_secs(2));

    println!("Joins were successful.");
}

fn test_fs() -> Result<()> {
    assert_eq!(fs::canonicalize(PathBuf::from("."))?, PathBuf::from("/"));
    assert_eq!(
        fs::canonicalize(
            PathBuf::from("/")
                .join("foo")
                .join("bar")
                .join(".")
                .join("..")
                .join("baz")
        )?,
        PathBuf::from("/foo/baz")
    );

    Ok(())
}

/// Hmmmm.  This failed twice, blocking on (once presumably and the other confirmedly) the receive,
/// but has now succeeded many times in a row, with no functional change being made to the code.
/// This fills me with discomfort, but I guess I'll pretend it's working and correct and everything
/// until something goes wrong again.  ...  <_<b
/// WAIT.  I forgot I accidentally set channel size from 0 to 3.
/// ...Yup, changing it back to 0 broke it again.  ...With whom do I file a bug report?
fn test_csp() -> Result<()> {
    println!("--> test_csp");

    fn fibonacci(sender: Sender<u64>) {
        println!("--> test_csp.fibonacci");
        let (mut x, mut y) = (0, 1);
        while sender.send(x).is_ok() {
            println!("--- test_csp.fibonacci loop {x} {y}");
            //thread::sleep(Duration::from_secs(1));
            let tmp = x;
            x = y;
            y += tmp;
        }
        println!("<-- test_csp.fibonacci");
    }

    println!("--- test_csp 1");
    let (s, r) = bounded(1); //DUMMY Erroneously deadlocks if 0
    println!("--- test_csp 2");
    thread::spawn(|| fibonacci(s));
    println!("--- test_csp 3");

    // Print the first 20 Fibonacci numbers.
    for num in r.iter().take(20) {
        println!("{}", num);
    }
    println!("--- test_csp 4");

    println!("<-- test_csp 5");
    Ok(())
}

fn current_millis() -> u128 {
    return EspSystemTime {}.now().as_millis();
}

fn test_csp_heavy() {
    // let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind address");
    // socket.set_broadcast(true).expect("failed to set broadcast");
    // socket.send_to("asdf".as_bytes(), "255.255.255.255:3400").expect("couldn't send data");

    println!("--> test_csp_heavy");

    const MSGS: u64 = 1000;
    const POLLERS: u64 = 10;

    fn generator(s: Sender<String>) {
        println!("--> test_csp_heavy.generator");
        let mut rand = rand::thread_rng();
        for _ in 0..(MSGS*POLLERS) {
            let i = rand.gen::<f64>();
            //println!("--- test_csp.generator send...");
            s.send(format!("{i}")).unwrap();
            //println!("--- ...test_csp.generator sent");
        }
        println!("<-- test_csp_heavy.generator");
    }

    fn poller(id: u64, r: Receiver<String>, s: Sender<String>) {
        println!("--> test_csp_heavy.poller {id}");
        let mut rand = rand::thread_rng();
        let mut done = false;
        for _ in 0..MSGS {
            let x = r.recv().unwrap();
            //sleep(rand.gen_range(500..=2000));
            //println!("--- test_csp_heavy.poller {id} send...");
            done = !s.send(x).is_ok();
            //println!("--- ...test_csp_heavy.poller {id} sent");
        }        
        println!("<-- test_csp_heavy.poller {id}");
    }

    println!("--- test_csp_heavy 1");
    let (sg, rg) = bounded(1);
    let (s0, r0) = bounded(1);
    // let (s1, r1) = bounded(0);
    // let (s2, r2) = bounded(0);

    println!("--- test_csp_heavy 2");
    thread::spawn(|| generator(sg));

    println!("--- test_csp_heavy 2.1");
    for id in 0..POLLERS {
        let s = s0.clone();
        let r = rg.clone();
        thread::spawn(move || poller(id, r, s)); //THINK Not sure why I suddenly needed `move`
    }
    println!("--- test_csp_heavy 3");

    let mut rand = rand::thread_rng();

    let start = current_millis();
    let mut i = 0;
    for _ in 0..(MSGS*POLLERS) {
        //sleep(rand.gen_range(100..=1000));
        select! {
            recv(r0) -> msg => i = i+1,//println!("rx 0 {}", msg.unwrap()),
            // recv(r1) -> msg => println!("rx 1 {}", msg.unwrap()),
            // recv(r2) -> msg => println!("rx 2 {}", msg.unwrap()),
        }
    }
    let end = current_millis();
    println!("rx {i} msgs in {}ms", end-start);

    println!("--- test_csp_heavy 4");

    println!("<-- test_csp_heavy");
}

fn test_tcp() -> Result<()> {
    info!("About to open a TCP connection to 1.1.1.1 port 80");

    let mut stream = TcpStream::connect("one.one.one.one:80")?;

    let err = stream.try_clone();
    if let Err(err) = err {
        info!(
            "Duplication of file descriptors does not work (yet) on the ESP-IDF, as expected: {}",
            err
        );
    }

    stream.write_all("GET / HTTP/1.0\n\n".as_bytes())?;

    let mut result = Vec::new();

    stream.read_to_end(&mut result)?;

    info!(
        "1.1.1.1 returned:\n=================\n{}\n=================\nSince it returned something, all is OK",
        std::str::from_utf8(&result)?);

    Ok(())
}

fn test_broadcast() {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind address");
    socket.set_broadcast(true).expect("failed to set broadcast");
    socket.send_to("asdf".as_bytes(), "255.255.255.255:3400").expect("couldn't send data");
}

fn test_tcp_bind() -> Result<()> {
    fn test_tcp_bind_accept() -> Result<()> {
        info!("About to bind a simple echo service to port 8080");

        let listener = TcpListener::bind("0.0.0.0:8080")?;

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    info!("Accepted client");

                    thread::spawn(move || {
                        test_tcp_bind_handle_client(stream);
                    });
                }
                Err(e) => {
                    error!("Error: {}", e);
                }
            }
        }

        unreachable!()
    }

    fn test_tcp_bind_handle_client(mut stream: TcpStream) {
        // read 20 bytes at a time from stream echoing back to stream
        loop {
            let mut read = [0; 128];

            match stream.read(&mut read) {
                Ok(n) => {
                    if n == 0 {
                        // connection was closed
                        break;
                    }
                    stream.write_all(&read[0..n]).unwrap();
                }
                Err(err) => {
                    panic!("{}", err);
                }
            }
        }
    }

    thread::spawn(|| test_tcp_bind_accept().unwrap());

    Ok(())
}

fn test_timer(
    mut eventloop: EspBackgroundEventLoop,
    mut client: EspMqttClient<ConnState<MessageImpl, EspError>>,
) -> Result<EspTimer> {
    use embedded_svc::event_bus::Postbox;

    info!("About to schedule a one-shot timer for after 2 seconds");
    let mut once_timer = EspTimerService::new()?.timer(|| {
        info!("One-shot timer triggered");
    })?;

    once_timer.after(Duration::from_secs(2))?;

    thread::sleep(Duration::from_secs(3));

    info!("About to schedule a periodic timer every five seconds");
    let mut periodic_timer = EspTimerService::new()?.timer(move || {
        info!("Tick from periodic timer");

        let now = EspSystemTime {}.now();

        eventloop.post(&EventLoopMessage::new(now), None).unwrap();

        client
            .publish(
                "rust-esp32-std-demo",
                QoS::AtMostOnce,
                false,
                format!("Now is {:?}", now).as_bytes(),
            )
            .unwrap();
    })?;

    periodic_timer.every(Duration::from_secs(5))?;

    Ok(periodic_timer)
}

#[derive(Copy, Clone, Debug)]
struct EventLoopMessage(Duration);

impl EventLoopMessage {
    pub fn new(duration: Duration) -> Self {
        Self(duration)
    }
}

impl EspTypedEventSource for EventLoopMessage {
    fn source() -> *const c_types::c_char {
        b"DEMO-SERVICE\0".as_ptr() as *const _
    }
}

impl EspTypedEventSerializer<EventLoopMessage> for EventLoopMessage {
    fn serialize<R>(
        event: &EventLoopMessage,
        f: impl for<'a> FnOnce(&'a EspEventPostData) -> R,
    ) -> R {
        f(&unsafe { EspEventPostData::new(Self::source(), Self::event_id(), event) })
    }
}

impl EspTypedEventDeserializer<EventLoopMessage> for EventLoopMessage {
    fn deserialize<R>(
        data: &EspEventFetchData,
        f: &mut impl for<'a> FnMut(&'a EventLoopMessage) -> R,
    ) -> R {
        f(unsafe { data.as_payload() })
    }
}

fn test_eventloop() -> Result<(EspBackgroundEventLoop, EspBackgroundSubscription)> {
    use embedded_svc::event_bus::EventBus;

    info!("About to start a background event loop");
    let mut eventloop = EspBackgroundEventLoop::new(&Default::default())?;

    info!("About to subscribe to the background event loop");
    let subscription = eventloop.subscribe(|message: &EventLoopMessage| {
        info!("Got message from the event loop: {:?}", message.0);
    })?;

    Ok((eventloop, subscription))
}

fn test_mqtt_client() -> Result<EspMqttClient<ConnState<MessageImpl, EspError>>> {
    info!("About to start MQTT client");

    let conf = MqttClientConfiguration {
        client_id: Some("rust-esp32-std-demo"),
        crt_bundle_attach: Some(esp_idf_sys::esp_crt_bundle_attach),

        ..Default::default()
    };

    let (mut client, mut connection) =
        EspMqttClient::new_with_conn("mqtts://broker.emqx.io:8883", &conf)?;

    info!("MQTT client started");

    // Need to immediately start pumping the connection for messages, or else subscribe() and publish() below will not work
    // Note that when using the alternative constructor - `EspMqttClient::new` - you don't need to
    // spawn a new thread, as the messages will be pumped with a backpressure into the callback you provide.
    // Yet, you still need to efficiently process each message in the callback without blocking for too long.
    //
    // Note also that if you go to http://tools.emqx.io/ and then connect and send a message to topic
    // "rust-esp32-std-demo", the client configured here should receive it.
    thread::spawn(move || {
        info!("MQTT Listening for messages");

        while let Some(msg) = connection.next() {
            match msg {
                Err(e) => info!("MQTT Message ERROR: {}", e),
                Ok(msg) => info!("MQTT Message: {:?}", msg),
            }
        }

        info!("MQTT connection loop exit");
    });

    client.subscribe("rust-esp32-std-demo", QoS::AtMostOnce)?;

    info!("Subscribed to all topics (rust-esp32-std-demo)");

    client.publish(
        "rust-esp32-std-demo",
        QoS::AtMostOnce,
        false,
        "Hello from rust-esp32-std-demo!".as_bytes(),
    )?;

    info!("Published a hello message to topic \"rust-esp32-std-demo\"");

    Ok(client)
}

#[cfg(feature = "experimental")]
mod experimental {
    use super::{thread, TcpListener, TcpStream};
    use log::info;

    use esp_idf_sys::c_types;

    pub fn test() -> anyhow::Result<()> {
        #[cfg(not(esp_idf_version = "4.3"))]
        test_tcp_bind_async()?;

        test_https_client()?;

        Ok(())
    }

    #[cfg(not(esp_idf_version = "4.3"))]
    fn test_tcp_bind_async() -> anyhow::Result<()> {
        async fn test_tcp_bind() -> smol::io::Result<()> {
            /// Echoes messages from the client back to it.
            async fn echo(stream: smol::Async<TcpStream>) -> smol::io::Result<()> {
                smol::io::copy(&stream, &mut &stream).await?;
                Ok(())
            }

            // Create a listener.
            let listener = smol::Async::<TcpListener>::bind(([0, 0, 0, 0], 8081))?;

            // Accept clients in a loop.
            loop {
                let (stream, peer_addr) = listener.accept().await?;
                info!("Accepted client: {}", peer_addr);

                // Spawn a task that echoes messages from the client back to it.
                smol::spawn(echo(stream)).detach();
            }
        }

        info!("About to bind a simple echo service to port 8081 using async (smol-rs)!");

        #[allow(clippy::needless_update)]
        {
            esp_idf_sys::esp!(unsafe {
                esp_idf_sys::esp_vfs_eventfd_register(&esp_idf_sys::esp_vfs_eventfd_config_t {
                    max_fds: 5,
                    ..Default::default()
                })
            })?;
        }

        thread::Builder::new().stack_size(4096).spawn(move || {
            smol::block_on(test_tcp_bind()).unwrap();
        })?;

        Ok(())
    }

    fn test_https_client() -> anyhow::Result<()> {
        use embedded_svc::http::{self, client::*, status, Headers, Status};
        use embedded_svc::io;
        use esp_idf_svc::http::client::*;

        let url = String::from("https://google.com");

        info!("About to fetch content from {}", url);

        let mut client = EspHttpClient::new(&EspHttpClientConfiguration {
            crt_bundle_attach: Some(esp_idf_sys::esp_crt_bundle_attach),

            ..Default::default()
        })?;

        let mut response = client.get(&url)?.submit()?;

        let mut body = [0_u8; 3048];

        let (body, _) = io::read_max(response.reader(), &mut body)?;

        info!(
            "Body (truncated to 3K):\n{:?}",
            String::from_utf8_lossy(body).into_owned()
        );

        Ok(())
    }
}

#[allow(unused_variables)]
fn httpd(
    mutex: Arc<(Mutex<Option<u32>>, Condvar)>,
) -> Result<esp_idf_svc::http::server::EspHttpServer> {
    use embedded_svc::errors::wrap::WrapError;
    use embedded_svc::http::server::registry::Registry;
    use embedded_svc::http::server::Response;
    use embedded_svc::http::SendStatus;

    let mut server = esp_idf_svc::http::server::EspHttpServer::new(&Default::default())?;

    server
        .handle_get("/", |_req, resp| {
            resp.send_str("Hello from Rust!")?;
            Ok(())
        })?
        .handle_get("/foo", |_req, resp| {
            Result::Err(WrapError("Boo, something happened!").into())
        })?
        .handle_get("/bar", |_req, resp| {
            resp.status(403)
                .status_message("No permissions")
                .send_str("You have no permissions to access this page")?;

            Ok(())
        })?
        .handle_get("/panic", |_req, _resp| panic!("User requested a panic!"))?;

    #[cfg(esp32s2)]
    httpd_ulp_endpoints(&mut server, mutex)?;

    Ok(server)
}

#[allow(dead_code)]
fn wifi(
    netif_stack: Arc<EspNetifStack>,
    sys_loop_stack: Arc<EspSysLoopStack>,
    default_nvs: Arc<EspDefaultNvs>,
) -> Result<Box<EspWifi>> {
    let mut wifi = Box::new(EspWifi::new(netif_stack, sys_loop_stack, default_nvs)?);

    info!("Wifi created, about to scan");

    let ap_infos = wifi.scan()?;

    let ours = ap_infos.into_iter().find(|a| a.ssid == SSID);

    let channel = if let Some(ours) = ours {
        info!(
            "Found configured access point {} on channel {}",
            SSID, ours.channel
        );
        Some(ours.channel)
    } else {
        info!(
            "Configured access point {} not found during scanning, will go with unknown channel",
            SSID
        );
        None
    };

    wifi.set_configuration(&Configuration::Mixed(
        ClientConfiguration {
            ssid: SSID.into(),
            password: PASS.into(),
            channel,
            ..Default::default()
        },
        AccessPointConfiguration {
            ssid: "aptest".into(),
            channel: channel.unwrap_or(1),
            ..Default::default()
        },
    ))?;

    info!("Wifi configuration set, about to get status");

    wifi.wait_status_with_timeout(Duration::from_secs(20), |status| !status.is_transitional())
        .map_err(|e| anyhow::anyhow!("Unexpected Wifi status: {:?}", e))?;

    let status = wifi.get_status();

    if let Status(
        ClientStatus::Started(ClientConnectionStatus::Connected(ClientIpStatus::Done(ip_settings))),
        ApStatus::Started(ApIpStatus::Done),
    ) = status
    {
        info!("Wifi connected");

        ping(&ip_settings)?;
    } else {
        bail!("Unexpected Wifi status: {:?}", status);
    }

    Ok(wifi)
}

fn ping(ip_settings: &ipv4::ClientSettings) -> Result<()> {
    info!("About to do some pings for {:?}", ip_settings);

    let ping_summary =
        ping::EspPing::default().ping(ip_settings.subnet.gateway, &Default::default())?;
    if ping_summary.transmitted != ping_summary.received {
        bail!(
            "Pinging gateway {} resulted in timeouts",
            ip_settings.subnet.gateway
        );
    }

    info!("Pinging done");

    Ok(())
}

fn enable_napt(wifi: &mut EspWifi) -> Result<()> {
    wifi.with_router_netif_mut(|netif| netif.unwrap().enable_napt(true));

    info!("NAPT enabled on the WiFi SoftAP!");

    Ok(())
}




fn sleep(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
}
