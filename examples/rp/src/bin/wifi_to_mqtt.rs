//! This example uses the RP Pico W board Wifi chip (cyw43).
//! Connects to specified Wifi network and creates a TCP endpoint on port 1234.

#![no_std]
#![no_main]
#![allow(async_fn_in_trait)]

use heapless::String;
use cyw43_pio::PioSpi;
use defmt::*;
use embassy_executor::Spawner;
use embassy_net::tcp::TcpSocket;
use embassy_net::{Config, Stack, StackResources, Ipv4Address};
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{InterruptHandler, Pio};
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use rust_mqtt::{
    client::{client::MqttClient, client_config::ClientConfig},
    packet::v5::reason_codes::ReasonCode,
    utils::rng_generator::CountingRng,
};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
});

const WIFI_NETWORK: &str = "TP-Link_71D9";
const WIFI_PASSWORD: &str = "xxx";

#[embassy_executor::task]
async fn wifi_task(runner: cyw43::Runner<'static, Output<'static>, PioSpi<'static, PIO0, 0, DMA_CH0>>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<cyw43::NetDriver<'static>>) -> ! {
    stack.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    
    info!("Hello World!");

    let p = embassy_rp::init(Default::default());

    let fw = include_bytes!("../../../../cyw43-firmware/43439A0.bin");
    let clm = include_bytes!("../../../../cyw43-firmware/43439A0_clm.bin");

    // To make flashing faster for development, you may want to flash the firmwares independently
    // at hardcoded addresses, instead of baking them into the program with `include_bytes!`:
    //     probe-rs download 43439A0.bin --format bin --chip RP2040 --base-address 0x10100000
    //     probe-rs download 43439A0_clm.bin --format bin --chip RP2040 --base-address 0x10140000
    //let fw = unsafe { core::slice::from_raw_parts(0x10100000 as *const u8, 230321) };
    //let clm = unsafe { core::slice::from_raw_parts(0x10140000 as *const u8, 4752) };

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = PioSpi::new(&mut pio.common, pio.sm0, pio.irq0, cs, p.PIN_24, p.PIN_29, p.DMA_CH0);

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (net_device, mut control, runner) = cyw43::new(state, pwr, spi, fw).await;
    unwrap!(spawner.spawn(wifi_task(runner)));

    control.init(clm).await;
    control
        .set_power_management(cyw43::PowerManagementMode::PowerSave)
        .await;

    let config = Config::dhcpv4(Default::default());
    //let config = embassy_net::Config::ipv4_static(embassy_net::StaticConfigV4 {
    //    address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 69, 2), 24),
    //    dns_servers: Vec::new(),
    //    gateway: Some(Ipv4Address::new(192, 168, 69, 1)),
    //});

    // Generate random seed
    let seed = 0x0123_4567_89ab_cdef; // chosen by fair dice roll. guarenteed to be random.

    // Init network stack
    static STACK: StaticCell<Stack<cyw43::NetDriver<'static>>> = StaticCell::new();
    static RESOURCES: StaticCell<StackResources<2>> = StaticCell::new();
    let stack = &*STACK.init(Stack::new(
        net_device,
        config,
        RESOURCES.init(StackResources::<2>::new()),
        seed,
    ));

    unwrap!(spawner.spawn(net_task(stack)));

    loop {
        //control.join_open(WIFI_NETWORK).await;
        match control.join_wpa2(WIFI_NETWORK, WIFI_PASSWORD).await {
            Ok(_) => break,
            Err(err) => {
                info!("join failed with status={}", err.status);
            }
        }
    }

    // Wait for DHCP, not necessary when using static IP
    info!("waiting for DHCP...");
    while !stack.is_config_up() {
        Timer::after_millis(100).await;
    }
    info!("DHCP is now up!");

    // And now we can use it!

    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];

    let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
    socket.set_timeout(Some(Duration::from_secs(10)));

    // TODO Set the IP Address of the machine running Docker with Mosquitto image - 192.168.1.180
    let remote_endpoint = (Ipv4Address::new(192, 168, 1, 180), 1883);
    println!("connecting...");
    let connection = socket.connect(remote_endpoint).await;
    if let Err(e) = connection {
        println!("connect error: {:?}", e);
    }
    println!("connected!");

    let mut config = ClientConfig::new(
        rust_mqtt::client::client_config::MqttVersion::MQTTv5,
        CountingRng(20000),
    );
    config.add_max_subscribe_qos(rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1);
    // config.add_client_id("clientId-8rhWgBODCl");
    config.max_packet_size = 100;
    let mut recv_buffer = [0; 80];
    let mut write_buffer = [0; 80];

    let mut client = MqttClient::<_, 5, _>::new(socket, &mut write_buffer, 80, &mut recv_buffer, 80, config);

    fn handle_mqtt_error(mqtt_error: ReasonCode) {
        match mqtt_error {
            ReasonCode::Success => println!("Operation was successful!"),
            ReasonCode::GrantedQoS1 => println!("Granted QoS level 1!"),
            ReasonCode::GrantedQoS2 => println!("Granted QoS level 2!"),
            ReasonCode::DisconnectWithWillMessage => println!("Disconnected with Will message!"),
            ReasonCode::NoMatchingSubscribers => println!("No matching subscribers on broker!"),
            ReasonCode::NoSubscriptionExisted => println!("Subscription not exist!"),
            ReasonCode::ContinueAuth => println!("Broker asks for more AUTH packets!"),
            ReasonCode::ReAuthenticate => println!("Broker requires re-authentication!"),
            ReasonCode::UnspecifiedError => println!("Unspecified error!"),
            ReasonCode::MalformedPacket => println!("Malformed packet sent!"),
            ReasonCode::ProtocolError => println!("Protocol specific error!"),
            ReasonCode::ImplementationSpecificError => println!("Implementation specific error!"),
            ReasonCode::UnsupportedProtocolVersion => println!("Unsupported protocol version!"),
            ReasonCode::ClientIdNotValid => println!("Client sent not valid identification"),
            ReasonCode::BadUserNameOrPassword => {
                println!("Authentication error, username of password not valid!")
            }
            ReasonCode::NotAuthorized => println!("Client not authorized!"),
            ReasonCode::ServerUnavailable => println!("Server unavailable!"),
            ReasonCode::ServerBusy => println!("Server is busy!"),
            ReasonCode::Banned => println!("Client is banned on broker!"),
            ReasonCode::ServerShuttingDown => println!("Server is shutting down!"),
            ReasonCode::BadAuthMethod => println!("Provided bad authentication method!"),
            ReasonCode::KeepAliveTimeout => println!("Client reached timeout"),
            ReasonCode::SessionTakeOver => println!("Took over session!"),
            ReasonCode::TopicFilterInvalid => println!("Topic filter is not valid!"),
            ReasonCode::TopicNameInvalid => println!("Topic name is not valid!"),
            ReasonCode::PacketIdentifierInUse => println!("Packet identifier is already in use!"),
            ReasonCode::PacketIdentifierNotFound => println!("Packet identifier not found!"),
            ReasonCode::ReceiveMaximumExceeded => println!("Maximum receive amount exceeded!"),
            ReasonCode::TopicAliasInvalid => println!("Invalid topic alias!"),
            ReasonCode::PacketTooLarge => println!("Sent packet was too large!"),
            ReasonCode::MessageRateTooHigh => println!("Message rate is too high!"),
            ReasonCode::QuotaExceeded => println!("Quota exceeded!"),
            ReasonCode::AdministrativeAction => println!("Administrative action!"),
            ReasonCode::PayloadFormatInvalid => println!("Invalid payload format!"),
            ReasonCode::RetainNotSupported => println!("Message retain not supported!"),
            ReasonCode::QoSNotSupported => println!("Used QoS is not supported!"),
            ReasonCode::UseAnotherServer => println!("Use another server!"),
            ReasonCode::ServerMoved => println!("Server moved!"),
            ReasonCode::SharedSubscriptionNotSupported => println!("Shared subscription is not supported"),
            ReasonCode::ConnectionRateExceeded => println!("Connection rate exceeded!"),
            ReasonCode::MaximumConnectTime => println!("Maximum connect time exceeded!"),
            ReasonCode::SubscriptionIdentifiersNotSupported => println!("Subscription identifier not supported!"),
            ReasonCode::WildcardSubscriptionNotSupported => println!("Wildcard subscription not supported!"),
            ReasonCode::TimerNotSupported => println!("Timer implementation is not provided"),
            ReasonCode::BuffError => println!("Error encountered during write / read from packet"),
            ReasonCode::NetworkError => println!("Unknown error!"),
        }
    }

    match client.connect_to_broker().await {
        Ok(()) => {}
        Err(mqtt_error) => handle_mqtt_error(mqtt_error),
    }

    loop {
        Timer::after(Duration::from_millis(1_000)).await;
        let temperature_string = "Hello World";
        
        match client
            .send_message(
                "temperature/1",
                temperature_string.as_bytes(),
                rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1,
                true,
            )
            .await
        {
            Ok(()) => {}
            Err(mqtt_error) => handle_mqtt_error(mqtt_error),
        }
        Timer::after(Duration::from_millis(3000)).await;
    }
}

