//! This example uses the RP Pico W board Wifi chip (cyw43).
//! Connects to specified Wifi network and creates a TCP endpoint on port 1234.

#![no_std]
#![no_main]
#![allow(async_fn_in_trait)]

use cyw43_pio::PioSpi;
use defmt::*;
use embassy_executor::Spawner;
use embassy_rp::adc::Adc;
use embassy_net::tcp::TcpSocket;
use embassy_net::{Config, Stack, StackResources, Ipv4Address};
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output, Pull};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{InterruptHandler, Pio};
use embassy_time::{Duration, Timer};
use p256::elliptic_curve::generic_array::GenericArray;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use rust_mqtt::{
    client::{client::MqttClient, client_config::ClientConfig},
    packet::v5::reason_codes::ReasonCode,
    utils::rng_generator::CountingRng,
};

use p256::{
    pkcs8::{DecodePrivateKey},
};

use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    SecretKey,
};

use p256::ecdsa::signature::Verifier;

use heapless::Vec;

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
    ADC_IRQ_FIFO => embassy_rp::adc::InterruptHandler;
});

const WIFI_NETWORK: &str = "TP-Link_71D9";
const WIFI_PASSWORD: &str = "05794706";

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

    let (signing_key, public_key) = load_keys_from_der();
    let mqtt_message = b"Hello, MQTT!";
    let (signature, v) = sign_message(&signing_key, &mqtt_message[..]);
    let is_valid_signature = verify_signature(&public_key, &mqtt_message[..], signature, v);
    if is_valid_signature {
        info!("Signature is valid!");
    } else {
        info!("Signature is invalid!");
    }

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
    let remote_endpoint = (Ipv4Address::new(192, 168, 1, 181), 1883);
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

    // Get data from the temp and humidity sensor
    let mut adc = Adc::new(p.ADC, Irqs, embassy_rp::adc::Config::default());
    let mut p27 = embassy_rp::adc::Channel::new_pin(p.PIN_27, Pull::None);
    let mut ts = embassy_rp::adc::Channel::new_temp_sensor(p.ADC_TEMP_SENSOR);
    fn convert_to_celsius(raw_temp: u16) -> f32 {
        // According to chapter 4.9.5. Temperature Sensor in RP2040 datasheet
        let temp = 27.0 - (raw_temp as f32 * 3.3 / 4096.0 - 0.706) / 0.001721;
        let sign = if temp < 0.0 { -1.0 } else { 1.0 };
        let rounded_temp_x10: i16 = ((temp * 10.0) + 0.5 * sign) as i16;
        (rounded_temp_x10 as f32) / 10.0
    }

    loop {
        Timer::after(Duration::from_millis(1_000)).await;

        let level = adc.read(&mut p27).await.unwrap();
        info!("Pin 26: {} raw", level);
        let temp = adc.read(&mut ts).await.unwrap();
        info!("Temp: {} degrees", convert_to_celsius(temp));
        
        fn u16_to_bytes<'b>(value: u16) -> &'b [u8; 2] {
            let bytes = value.to_ne_bytes();
            unsafe { &*(bytes.as_ptr() as *const [u8; 2]) }
        }
        let mqtt_message_temp = b"Temperature received from Pi Pico: ";
        let temperature_bytes = temp.to_le_bytes();
        let mut mqtt_message_temp_with_temp: Vec<u8, 128> = Vec::new();
        mqtt_message_temp_with_temp.extend_from_slice(mqtt_message_temp);
        mqtt_message_temp_with_temp.extend_from_slice(&temperature_bytes);
        let (signature, v) = sign_message(&signing_key, &mqtt_message_temp_with_temp[..]);
        
        fn create_message(signature: &[u8], message: &[u8]) -> Vec<u8, 128> {
            let mqtt_message_delimiter = b"####";
            // Create a new vector to hold the concatenated bytes
            let mut combined_message: Vec<u8, 128> = Vec::new();
        
            // Append the signature bytes to the combined message
            combined_message.extend_from_slice(signature);
            combined_message.extend_from_slice(mqtt_message_delimiter);
            // Append the message bytes to the combined message
            combined_message.extend_from_slice(message);
        
            // Return a reference to the combined message
            combined_message
        }

        // Create the combined message
        let combined_message = create_message(&signature, &mqtt_message_temp_with_temp);

        // Convert the combined message vector to a slice
        let combined_message_slice: &[u8] = combined_message.as_slice();

        info!("MQTT Message as byte array {:?}", combined_message_slice);

        match client
            .send_message(
                "temperature/1",
                combined_message_slice,
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

fn load_keys_from_der() -> (SigningKey, VerifyingKey) {
    // Load the private key from DER-encoded data
    let private_key_der = include_bytes!("examples/pkcs8-private-key.der");
    let private_key = SecretKey::from_pkcs8_der(private_key_der).unwrap();
    // Convert the private key to a signing key
    let signing_key = SigningKey::from(private_key);
    // Extract the corresponding public key from the private key
    let public_key = VerifyingKey::from(&signing_key);
    (signing_key, public_key)
}

fn sign_message(signing_key: &SigningKey, message: &[u8]) -> ([u8; 64], u8) {
    // Sign the message using the signing key
    let (signature, v) = signing_key.sign_recoverable(message).unwrap();
    // Serialize the recoverable signature to a compact format
    let compact_signature = signature.to_bytes();
    // Convert RecoveryId to u8
    let recovery_id_u8: u8 = v.into();
    // Convert GenericArray<u8> to [u8; 64]
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(compact_signature.as_slice());
    (signature_array, recovery_id_u8)
}

fn verify_signature(public_key: &VerifyingKey, message: &[u8], signature: [u8; 64], _v: u8) -> bool {
    // Create a Signature from the signature bytes
    let sig = p256::ecdsa::Signature::from_bytes(GenericArray::from_slice(&signature)).unwrap();

    // Verify the signature using the public key
    public_key.verify(message, &sig).is_ok()
}