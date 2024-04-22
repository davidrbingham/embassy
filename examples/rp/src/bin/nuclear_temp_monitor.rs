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
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{InterruptHandler, Pio};
use embassy_time::{Duration, Timer, Instant, TICK_HZ};
use p256::ecdsa::Signature;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use rust_mqtt::{
    client::{client::MqttClient, client_config::ClientConfig},
    packet::v5::reason_codes::ReasonCode,
    utils::rng_generator::CountingRng,
};

use p256::{
    pkcs8::DecodePrivateKey,
    ecdsa::{SigningKey, VerifyingKey},
    ecdsa::signature::Verifier,
    elliptic_curve::generic_array::GenericArray,
    SecretKey,
};

use blake2::{Blake2s256, Digest};

use heapless::{Vec, String};

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

const HEX_STRING_CAPACITY_64: usize = 64; // Blake2s256 hash is 32 bytes, hex is 2x size
const HEX_STRING_CAPACITY_128: usize = 128; // ECC signature is 64 bytes, hex is 2x size

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Hello World from Pi Pico to MQTT for COM771!");

    let p = embassy_rp::init(Default::default());

    let fw = include_bytes!("../../../../cyw43-firmware/43439A0.bin");
    let clm = include_bytes!("../../../../cyw43-firmware/43439A0_clm.bin");

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
    let seed = 0x0123_4567_89ab_cdef;

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
        match control.join_wpa2(WIFI_NETWORK, WIFI_PASSWORD).await {
            Ok(_) => break,
            Err(err) => {
                info!("join failed with status={}", err.status);
            }
        }
    }

    info!("waiting for DHCP...");
    while !stack.is_config_up() {
        Timer::after_millis(100).await;
    }
    info!("DHCP is now up!");

    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];

    let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
    socket.set_timeout(Some(Duration::from_secs(30)));

    // TODO Set the IP Address of the machine running Docker with Mosquitto image - 192.168.1.180
    let remote_endpoint = (Ipv4Address::new(192, 168, 1, 184), 8883);
    // let remote_endpoint = (Ipv4Address::new(192, 168, 1, 180), 1883);

    info!("MQTT :: connecting...");
    let connection = socket.connect(remote_endpoint).await;
    if let Err(e) = connection {
        error!("MQTT :: connect error: {:?}", e);
    }
    info!("MQTT :: connected!");

    let mut config = ClientConfig::new(
        rust_mqtt::client::client_config::MqttVersion::MQTTv5,
        CountingRng(20000),
    );
    config.add_max_subscribe_qos(rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1);
    config.add_client_id("clientId-pi-pico-w");
    config.keep_alive = 3000;
    config.max_packet_size = 300;
    let mut recv_buffer = [0; 300];
    let mut write_buffer = [0; 300];

    let mut client = MqttClient::<_, 5, _>::new(socket, &mut write_buffer, 300, &mut recv_buffer, 300, config);

    match client.connect_to_broker().await {
        Ok(()) => {}
        Err(mqtt_error) => handle_mqtt_error(mqtt_error),
    }

    let mut adc = Adc::new(p.ADC, Irqs, embassy_rp::adc::Config::default());
    let mut ts = embassy_rp::adc::Channel::new_temp_sensor(p.ADC_TEMP_SENSOR);

    let signing_key = get_ecc_p256_signing_key_from_der();

    loop {
        let temp = adc.read(&mut ts).await.unwrap();
        let temp_celsius = convert_to_celsius(temp);
        info!("Temp: {} degrees", &temp_celsius);

        // Message 1: Raw Temperature without ECC or Blake2 Hashing

        let mut message_data = String::<50>::new();
        if let Ok(_) = core::fmt::write(&mut message_data, format_args!("Reactor Core Temperature :: {:.1} °C", &temp_celsius)) {
            info!("Raw message to MQTT: {}", message_data);            
        } else {
            error!("Failed to write to the MQTT string!");
            continue;
        }

        info!("Message 1: Raw MQTT Message {:?}", &message_data);

        match client
        .send_message(
            "temperature/1",
            &message_data.as_bytes(),
            rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1,
            true,
        )
        .await
        {
            Ok(()) => {}
            Err(mqtt_error) => handle_mqtt_error(mqtt_error),
        }

        Timer::after(Duration::from_millis(1000)).await;

        // Message 2: Raw Temperature with Blake2 Hash

        let mut message_data = String::<50>::new();
        if let Ok(_) = core::fmt::write(&mut message_data, format_args!("Reactor Core Temperature :: {:.1} °C", &temp_celsius + 1.0)) {
            info!("Raw message to MQTT: {}", message_data);            
        } else {
            error!("Failed to write to the MQTT string!");
            continue;
        }

        let overhead_start = Instant::now();

        let hex_string_from_message_hash = hash_message_blake2(&message_data);

        let overhead_end = Instant::now();
        let duration_ms: String<16> = duration_to_bytes(overhead_start, overhead_end);

        let mqtt_hashed_raw_message = sign_message(&hex_string_from_message_hash.as_bytes(), &message_data.as_bytes(), &duration_ms);

        let mqtt_hashed_raw_message_slice: &[u8] = mqtt_hashed_raw_message.as_slice();

        info!("Message 2: Raw MQTT Message {:?}", &message_data);
        info!("Message 2: Hashed MQTT Message {:?}", &mqtt_hashed_raw_message_slice);

        match client
        .send_message(
            "temperature/2",
            mqtt_hashed_raw_message_slice,
            rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1,
            true,
        )
        .await
        {
            Ok(()) => {}
            Err(mqtt_error) => handle_mqtt_error(mqtt_error),
        }

        Timer::after(Duration::from_millis(1000)).await;

        // Message 3: Raw Temperature with ECC Signature generated from raw message text (unhashed)

        let mut message_data = String::<50>::new();
        if let Ok(_) = core::fmt::write(&mut message_data, format_args!("Reactor Core Temperature :: {:.1} °C", &temp_celsius - 1.0)) {
            info!("Raw message to MQTT: {}", message_data);            
        } else {
            error!("Failed to write to the MQTT string!");
            continue;
        }

        let overhead_start = Instant::now();

        let (r_bytes, s_bytes) = generate_signature(&signing_key, &message_data.as_bytes());
        let hex_string_from_signature = convert_signature_to_hex_string(&r_bytes, &s_bytes);

        let overhead_end = Instant::now();
        let duration_ms: String<16> = duration_to_bytes(overhead_start, overhead_end);

        let mqtt_signed_raw_message = sign_message(&hex_string_from_signature.as_bytes(), &message_data.as_bytes(), &duration_ms);
        let mqtt_signed_raw_message_slice: &[u8] = mqtt_signed_raw_message.as_slice();

        info!("Message 3: Raw MQTT Message {:?}", &message_data);
        info!("Message 3: Signed MQTT Message {:?}", &mqtt_signed_raw_message_slice);
        info!("Message 3: Raw MQTT Signature as hex string {:?}", &hex_string_from_signature);

        match client
            .send_message(
                "temperature/3",
                mqtt_signed_raw_message_slice,
                rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1,
                true,
            )
            .await
        {
            Ok(()) => {}
            Err(mqtt_error) => handle_mqtt_error(mqtt_error),
        }

        Timer::after(Duration::from_millis(1000)).await;

        // Message 4: Raw Temperature with ECC Signature generated after Blake2 hashing of raw message

        let mut message_data = String::<50>::new();
        if let Ok(_) = core::fmt::write(&mut message_data, format_args!("Reactor Core Temperature :: {:.1} °C", &temp_celsius + 2.0)) {
            info!("Raw message to MQTT: {}", message_data);            
        } else {
            error!("Failed to write to the MQTT string!");
            continue;
        }

        let overhead_start = Instant::now();

        let hex_string_from_message_hash = hash_message_blake2(&message_data);

        let (r_bytes, s_bytes) = generate_signature(&signing_key, &hex_string_from_message_hash.as_bytes());
        let hex_string_from_signature = convert_signature_to_hex_string(&r_bytes, &s_bytes);

        let overhead_end = Instant::now();
        let duration_ms: String<16> = duration_to_bytes(overhead_start, overhead_end);

        let mqtt_signed_hashed_raw_message = sign_message(&hex_string_from_signature.as_bytes(), &message_data.as_bytes(), &duration_ms);
        let mqtt_signed_hashed_message_slice: &[u8] = mqtt_signed_hashed_raw_message.as_slice();

        info!("Message 4: Raw MQTT Message {:?}", &message_data);
        info!("Message 4: Hex string used to create ECC signature to be matched on Java side {:?}", &hex_string_from_message_hash);

        match client
            .send_message(
                "temperature/4",
                mqtt_signed_hashed_message_slice,
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

fn handle_mqtt_error(mqtt_error: ReasonCode) {
    match mqtt_error {
        ReasonCode::Success => info!("Operation was successful!"),
        ReasonCode::GrantedQoS1 => info!("Granted QoS level 1!"),
        ReasonCode::GrantedQoS2 => info!("Granted QoS level 2!"),
        ReasonCode::DisconnectWithWillMessage => info!("Disconnected with Will message!"),
        ReasonCode::NoMatchingSubscribers => info!("No matching subscribers on broker!"),
        ReasonCode::NoSubscriptionExisted => info!("Subscription not exist!"),
        ReasonCode::ContinueAuth => info!("Broker asks for more AUTH packets!"),
        ReasonCode::ReAuthenticate => info!("Broker requires re-authentication!"),
        ReasonCode::UnspecifiedError => info!("Unspecified error!"),
        ReasonCode::MalformedPacket => info!("Malformed packet sent!"),
        ReasonCode::ProtocolError => info!("Protocol specific error!"),
        ReasonCode::ImplementationSpecificError => info!("Implementation specific error!"),
        ReasonCode::UnsupportedProtocolVersion => info!("Unsupported protocol version!"),
        ReasonCode::ClientIdNotValid => info!("Client sent not valid identification"),
        ReasonCode::BadUserNameOrPassword => {
            info!("Authentication error, username of password not valid!")
        }
        ReasonCode::NotAuthorized => info!("Client not authorized!"),
        ReasonCode::ServerUnavailable => info!("Server unavailable!"),
        ReasonCode::ServerBusy => info!("Server is busy!"),
        ReasonCode::Banned => info!("Client is banned on broker!"),
        ReasonCode::ServerShuttingDown => info!("Server is shutting down!"),
        ReasonCode::BadAuthMethod => info!("Provided bad authentication method!"),
        ReasonCode::KeepAliveTimeout => info!("Client reached timeout"),
        ReasonCode::SessionTakeOver => info!("Took over session!"),
        ReasonCode::TopicFilterInvalid => info!("Topic filter is not valid!"),
        ReasonCode::TopicNameInvalid => info!("Topic name is not valid!"),
        ReasonCode::PacketIdentifierInUse => info!("Packet identifier is already in use!"),
        ReasonCode::PacketIdentifierNotFound => info!("Packet identifier not found!"),
        ReasonCode::ReceiveMaximumExceeded => info!("Maximum receive amount exceeded!"),
        ReasonCode::TopicAliasInvalid => info!("Invalid topic alias!"),
        ReasonCode::PacketTooLarge => info!("Sent packet was too large!"),
        ReasonCode::MessageRateTooHigh => info!("Message rate is too high!"),
        ReasonCode::QuotaExceeded => info!("Quota exceeded!"),
        ReasonCode::AdministrativeAction => info!("Administrative action!"),
        ReasonCode::PayloadFormatInvalid => info!("Invalid payload format!"),
        ReasonCode::RetainNotSupported => info!("Message retain not supported!"),
        ReasonCode::QoSNotSupported => info!("Used QoS is not supported!"),
        ReasonCode::UseAnotherServer => info!("Use another server!"),
        ReasonCode::ServerMoved => info!("Server moved!"),
        ReasonCode::SharedSubscriptionNotSupported => info!("Shared subscription is not supported"),
        ReasonCode::ConnectionRateExceeded => info!("Connection rate exceeded!"),
        ReasonCode::MaximumConnectTime => info!("Maximum connect time exceeded!"),
        ReasonCode::SubscriptionIdentifiersNotSupported => info!("Subscription identifier not supported!"),
        ReasonCode::WildcardSubscriptionNotSupported => info!("Wildcard subscription not supported!"),
        ReasonCode::TimerNotSupported => info!("Timer implementation is not provided"),
        ReasonCode::BuffError => info!("Error encountered during write / read from packet"),
        ReasonCode::NetworkError => info!("Unknown error!"),
    }
}

fn load_keys_from_der() -> (SigningKey, VerifyingKey) {
    let private_key_der = include_bytes!("ecc/pkcs8-private-key.der");
    let private_key = SecretKey::from_pkcs8_der(private_key_der).unwrap();
    let signing_key = SigningKey::from(private_key);
    let public_key = VerifyingKey::from(&signing_key);
    (signing_key, public_key)
}

fn generate_signature(signing_key: &SigningKey, message: &[u8]) -> ([u8; 32], [u8; 32]) {
    let (signature, v) = signing_key.sign_recoverable(message).unwrap();
    
    let compact_signature = signature.to_bytes();
    
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&compact_signature[..32]);
    s_bytes.copy_from_slice(&compact_signature[32..]);
    
    (r_bytes, s_bytes)
}

fn verify_signature(public_key: &VerifyingKey, message: &[u8], r_bytes: [u8; 32], s_bytes: [u8; 32]) -> bool {
    let mut compact_signature = [0u8; 64];
    compact_signature[..32].copy_from_slice(&r_bytes);
    compact_signature[32..].copy_from_slice(&s_bytes);
    
    let generic_array_signature = GenericArray::from(compact_signature);
    
    let signature = Signature::from_bytes(&generic_array_signature).unwrap();    
    public_key.verify(message, &signature).is_ok()
}

fn get_ecc_p256_signing_key_from_der() -> SigningKey {
    let (signing_key, public_key) = load_keys_from_der();
    let mqtt_message = b"Hello world, MQTT!";
    
    let (r_bytes, s_bytes) = generate_signature(&signing_key, mqtt_message);
    let is_valid_signature = verify_signature(&public_key, mqtt_message, r_bytes, s_bytes);
    
    if is_valid_signature {
        info!("Signature is valid!");
    } else {
        info!("Signature is invalid!");
    }
    
    signing_key
}

fn convert_hash_to_hex_string(hashed_message: &[u8]) -> heapless::String<HEX_STRING_CAPACITY_64> {
    let mut hex_string_from_message_hash: heapless::String<HEX_STRING_CAPACITY_64> = heapless::String::new();
    let mut hex_bytes = [0u8; HEX_STRING_CAPACITY_64];
    hex::encode_to_slice(hashed_message, &mut hex_bytes).unwrap();
    let hex_str = unsafe {
        core::str::from_utf8_unchecked(&hex_bytes)
    };
    hex_string_from_message_hash.push_str(hex_str).unwrap();
    hex_string_from_message_hash
}

fn convert_signature_to_hex_string(r_bytes: &[u8; 32], s_bytes: &[u8; 32]) -> heapless::String<HEX_STRING_CAPACITY_128> {
    let mut hex_string_from_signature: heapless::String<HEX_STRING_CAPACITY_128> = heapless::String::new();
    let mut r_hex_bytes = [0u8; HEX_STRING_CAPACITY_64];

    hex::encode_to_slice(r_bytes, &mut r_hex_bytes).unwrap();
    let r_hex_str = unsafe {
        core::str::from_utf8_unchecked(&r_hex_bytes)
    };
    hex_string_from_signature.push_str(r_hex_str).unwrap();
    
    let mut s_hex_bytes = [0u8; HEX_STRING_CAPACITY_64];
    hex::encode_to_slice(s_bytes, &mut s_hex_bytes).unwrap();
    let s_hex_str = unsafe {
        core::str::from_utf8_unchecked(&s_hex_bytes)
    };
    hex_string_from_signature.push_str(s_hex_str).unwrap();
    
    hex_string_from_signature
}

fn convert_to_celsius(raw_temp: u16) -> f32 {
    // According to chapter 4.9.5. Temperature Sensor in RP2040 datasheet
    let temp = 27.0 - (raw_temp as f32 * 3.3 / 4096.0 - 0.706) / 0.001721;
    let sign = if temp < 0.0 { -1.0 } else { 1.0 };
    let rounded_temp_x10: i16 = ((temp * 10.0) + 0.5 * sign) as i16;
    (rounded_temp_x10 as f32) / 10.0
}

fn hash_message_blake2(message_data: &String::<50>) -> heapless::String<HEX_STRING_CAPACITY_64> {
    let mut hasher = Blake2s256::new();
    hasher.update(message_data.as_bytes());
    let hashed_message = hasher.finalize();

    let hex_string_from_message_hash = convert_hash_to_hex_string(hashed_message.as_slice());

    info!("Blake2 Hash from: {}", &message_data); 
    info!("Blake2 Hash bytes: {}", hashed_message.as_slice());
    info!("Blake2 Hash hex string: {}", &hex_string_from_message_hash);

    hex_string_from_message_hash
}

fn duration_to_bytes(start: Instant, end: Instant) -> String<16> {
    let duration_ticks = end.duration_since(start).as_ticks();
    let duration_ms = (duration_ticks * 1000) / TICK_HZ;
    info!("Calculated overhead: {} ms", &duration_ms); 

    let mut duration_str = String::<16>::new();
    if let Ok(_) = core::fmt::write(&mut duration_str, format_args!("{}", &duration_ms)) {
        info!("Calculated overhead as string: {}", &duration_str);
    } else {
        error!("Failed to write to the duration as string!");
    }

    duration_str
}

fn sign_message(signature: &[u8], message: &[u8], duration_ms: &String<16>) -> Vec<u8, 512> {
    let mqtt_message_delimiter = b"####";
    let mut combined_message: Vec<u8, 512> = Vec::new();

    info!("sign_message :: Signature: {:?}", signature);
    info!("sign_message :: Message delimiter: {:?}", mqtt_message_delimiter);
    info!("sign_message :: Message: {:?}", message);
    info!("sign_message :: Duration (ms): {:?}", duration_ms);
    
    combined_message.extend_from_slice(signature);
    info!("sign_message :: Combined message after adding signature: {:?}", combined_message);
    
    combined_message.extend_from_slice(mqtt_message_delimiter);
    info!("sign_message :: Combined message after adding delimiter: {:?}", combined_message);
    
    combined_message.extend_from_slice(message);
    info!("sign_message :: Combined message after adding message: {:?}", combined_message);

    combined_message.extend_from_slice(mqtt_message_delimiter);
    info!("sign_message :: Combined message after adding delimiter: {:?}", combined_message);
    
    combined_message.extend_from_slice(duration_ms.as_bytes());
    info!("sign_message :: Combined message after adding duration: {:?}", combined_message);
    
    combined_message
}