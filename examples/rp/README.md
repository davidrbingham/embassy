
docker run --name mq -it -p 1883:1883 -p 9001:9001 -v /etc/mosquitto/mosquitto.conf:/mosquitto/config/mosquitto.conf -v /mosquitto/data -v /mosquitto/log eclipse-mosquitto

https://marketplace.visualstudio.com/items?itemName=probe-rs.probe-rs-debugger


## IP4 Addresses

Set TP Link Travel Router to Shared Hotspot Mode (at http://tplinkwifi.net/).

Set the DHCP IP4 Range - 192.168.1.180 - 192.168.1.199

On MAC:

Local IP address
For wireless: Use ipconfig getifaddr en0
For ethernet: Use ipconfig getifaddr en1.

ipconfig getifaddr en0 is default for the Wi-Fi network adapter

Make sure you are connected to the router you are testing with as this will change.

```
ipconfig getifaddr en0
192.168.1.180
```

## DHT Sensor

https://github.com/michaelbeaumont/dht-sensor