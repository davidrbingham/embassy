
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


## Install Docker on Raspberry Pi 4 64bit

sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

davidbingham@raspberrypi:~ $ docker --version
Docker version 26.0.1, build d260a54

sudo apt-get update
sudo apt-get install docker-compose

## Install Git on Raspberry Pi 4 64bit

sudo apt-get update
sudo apt-get install git-all
git version

git clone https://github.com/davidrbingham/mqtt.git
Use personal access token as the password

## Run docker compose from the command line

cd /workspaces/mqtt/docker
sudo docker-compose -f docker-compose.yaml up

## Setting up Raspberry Pi Wi-Fi Command Line

nmcli dev wifi list
sudo nmcli radio wifi on
sudo nmcli dev wifi connect TP-Link_71D9 password "05794706"
https://forums.raspberrypi.com/viewtopic.php?t=360175
/etc/NetworkManager/system-connections/