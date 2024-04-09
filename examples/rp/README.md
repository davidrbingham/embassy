
docker run --name mq -it -p 1883:1883 -p 9001:9001 -v /etc/mosquitto/mosquitto.conf:/mosquitto/config/mosquitto.conf -v /mosquitto/data -v /mosquitto/log eclipse-mosquitto

https://marketplace.visualstudio.com/items?itemName=probe-rs.probe-rs-debugger