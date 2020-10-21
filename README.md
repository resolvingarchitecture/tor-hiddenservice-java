# TOR Hidden Service

## TOR Project Information
https://2019.www.torproject.org/docs/tor-onion-service.html.en#two

Python Controller Docs: https://stem.torproject.org/

## Tor Embedded
To come...

## Tor External
TOR as a hidden service running with an external TOR instance requires installing TOR as a daemon.
This is accomplished by the 1M5 TOR Sensor by using the local Tor's SOCKSv5 proxy address and port.
Install and configure TOR daemon:

1. sudo apt-get update
2. sudo apt-get upgrade
3. sudo apt install tor -y
4. in /etc/tor/torrc uncomment line: ControlPort 9051
5. in /etc/tor/torrc uncomment line: CookieAuthentication 1
6. in /etc/tor/torrc replace: CookieAuthentication 1 with CookieAuthentication 0
7. tor
