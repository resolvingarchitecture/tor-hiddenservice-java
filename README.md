# TOR Hidden Service

## TOR Project Information
https://2019.www.torproject.org/docs/tor-onion-service.html.en#two

Python Controller Docs: https://stem.torproject.org/

## Tor Router
TOR as a hidden service running with an external TOR instance requires installing TOR as a daemon.
Install and configure TOR daemon:

1. sudo apt-get update
2. sudo apt-get upgrade
3. sudo apt install tor -y
4. in /etc/tor/torrc uncomment line: ControlPort 9051
5. in /etc/tor/torrc uncomment line: CookieAuthentication 1
6. in /etc/tor/torrc replace: CookieAuthentication 1 with CookieAuthentication 0
7. tor

If you want to specify a virtual port and/or a target port use the following parameters for the service:

* ra.tor.virtualPort
* ra.tor.targetPort

Not providing them will result in them being assigned random ports.

An HTTP Server listening on the targetPort will get started on service start.
