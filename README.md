# TOR Hidden Service

## TOR Project Information
https://2019.www.torproject.org/docs/tor-onion-service.html.en#two

Python Controller Docs: https://stem.torproject.org/

## Tor Router
TOR as a hidden service running with an external TOR instance requires installing TOR as a daemon.
Install and configure TOR daemon:

1. update distro (ubuntu: sudo apt-get update, alpine: apk update)
2. upgrade distro (ubuntu: sudo apt-get upgrade, alpine: apk upgrade)
3. install tor (ubuntu: sudo apt install tor -y, alpine: apk add tor)
4. if torrc doesn't exist in /etc/tor, then copy /etc/tor/torrc.sample to /etc/tor/torrc
5. in /etc/tor/torrc uncomment line: ControlPort 9051
6. in /etc/tor/torrc uncomment line: CookieAuthentication 1
7. in /etc/tor/torrc replace: CookieAuthentication 1 with CookieAuthentication 0
8. register tor as a service (alpine: rc-update add tor)
9. start tor service (alpine: rc-service tor start)

If you want to specify a virtual port and/or a target port use the following parameters for the service:

* ra.tor.virtualPort
* ra.tor.targetPort

Not providing them will result in them being assigned random ports.

An HTTP Server listening on the targetPort will get started on service start.
