# proxy-Zata

proxy-Zata
v1.0

This is a local Socks5 server written in python, used for integrating Multi-hop (Socks4/Socks5/HTTP) forward proxy then provide one local Socks5 proxy which is already builded and connected all the Multi-hop (Socks4/Socks5/HTTP) proxies you set. 

It is built in case your application is not works for Multi-hop proxies instand of one proxy( such as burp suite, most of python web tools...). proxy-Zata can proccess complex proxychain and provide your application a useable proxy.

1. proxy-Zata <---> proxy1 <---> proxy2 <---> proxy3
2. your application <---> proxy-Zata <---> proxy1 <---> proxy2 <---> proxy3 <---> target

so far, it only works for socks protocol.

## usage
see config.py

## about
local-server part is from [rushter/socks5](https://github.com/rushter/socks5)
