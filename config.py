# local Socks5 Setting
ip = "192.168.1.2"
port = 9999
username = '111'
password = '111'

# Multi-hop proxy set, domain-mode is not yet supported 
# DONT FORGET TO SET PROXYCHAIN!
proxy1 = {
	"mode":"Socks5",
	"ip":"192.168.1.1",
	"port":9999,
	"username":"admin",
	"password":"810975"
}
# proxy2 = {
# 	"mode":"Socks5",
# 	"ip":"192.168.1.22",
# 	"port":19999,
# 	"username":"admin",
# 	"password":"12345"
# }
proxychain=[proxy1]
# proxychain=[proxy1,proxy2]