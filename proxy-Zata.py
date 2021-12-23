import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
import config

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    remote = None

    def handle(self):
        
        logging.info('Accepting connection from %s:%s' % self.client_address)

        # greeting header
        # read and unpack 2 bytes from a client
        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        # socks 5
        assert version == SOCKS_VERSION
        assert nmethods > 0

        # get available methods
        methods = self.get_available_methods(nmethods)

        # accept only USERNAME/PASSWORD auth
        if 2 not in set(methods):
            # close connection
            self.server.close_request(self.request)
            return

        # send welcome message
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

        if not self.verify_credentials():
            return

        # setup proxychain
        if config.proxychain :
            self.setup_proxychain()
            self.exchange_loop(self.connection, self.get_remote())
        else:
            # request
            version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
            assert version == SOCKS_VERSION

            if address_type == 1:  # IPv4
                address = socket.inet_ntoa(self.connection.recv(4))
            elif address_type == 3:  # Domain name
                domain_length = self.connection.recv(1)[0]
                address = self.connection.recv(domain_length)
                address = socket.gethostbyname(address)
            port = struct.unpack('!H', self.connection.recv(2))[0]
            # reply
            try:
                if cmd == 1:  # CONNECT
                    # remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote = self.get_remote()
                    remote.connect((address, port))
                    bind_address = remote.getsockname()
                    logging.info('Connected to %s %s' % (address, port))
                else:
                    self.server.close_request(self.request)

                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
                port = bind_address[1]
                reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1,
                                    addr, port)
            except Exception as err:
                logging.error(err)
                # return connection refused error
                reply = self.generate_failed_reply(address_type, 5)
            self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == config.username and password == config.password:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break
    
    def setup_proxychain(self):
        logging.info('setup proxychain')
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((config.proxychain[0].get("ip"),config.proxychain[0].get("port")))
            for i in range(len(config.proxychain)) :
                if i == (len(config.proxychain) - 1) :
                    remote = self.connect_to_proxy(remote, config.proxychain[i])
                else :
                    remote = self.connect_to_proxy(remote, config.proxychain[i], config.proxychain[i+1].get("ip"), config.proxychain[i+1].get("port"))
        except Exception as err:
            logging.error(err)
        self.remote = remote

    def connect_to_proxy(self, mysocket, proxy, *target): 
        logging.info('connected to proxy %s %s' % (proxy.get('ip') , proxy.get('port')))
        #mysocket.connect((proxy.get('ip') , proxy.get('port')))
        use_auth = 0
        if 'username' in proxy and 'password' in proxy and len(proxy.get('username')) > 0 and len(proxy.get('password')) > 0 :
            mysocket.sendall(struct.pack("!BBBB", SOCKS_VERSION, 2, 0, 2))
            use_auth = 1
        else :
            mysocket.sendall(struct.pack("!BBB", SOCKS_VERSION, 1, 0))
        version , auth = struct.unpack("!BB",mysocket.recv(2))
        assert version == 5
        if auth == 2:
            if not use_auth :
                logging.error("No username/password supplied, Server %s requested authentication" % (proxy.get('ip').join(proxy.get('port'))))
                return None
            else: 
                mysocket.sendall(struct.pack("!BB%dsB%ds" % (len(proxy.get('username')),len(proxy.get('password'))), 1, len(proxy.get('username')), proxy.get('username').encode(), len(proxy.get('password')), proxy.get('password').encode()))               
                assert struct.unpack("!BB",mysocket.recv(2)) == (1,0)
        else :
            assert auth == 0
        # finish authentication ,send connect  
        if target and target[0] and target[1]:
            mysocket.sendall(struct.pack("!BBBB4sH", SOCKS_VERSION, 1, 0, 1, socket.inet_aton(target[0]), target[1]))
            version,rep,_,_,_,_ = struct.unpack("!BBBBIH", mysocket.recv(10))
            assert version == 5 and rep == 0

        return mysocket

    def get_remote(self):
        if not self.remote:
            if not config.proxychain:
                self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                logging.error("proxychain setup error")
        return self.remote


if __name__ == '__main__':
    with ThreadingTCPServer((config.ip, config.port), SocksProxy) as server:
        server.serve_forever()