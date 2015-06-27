import time
import threading
import socketserver
import socket
import logging
from dns_packet import DNSPacket

logging.basicConfig(level=logging.WARNING)
cache = {}
forwarder_addr = None


class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global cache
        response = None
        # Get recv data
        data = self.request[0]
        # Get socket to answer to client
        sock = self.request[1]
        cur_thread = threading.current_thread()
        request = DNSPacket(data)
        record = request.data[2:]
        if record in cache:
            logging.debug(cache[record])
            cache_data = cache[record][0].data
            cache_time = cache[record][1]
            cache_ttl = cache[record][2]
            if time.time() - cache_time <= cache_ttl:
                response = DNSPacket(cache_data)
                response.add_id(request.HEADER[0])
                response.set_ttl(cache_time, cache_ttl, time.time())
                sock.sendto(response.data, self.client_address)
                logging.warning("Response from cache")
                logging.warning(response.QNAME[0].decode("utf-8"))
                return

        # Have to ask forwarder
        try:
            f_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            f_sock.sendto(data, forwarder_addr)
            response = f_sock.recv(4096)
        except socket.timeout:
            # We don't have to crash if we have timeout from forwarder
            # Just go on
            pass

        if response:
            response_packet = DNSPacket(response)
            sock.sendto(response_packet.data, self.client_address)
            cache[record] = [response_packet, time.time(), response_packet.get_ttl()]
            logging.warning("Response from forwarder")
            logging.warning(response_packet.QNAME[0].decode("utf-8"))
            logging.debug(cache)
            logging.debug(cache[record][0].data)


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass


class DNSCacheServer:
    """
    Cache full ANSWERS from forwarder
    """
    def __init__(self, ip, port, forwarder_ip):
        self.ip = ip
        self.port = port
        global forwarder_addr
        forwarder_addr = (forwarder_ip, 53)

    def run_server(self):
        server = ThreadedUDPServer((self.ip, self.port), ThreadedUDPRequestHandler)

        # Start a thread with the server - that thread will then start one more
        # per each request
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        logging.warning("Running dns on {} {}".format(self.ip, self.port))
        logging.debug("Server loop running in thread: {}".format(server_thread.name))

        try:
            while 1:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            logging.warning("Exiting")
            server.shutdown()

if __name__ == '__main__':
    s = DNSCacheServer("localhost", 53, "8.8.8.8")
    s.run_server()
