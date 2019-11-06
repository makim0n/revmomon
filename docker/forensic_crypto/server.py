import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, 
                                ciphers="AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256",
                                ssl_version=ssl.PROTOCOL_TLSv1_2,
                                certfile='./keys/cert1.crt', 
                                keyfile="./keys/key_priv1.key", 
                                server_side=True)
httpd.serve_forever()
