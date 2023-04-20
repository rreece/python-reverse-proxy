#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse, sys, requests

from socketserver import ThreadingMixIn


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    hostname = "en.wikipedia.org"

    def do_HEAD(self):
        self.do_GET(body=False)
        return
        
    def do_GET(self, body=True):
        sent = False
        try:
            url = "https://{}{}".format(self.hostname, self.path)
            req_headers = self.parse_headers()

            print(req_headers)
            print(url)
            headers = dict(req_headers)
#            headers.update({"Host": self.hostname})
            resp = requests.get(url, headers=headers, verify=False)
            sent = True
            help(resp)
            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            msg = resp.text
            if body:
                self.wfile.write(msg.encode(encoding="UTF-8", errors="strict"))
            return
        finally:
            if not sent:
                self.send_error(404, "ERROR trying to proxy!")

    def do_POST(self, body=True):
        sent = False
        try:
            url = "https://{}{}".format(self.hostname, self.path)
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len)
            req_headers = self.parse_headers()
            headers = dict(req_headers)
            headers.update({"Host": self.hostname})
            resp = requests.post(url, data=post_body, headers=headers, verify=False)
            sent = True

            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            if body:
                self.wfile.write(resp.content)
            return
        finally:
            if not sent:
                self.send_error(404, "ERROR trying to proxy!")

    def parse_headers(self):
        req_headers = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(":", 1)]
            if len(line_parts) == 2:
                req_headers[line_parts[0]] = line_parts[1]
        return req_headers

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        print ("Response Header")
        for key in respheaders:
            if key not in ["Content-Encoding", "Transfer-Encoding", "content-encoding", "transfer-encoding", "content-length", "Content-Length"]:
                print (key, respheaders[key])
                self.send_header(key, respheaders[key])
        self.send_header("Content-Length", len(resp.content))
        self.end_headers()


def parse_args():
    parser = argparse.ArgumentParser(description="Proxy HTTP requests")
    parser.add_argument("--port", dest="port", type=int, default=9999,
                        help="serve HTTP requests on specified port (default: random)")
    parser.add_argument("--hostname", dest="hostname", type=str, default="en.wikipedia.org",
                        help="hostname to be processd (default: en.wikipedia.org)")
    args = parser.parse_args()
    return args


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def main():
    args = parse_args()
    ProxyHTTPRequestHandler.hostname = args.hostname
    print("http server is starting on {} port {}...".format(args.hostname, args.port))
    server_address = ("127.0.0.1", args.port)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print("http server is running as reverse proxy")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    print("Http server stopped.")


if __name__ == "__main__":
    main()
