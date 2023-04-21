#!/usr/bin/env python3
import argparse
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import os
import requests
from socketserver import ThreadingMixIn
import sys


with open("proxy_config.json") as user_file:
    _config = json.load(user_file)

URL  = _config["URL"]
PORT = _config["PORT"]
KEY  = _config["KEY"]


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    hostname = URL

    def do_HEAD(self):
        self.do_GET(include_content=False)
        return
        
    def do_GET(self, include_content=True):
        try:
            auth_token = self.headers.get("authentication")
            if auth_token == KEY:
                url = "%s%s" % (URL, self.path)
                fwd_headers = dict()
                allowed_headers = ["Host", "User-Agent", "Accept", "Content-Type", "Content-Length"]
                for key in allowed_headers:
                    fwd_headers[key] = self.headers[key]
                fwd_headers.update({"Host": self.hostname})
                resp = requests.get(url, headers=fwd_headers, verify=False)
                self.send_response(resp.status_code)
                for key in resp.headers:
                    self.send_header(key, resp.headers[key])
                self.end_headers()
                text_reply = resp.text
                if include_content:
                    self.wfile.write(bytes(text_reply, "utf-8"))
            else:
                self.send_error(401, "ERROR: not authorized!")

        except Exception as exc:
            self.send_error(500, "ERROR trying to proxy!\n%s" % exc)

    def do_POST(self, include_content=True):
        try:
            auth_token = self.headers.get("authentication")
            if auth_token == KEY:
                url = "%s%s" % (URL, self.path)
                fwd_headers = dict()
                allowed_headers = ["Host", "User-Agent", "Accept", "Content-Type", "Content-Length"]
                for key in allowed_headers:
                    fwd_headers[key] = self.headers[key]
                fwd_headers.update({"Host": self.hostname})
                content_len = int(self.headers.get("Content-Length", 0))
                content = self.rfile.read(content_len)
                resp = requests.post(url, data=content, headers=fwd_headers, verify=False)
                self.send_response(resp.status_code)
                for key in resp.headers:
                    self.send_header(key, resp.headers[key])
                self.end_headers()
                if include_content:
                    self.wfile.write(resp.content)
            else:
                self.send_error(401, "ERROR: not authorized!")

        except Exception as exc:
            self.send_error(500, "ERROR trying to proxy!\n%s" % exc)


def parse_args():
    parser = argparse.ArgumentParser(description="Proxy HTTP requests")
    parser.add_argument("--port", dest="port", type=int, default=PORT,
                        help="serve HTTP requests on specified port.")
    parser.add_argument("--hostname", dest="hostname", type=str, default=URL,
                        help="hostname to send requests to.")
    args = parser.parse_args()
    return args


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def main():
    args = parse_args()
    ProxyHTTPRequestHandler.hostname = args.hostname
    route_entry = "0.0.0.0"
    print("http server is starting on %s port %i..." % (route_entry, args.port))
    server_address = (route_entry, args.port)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print("http server is running as reverse proxy to %s" % args.hostname)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    print("http server stopped.")


if __name__ == "__main__":
    main()
