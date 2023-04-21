#!/usr/bin/env python3
import argparse
from http.server import BaseHTTPRequestHandler,HTTPServer
import os
import requests
from socketserver import ThreadingMixIn
import sys


URL = "https://en.wikipedia.org"
KEY = "1234"


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    hostname = URL

    def do_HEAD(self):
        self.do_GET(body=False)
        return
        
    def do_GET(self, body=True):
        sent = False
        try:
            url = "%s%s" % (URL, self.path)
            print("DEBUG: url = ", url)
            req_headers = self.parse_headers(self.headers)
#            print(req_headers)
#            print(url)
            headers = dict(req_headers)
            headers.update({"Host": self.hostname})
            resp = requests.get(url, headers=headers, verify=False)
            sent = True
#            help(resp)
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
            url = "%s%s" % (URL, self.path)
            print("DEBUG: URL = ", URL)
            print("DEBUG: url = ", url)
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len)
            req_headers = self.parse_headers(self.headers)
            headers = dict(req_headers)
            headers.update({"Host": self.hostname})
            print("DEBUG: post_body = ", post_body)
            print("DEBUG: headers = ", headers)
            resp = requests.post(url, data=post_body, headers=headers, verify=False)
            print("DEBUG: resp = ", headers)
            sent = True
            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            if body:
                self.wfile.write(resp.content)
            return
        finally:
            if not sent:
                self.send_error(404, "ERROR trying to proxy!")

    def parse_headers(self, headers):
        print("DEBUG: type(parse_headers) = ", type(headers))
        print("DEBUG: parse_headers = ", headers)
        req_headers = {}
        for key in headers:
            print("DEBUG: parse_headers key = ", key)
            req_headers[key] = headers[key]
        print("DEBUG: parse_headers req_headers = ", req_headers)
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
    parser.add_argument("--hostname", dest="hostname", type=str, default=URL,
                        help="hostname to be processd (default: en.wikipedia.org)")
    args = parser.parse_args()
    return args


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def main():
    args = parse_args()
    ProxyHTTPRequestHandler.hostname = args.hostname
    localhost = "127.0.0.1"
    print("http server is starting on {} port {}...".format(localhost, args.port))
    server_address = (localhost, args.port)
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
