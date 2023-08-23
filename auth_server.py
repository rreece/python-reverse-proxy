"""
Based on:
https://docs.python.org/3/library/http.server.html
https://www.pythonpool.com/python-http-server/
https://gist.github.com/dragermrb/108158f5a284b5fba806
"""

from http.server import BaseHTTPRequestHandler, HTTPServer


URL = "https://en.wikipedia.org"
KEY = "1234"


class AuthServer(BaseHTTPRequestHandler):
    def do_GET(self):
        auth_token = self.headers.get("authentication")
        if auth_token == KEY:
            print("DEBUG: Authorized!")
            text_reply = "You have authenticated."
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(text_reply, "utf-8"))
        else:
            print("DEBUG: Authorization failed!")
            text_reply = "ERROR: Authorization failed!"
            self.send_response(401)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(text_reply, "utf-8"))

    def do_POST(self):
        auth_token = self.headers.get("authentication")
        content_len = int(self.headers.get("Content-Length"))
        post_body = self.rfile.read(content_len)
        print("DEBUG: post_body = ", post_body)

        if auth_token == KEY:
            print("DEBUG: Authorized!")
            text_reply = "You have authenticated."
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(text_reply, "utf-8"))
        else:
            print("DEBUG: Authorization failed!")
            text_reply = "ERROR: Authorization failed!"
            self.send_response(401)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(text_reply, "utf-8"))


def main():
    host_name = "localhost"
    sever_port = 9000
    server = HTTPServer((host_name, sever_port), AuthServer)
    print(f"Server started http://{host_name}:{sever_port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("Http server stopped.")


if __name__ == "__main__":
    main()
