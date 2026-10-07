#!/usr/bin/env python3
"""A reverse proxy that shows a web UI under placeholder names.

    mask-proxy.py --listen 18097 --upstream http://127.0.0.1:19097 \\
        --map real-name=placeholder [--map ...]

Every --map pair is replaced in the text the upstream returns, and replaced
back in the paths the browser asks for, so the browser only ever sees, and
only ever asks for, the placeholders. Pairs are applied in the order given;
put the longer names first.

It exists for demo 5: the Tekton Dashboard shows the names of real runs,
repositories and images, and a web page cannot be passed through sed the way
terminal output can.

WebSocket upgrades are refused. They would carry the same names in frames this
proxy does not rewrite; the recording reloads the page instead of watching.
"""
import argparse
import http.client
import http.server
import socketserver
import urllib.parse

TEXT = ('text/', 'application/json', 'application/javascript', 'application/yaml', 'application/x-ndjson')


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    upstream = None
    pairs = []

    def log_message(self, *args):
        pass

    def shown(self, data: bytes) -> bytes:
        for real, placeholder in self.pairs:
            data = data.replace(real, placeholder)
        return data

    def real(self, text: str) -> str:
        for real, placeholder in self.pairs:
            text = text.replace(placeholder.decode(), real.decode())
        return text

    def do_GET(self):
        if self.headers.get('Upgrade', '').lower() == 'websocket':
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        target = urllib.parse.urlsplit(self.upstream)
        conn = http.client.HTTPConnection(target.hostname, target.port, timeout=600)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ('host', 'accept-encoding', 'connection', 'if-none-match', 'if-modified-since')}
        headers['Accept-Encoding'] = 'identity'
        try:
            conn.request('GET', self.real(self.path), headers=headers)
            resp = conn.getresponse()
        except OSError as err:
            self.send_error(502, str(err))
            return

        self.send_response(resp.status)
        text = resp.getheader('Content-Type', '').startswith(TEXT)
        for key, value in resp.getheaders():
            if key.lower() in ('content-length', 'transfer-encoding', 'connection', 'etag', 'last-modified'):
                continue
            self.send_header(key, value)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()

        def send(chunk: bytes):
            if chunk:
                self.wfile.write(b'%x\r\n%s\r\n' % (len(chunk), chunk))
                self.wfile.flush()

        try:
            if text:
                # Line by line, so a name is never split across two chunks and
                # a log that is still being written reaches the browser as it
                # grows.
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    send(self.shown(line))
            else:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    send(chunk)
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
        except OSError:
            pass
        finally:
            conn.close()


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--listen', type=int, required=True)
    parser.add_argument('--upstream', required=True)
    parser.add_argument('--map', action='append', default=[], metavar='REAL=PLACEHOLDER')
    args = parser.parse_args()
    Handler.upstream = args.upstream
    Handler.pairs = [tuple(part.encode() for part in pair.split('=', 1)) for pair in args.map]
    Server(('127.0.0.1', args.listen), Handler).serve_forever()


if __name__ == '__main__':
    main()
