"""The little of Firefox's Marionette protocol the recording needs.

Marionette is the remote-control protocol built into Firefox (start it with
`firefox --marionette --headless`). Messages are JSON arrays, each prefixed
with its length and a colon. No browser driver or extra package is involved.
"""
import base64
import json
import socket
import time


class Firefox:
    def __init__(self, port=2828, timeout=60):
        deadline = time.time() + timeout
        while True:
            try:
                self.sock = socket.create_connection(('127.0.0.1', port), timeout=120)
                break
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.5)
        self.buffer = b''
        self.next_id = 0
        self._read()  # the server's greeting
        self.command('WebDriver:NewSession', {'capabilities': {'alwaysMatch': {'acceptInsecureCerts': True}}})

    def _read(self):
        while b':' not in self.buffer:
            self.buffer += self.sock.recv(65536)
        length, _, rest = self.buffer.partition(b':')
        length = int(length)
        while len(rest) < length:
            rest += self.sock.recv(1 << 20)
        self.buffer = rest[length:]
        return json.loads(rest[:length])

    def command(self, name, params=None):
        self.next_id += 1
        message = json.dumps([0, self.next_id, name, params or {}])
        self.sock.sendall(f'{len(message)}:{message}'.encode())
        while True:
            reply = self._read()
            if reply[0] == 1 and reply[1] == self.next_id:
                if reply[2]:
                    raise RuntimeError(f'{name}: {reply[2]}')
                return reply[3]

    def resize(self, width, height):
        self.command('WebDriver:SetWindowRect', {'width': width, 'height': height})

    def go(self, url):
        self.command('WebDriver:Navigate', {'url': url})

    def js(self, script, *args):
        return self.command('WebDriver:ExecuteScript', {'script': script, 'args': list(args)})['value']

    def screenshot(self, path):
        data = self.command('WebDriver:TakeScreenshot', {'full': False})['value']
        with open(path, 'wb') as out:
            out.write(base64.b64decode(data))

    def quit(self):
        try:
            self.command('Marionette:Quit', {'flags': ['eForceQuit']})
        except Exception:
            pass
