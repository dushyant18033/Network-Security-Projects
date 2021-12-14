import socket
import sys
from backend import TransportAuthority
import json

if len(sys.argv) < 2:
    quit()
id = int(sys.argv[1])

PORT = 1234
ta = None

# National TransportAuthority
if id == 1:
    PORT = 12341
    ta = TransportAuthority("NATIONAL TRANSPORT AUTHORITY",
                            PORT, (5, 119), (77, 119))

    ta.addPortToDirectory("DELHI TRANSPORT AUTHORITY", 12342)
    ta.addkPUToDirectory("DELHI TRANSPORT AUTHORITY", kPU=(5, 91))

    ta.addPortToDirectory("HARYANA TRANSPORT AUTHORITY", 12343)
    ta.addkPUToDirectory("HARYANA TRANSPORT AUTHORITY", kPU=(17, 91))

# Delhi TransportAuthority
elif id == 2:
    PORT = 12342
    ta = TransportAuthority("DELHI TRANSPORT AUTHORITY",
                            PORT, (5, 91), (29, 91))

    ta.addPortToDirectory("NATIONAL TRANSPORT AUTHORITY",
                          12341, setAsManager=True)
    ta.addkPUToDirectory("NATIONAL TRANSPORT AUTHORITY", kPU=(5, 119))

# Haryana TransportAuthority
elif id == 3:
    PORT = 12343
    ta = TransportAuthority("HARYANA TRANSPORT AUTHORITY",
                            PORT, (17, 91), (17, 91))

    ta.addPortToDirectory("NATIONAL TRANSPORT AUTHORITY",
                          12341, setAsManager=True)
    ta.addkPUToDirectory("NATIONAL TRANSPORT AUTHORITY", kPU=(5, 119))

else:
    quit()

serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind(("", PORT))
serv.listen(5)

print("Listening on port:", PORT)

while True:
    c, addr = serv.accept()
    print('Got connection from', addr)
    msg = json.loads(c.recv(1024).decode())
    print('Got message:', msg)

    # client connection for license verification
    if msg['type'] == 1:
        status = ta.verify(msg['cert'], msg['sign'], msg['signingAuthority'])
        resp = json.dumps({
            "status": ("looks good" if status else "suspicious"),
        })
        print("responding:", resp)
        c.send(resp.encode())

    # connection from another transport authority
    elif msg['type'] == 2:
        resp = json.dumps({
            "signed_cert": ta.obtainPU(msg['authorityName']),
        })
        print("responding:", resp)
        c.send(resp.encode())

    else:
        pass
