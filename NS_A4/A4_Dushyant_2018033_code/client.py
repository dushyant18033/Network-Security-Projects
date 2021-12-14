import socket
import sys
import json

if len(sys.argv) < 2:
    quit()
PORT = int(sys.argv[1])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", PORT))

# license = json.dumps({
#     "type": 1,
#     "signingAuthority": "NATIONAL TRANSPORT AUTHORITY",
#     "cert": (1, 13, 0, 19, 8, 14, 13, 0, 11, 19, 17, 0, 13, 18, 15, 14, 17, 19,
#              0, 20, 19, 7, 14, 17, 8, 19, 24, 3, 20, 18, 7, 24, 0, 13, 19, 15, 0, 13, 2, 7, 0, 11),
#     "sign": 109
# })

license = json.dumps({
    "type": 1,
    "signingAuthority": "DELHI TRANSPORT AUTHORITY",
    "cert": (1, 3, 4, 11, 7, 8, 19, 17, 0, 13, 18, 15, 14, 17, 19, 0, 20, 19, 7, 14, 17, 8, 19, 24, 3, 20, 18, 7, 24, 0, 13, 19, 15, 0, 13, 2, 7, 0, 11),
    "sign": 6
})


print("Sending for verification ...")
s.send(license.encode())

print("Waiting to receive license status from the server ...")
print(s.recv(1024).decode())
