from backend import TransportAuthority, RSA

ta = TransportAuthority("DELHI TRANSPORT AUTHORITY",
                        12345, (5, 91), (29, 91))

cert = (1,) + RSA.rsa_encode_string("DELHI TRANSPORT AUTHORITY") + \
    RSA.rsa_encode_string("Dushyant Panchal")

print(f"""
    "cert": {cert},
    "sign": {ta.sign(cert)}
""")
