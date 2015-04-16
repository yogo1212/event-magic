depth=1 C = GB, ST = United Kingdom, L = Derby, O = Mosquitto, OU = CA, CN = mosquitto.org, emailAddress = roger@atchoo.org
verify return:1
depth=0 C = GB, ST = United Kingdom, L = Derby, O = Mosquitto, OU = Public server, CN = test.mosquitto.org, emailAddress = roger@atchoo.org
verify return:1
CONNECTED(00000003)
---
Certificate chain
 0 s:/C=GB/ST=United Kingdom/L=Derby/O=Mosquitto/OU=Public server/CN=test.mosquitto.org/emailAddress=roger@atchoo.org
   i:/C=GB/ST=United Kingdom/L=Derby/O=Mosquitto/OU=CA/CN=mosquitto.org/emailAddress=roger@atchoo.org
 1 s:/C=GB/ST=United Kingdom/L=Derby/O=Mosquitto/OU=CA/CN=mosquitto.org/emailAddress=roger@atchoo.org
   i:/C=GB/ST=United Kingdom/L=Derby/O=Mosquitto/OU=CA/CN=mosquitto.org/emailAddress=roger@atchoo.org
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIDLTCCApYCCQCs9UdhbDFjdjANBgkqhkiG9w0BAQsFADCBkDELMAkGA1UEBhMC
R0IxFzAVBgNVBAgMDlVuaXRlZCBLaW5nZG9tMQ4wDAYDVQQHDAVEZXJieTESMBAG
A1UECgwJTW9zcXVpdHRvMQswCQYDVQQLDAJDQTEWMBQGA1UEAwwNbW9zcXVpdHRv
Lm9yZzEfMB0GCSqGSIb3DQEJARYQcm9nZXJAYXRjaG9vLm9yZzAeFw0xNTAxMDcy
MjU4MTlaFw0xOTEyMTIyMjU4MTlaMIGgMQswCQYDVQQGEwJHQjEXMBUGA1UECAwO
VW5pdGVkIEtpbmdkb20xDjAMBgNVBAcMBURlcmJ5MRIwEAYDVQQKDAlNb3NxdWl0
dG8xFjAUBgNVBAsMDVB1YmxpYyBzZXJ2ZXIxGzAZBgNVBAMMEnRlc3QubW9zcXVp
dHRvLm9yZzEfMB0GCSqGSIb3DQEJARYQcm9nZXJAYXRjaG9vLm9yZzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALfvUzt6xxFVDnpMzj0fz4VhJQyNQ1Ry
A1pof/uumjVJe+UGwgD+C8XS33/317FxbZw8aPA8gtGe6hfSFRdG1L1DerVpHxPN
YphhFrofEiE+LW7qyjPGkmAPycOiby62Q+ln1N5+psrPtVLSg47loDlM38klNC1W
I729jZ1R0NWZ8VCN8hpfVqO+ygtzF5ed9n22cL6oBJqtGDUjuw7bVPKP1ie0Y9md
KlN09eV2jVKAINWsmAZgGOypxB3z7MkbHbeLoLcRWMdUuNFAdorAiqvkVicwZYmu
XRH+hCAbGbu+gUIBaxf2QkgWQzsx/u1lyM4Iu3fzehVAw5Ukm3JRUM0CAwEAATAN
BgkqhkiG9w0BAQsFAAOBgQCZcWXMeAHcCoNI7n+xHgv33d9UWmWuyqaFPpKE62l8
D9ViBjjsWd4iU4VCrNWegHTh/TdzFMi7VFf7c8YqNTWdXPQywoCJSFT/r20mv2Le
I+LSaLPziCtFS1cYUldQ971PQgMP9Yce946zpFEcdY0gRXCRWGgOap2DzvcqCn1v
PA==
-----END CERTIFICATE-----
subject=/C=GB/ST=United Kingdom/L=Derby/O=Mosquitto/OU=Public server/CN=test.mosquitto.org/emailAddress=roger@atchoo.org
issuer=/C=GB/ST=United Kingdom/L=Derby/O=Mosquitto/OU=CA/CN=mosquitto.org/emailAddress=roger@atchoo.org
---
No client certificate CA names sent
---
SSL handshake has read 2251 bytes and written 421 bytes
---
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: B8A651ED93CA21F25B0D3EB76256348960C7265782282E044E7FF22377A155AB
    Session-ID-ctx: 
    Master-Key: CF7B3F253F94F59E94F92EFD6AB3C8AD0572F157B331C5A2C0A28F86237CB06AC0903B1D6B66F8055265F1806E853B96
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 61 81 68 96 8f a0 4b d9-4b 07 e0 35 f8 d8 8f 86   a.h...K.K..5....
    0010 - e1 74 58 ae 29 24 ed 0a-96 72 59 62 02 71 ec 23   .tX.)$...rYb.q.#
    0020 - de 8e 55 6f b9 24 35 2f-34 90 1a 03 0f 96 b6 52   ..Uo.$5/4......R
    0030 - 7d 14 fd e9 44 f0 98 b9-8d 92 7a 33 f5 de a9 9c   }...D.....z3....
    0040 - 09 0a e1 cd 30 f7 c6 1d-2d 95 ec 97 8d 4e 95 1f   ....0...-....N..
    0050 - f5 56 80 aa dc cd 77 73-e8 52 fb a3 71 5d ad 21   .V....ws.R..q].!
    0060 - 69 97 4b f6 93 f0 2b c2-26 ef 32 44 82 a8 fc f1   i.K...+.&.2D....
    0070 - bf af 6a 28 17 6f 4d f9-29 87 f0 3c 84 68 96 a2   ..j(.oM.)..<.h..
    0080 - c8 1c 70 76 d5 f7 28 96-f5 b6 2b 38 ea 8e 85 94   ..pv..(...+8....
    0090 - 76 c5 f0 0a fe 4f 7a d2-3f e8 ae 34 3c 03 24 e1   v....Oz.?..4<.$.
    00a0 - a9 25 77 5d b7 56 b4 3d-4b ad fe 61 a6 d9 79 e0   .%w].V.=K..a..y.

    Start Time: 1429190148
    Timeout   : 300 (sec)
    Verify return code: 0 (ok)
---
