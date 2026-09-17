// test/vectors/destsim-throwaway-tls-cert.ts -- a THROWAWAY, TEST-ONLY, self-signed TLS certificate +
// private key pair, used SOLELY to stand up the local node:tls syslog-TLS emulator
// (test/destsim/server.ts's startSyslogEmulator) on 127.0.0.1 so the sender's real socket contract
// (src/notify/siem-syslog-sender.ts) can be exercised over an actual TLS handshake rather than a fully
// in-memory mock.
//
// NOT a downpipe/1.0 archive-format conformance vector like this directory's other entries -- it lives
// here (rather than alongside its consumer in test/destsim/) because the repo's local pre-commit hook
// refuses any staged file containing a PEM "BEGIN ... PRIVATE KEY" block UNLESS the path is under
// test/vectors/ (see .git/hooks/pre-commit and this repo's .gitleaks.toml, which documents the SAME
// test/vectors/ exemption for "intentionally-committed fake keys"). This file is exactly that: a fake,
// throwaway key, deliberately committed, never used for anything beyond a loopback test TLS listener.
//
// THIS IS NOT A PRODUCTION SECRET. It signs nothing real, protects nothing real, and is committed to the
// repository in plain text on purpose: it exists only so a validator can bind a loopback TLS listener
// without shelling out to openssl at test time (and without depending on openssl being on PATH in every
// CI/dev environment). The matching client connection (test/destsim/server.ts's makeRealSyslogConnect)
// connects with rejectUnauthorized:false, since a self-signed cert is never in any real trust store and
// this suite is proving WIRE FORMAT / framing correctness, not certificate-chain trust (the real
// cloudflare:sockets connect() in production handles actual TLS trust; that is out of scope for this
// destination emulator).
//
// Regenerate (if ever needed) with, e.g.:
//   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 7300 -nodes \
//     -subj "/CN=localhost/O=downpipes-destsim-throwaway-test-cert" \
//     -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
// Valid for 20 years from generation purely so this file never needs churn; it carries no
// authority beyond a local loopback test listener, so a long validity window costs nothing.

export const THROWAWAY_TLS_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDhTCCAm2gAwIBAgIUKWN5rmPzpD/ruuaDYhp2FxbV98IwDQYJKoZIhvcNAQEL
BQAwRDESMBAGA1UEAwwJbG9jYWxob3N0MS4wLAYDVQQKDCVkb3ducGlwZXMtZGVz
dHNpbS10aHJvd2F3YXktdGVzdC1jZXJ0MB4XDTI2MDcwNzEwNTMwNloXDTQ2MDcw
MjEwNTMwNlowRDESMBAGA1UEAwwJbG9jYWxob3N0MS4wLAYDVQQKDCVkb3ducGlw
ZXMtZGVzdHNpbS10aHJvd2F3YXktdGVzdC1jZXJ0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAjrCfuEkoaWTJUB2EH7hNM49prLpcn2WMByvk34Hchb9J
2XFNBOHynkXhkNDyz827L5zrCYy+XaAPBBllTOqaDbozFNN1FXE9Amqv86qGNqJm
sH5AaURZF1tbQoHCEsW1CJSGtofLJL2t5gDwDQO4KC0zk84ABY5AdiXvq1kn8y3X
H41Mc9tgEn8cmu3SGyDOh2go1u/UDO/Ys/W10nPZZ/HxujrqOgzrx35DuayyVxAk
Pi+zfENZYRkI9K0E6ZMrfmm2DohY1uxd2YsAsu9oEm5j/InUjl7NiatuT9VBncX0
8k23CEcuOLuOq7w+/v7nUJF+vqm7jkGEAkfnomRriwIDAQABo28wbTAdBgNVHQ4E
FgQUo+kbu57OUox2zrTg0nPznRrGdeMwHwYDVR0jBBgwFoAUo+kbu57OUox2zrTg
0nPznRrGdeMwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAHYk1S3USwoVkiWYf5wAyeIBNvQFx+mD
RoG3zy4lvEbxmoW6VNBYNXk2k4gRQMVtOYZF7N6SuBQEbBrWJU/dysBZPdwO/Qp5
3pqbUx6Lmt3mVKvwu3opSNWWjW2H8BsXhuevoSrFfDny8wN5PnLOGKMdapM1UoiU
V6linVJlI2G9amhuBKCNQo/OZ03ww76EPh4awE9ppab1PeZ3lVz4dI6CpH9KPlvn
60tYBWh/qHrrM9dtpOuVvyvXNiuD88vcEe20bP4tBJIEf2WTGvyoUltwIkBAazNK
3MhSNgCe6P9HnOsr9mhc3JBU1TcAyXojjrvJjvT6Qm10hBDLeJSoLy8=
-----END CERTIFICATE-----
`;

export const THROWAWAY_TLS_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCOsJ+4SShpZMlQ
HYQfuE0zj2msulyfZYwHK+TfgdyFv0nZcU0E4fKeReGQ0PLPzbsvnOsJjL5doA8E
GWVM6poNujMU03UVcT0Caq/zqoY2omawfkBpRFkXW1tCgcISxbUIlIa2h8skva3m
APANA7goLTOTzgAFjkB2Je+rWSfzLdcfjUxz22ASfxya7dIbIM6HaCjW79QM79iz
9bXSc9ln8fG6Ouo6DOvHfkO5rLJXECQ+L7N8Q1lhGQj0rQTpkyt+abYOiFjW7F3Z
iwCy72gSbmP8idSOXs2Jq25P1UGdxfTyTbcIRy44u46rvD7+/udQkX6+qbuOQYQC
R+eiZGuLAgMBAAECggEADWhPObO2FmEgAWUkmw5oQqYBGffQ6DFUfQAE23OKUw7s
U4Av6nuInpKWZVMc3aXJJuops5YD9Swq/Qmd2SJaI1wRnK1Z3Q/s2aNIsS6eudd8
qqzSRJHlhSpSYudqYvUs04eROOl9jxA7nNcNt0tYLH5C0GqU2fDJ4dAiuwj/lfve
whtyNL0ExfmUB2w81cV3gyFAG1GYpJjpXShp+jhanJAMH+AUbgv50w4ClsDIB/XT
p6dZKVS9weRk3xHm6V1tM1Z1UaVKn+2nTOibfTGW8N7j5w+h/6Mfycn7u/MrOwBD
xbI5VastvlvmlFZz+yxcVy+3iyYBegev3VzkIgiXcQKBgQDEvhQOBvYqN2vrdv7W
FnJbWB4nv36l9C7+SKueXs1x5mqtvJiiPtIYB1TNyY26xPhF1Z/c8M/6Id8VJghx
TB8sbaK+sRaniIlLy2sD/uuFmbo/IU69MrYooduuw1SSBjsOUqK0z2lhTwmYAEEZ
5yRpRQ3YIsKTTYT4DgBMY9igjQKBgQC5qsxKo81zlyG98clkh57ZQraJ7Dg6ZNk3
SbViFq5vSIwke4FX8JIM6Sik4e32dX9mHvAVtLGvSceDwGSjxoMa4w/wdbJeB0mT
0cQuBAmy+ips8bLwz0PlzYwsDeuPUzgj/EpaRqWenvavPUXA1lJn8pGWsUon1e5v
+Wc42L9ydwKBgHDZ9vb0107v619tKk/zIDV1Hhb+qM7YefwyAv8csgubd6WggIzQ
LALMccB41GtFgIPOPZymJSX9N9ERt9YFK/x4BtoLCkue7eIkFIZ+Ouqvez2rBVdR
N1unPDPKpz/7gvR8Qggk0PWYOJCP1Mfe5evcSEyp46JK3PLMVS98Nk4hAoGASVL0
nz2Vc+LpxnPojzUoPLEmGc4aXqVZS4ZmhbhjZzuFbRsBd9NgOo0SKhu3uK+qgpAR
TOExkwJWMugWVr+dI08tCk/RA2VpX2FmUq3xjqdRffjuLEAOloDYrMVKlC3PbBbE
3mYsHjq1PXu7Qm7h2H9pk9Osb5MDOWGLrF2dLf0CgYAHpMarrwL3zTABqoBrsls9
54tAEHSMcBJoaq5TKAbj9QRg2dJxsi6zhu/A1IfH7wbX++GGnJR4a1+zBs0H/YRs
JHs4MSbB/TbBaIVVUiTuC0ownvZoTbIgpdxQEjbjVRcl3Jl2SR2VG43ViwcxMAFU
57QcpNl7zh1rpcq0RD92vw==
-----END PRIVATE KEY-----
`;
