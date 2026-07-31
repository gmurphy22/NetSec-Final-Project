# Secure Chat, COMP 3500 Network Security Final Project

A client/server chat app that runs on localhost. Register, log in, and send
messages over TLS.

Author: Gage Murphy

## Quick start

```bash
# install dependencies
pip install -r requirements.txt

# generate the TLS cert (optional, the server does it on first run)
python gen_cert.py

# start the server in one terminal
python server.py

# start a client in another terminal (or a few)
python client.py
```

Run the client from the same folder as the server so it can find `cert.pem` to
verify the server.

Once you're logged in, type a message and hit Enter. Commands are `/who` and
`/quit`.

## Files

 `server.py` TLS server, accept loop, message relay, ties everything together 
 `client.py` Terminal client 
 `auth.py` Argon2id shadow file passwords, lockout, session tokens 
 `database.py` SQLite profile store 
 `firewall.py` Connection firewall, adapted from my VPN project
 `validation.py` Input checks 
 `security_log.py`  Security log 
 `wire.py`  JSON line protocol 
 `gen_cert.py`  Self signed cert generator 
 `config.py`  All the settings 

`cert.pem`, `key.pem`, `users.db`, `shadow.txt` and `security.log` are all
generated when you run it, and they're in the .gitignore.

## Security controls

Authentication: Argon2id with a per-user salt (password cracking, rainbow tables), plus account lockout with backoff (brute-force logins)
Transport:  TLS 1.2+ (sniffing, MITM)
Session: random 256-bit session tokens (session hijacking)
Application: input validation and parameterised SQL (injection, malformed input)
Network: connection firewall (connection and login flooding)
Logging: security log (catching intrusion attempts)


### Password storage

Nothing is stored in plaintext. Every user gets their own random 16 byte salt,
the password goes through Argon2id, and the result goes in the shadow file as:

```
username:salt_hex:password_hash_hex
```

Logging in re-hashes what you typed with your stored salt and compares in
constant time. Argon2id over bcrypt and PBKDF2 because it's memory
hard, so it's a lot more expensive to crack on a GPU.

### The firewall

`firewall.py` came out of my VPN project from another class. In that one it used
`iptables` for NAT and DNS leak prevention, which needs root and doesn't make
sense for a localhost app. Same idea though, only let approved connections in
and throttle anyone being abusive, just done at the application layer with a
localhost allowlist plus per IP connection and login rate limits.

## References

- [`argon2-cffi`](https://argon2-cffi.readthedocs.io/) for the Argon2id hashing
- [`cryptography`](https://cryptography.io/) for the cert generation
- Standard library: `ssl`, `socket`, `sqlite3`, `secrets`, `hmac`, `threading`
