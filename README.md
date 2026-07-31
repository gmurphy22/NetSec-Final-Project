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
 `shadow.txt`' Encrypted passwords

`cert.pem`, `key.pem`, `users.db`, and `security.log` are all
generated when you run it, and they're in the .gitignore.


## References

- [`argon2-cffi`](https://argon2-cffi.readthedocs.io/) for the Argon2id hashing
- [`cryptography`](https://cryptography.io/) for the cert generation
- Standard library: `ssl`, `socket`, `sqlite3`, `secrets`, `hmac`, `threading`
