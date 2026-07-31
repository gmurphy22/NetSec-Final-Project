# Secure Chat, COMP 3500 Network Security Final Project

A client/server chat app that runs on localhost. Register, log in, and send
messages over TLS.

Author: Gage Murphy

## Tutorial

```bash
# install dependencies
pip install -r requirements.txt

# generate the TLS cert (server does it on first run)
python gen_cert.py

# start the server in one terminal
python server.py

# in another terminal (same folder)
python client.py
```


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

