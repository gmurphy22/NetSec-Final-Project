"""
all the settings for the chat app in one file so i don't have to hunt for
magic numbers later. no secrets in here.... the tls key and the per user salts
get made at runtime.
"""

# network
HOST = "127.0.0.1"          # localhost only
PORT = 5500

# files
CERT_FILE   = "cert.pem"    # tls certificate, public
KEY_FILE    = "key.pem"     # tls private key, keep this one secret
DB_FILE     = "users.db"    # sqlite profile database
SHADOW_FILE = "shadow.txt"  # username:salt:hash, no plaintext passwords
LOG_FILE    = "security.log"

# argon2id settings
ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536  # kib, so 64 mb
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN    = 32     # bytes
ARGON2_SALT_LEN    = 16     # bytes, one per user

# lockout
MAX_FAILED_LOGINS    = 5    # fails before the account locks
LOCKOUT_BASE_SECONDS = 5    # first lockout, doubles after that
LOCKOUT_MAX_SECONDS  = 300  # cap so nobody is locked out forever

# input limits
MIN_USERNAME_LEN = 3
MAX_USERNAME_LEN = 32
MAX_DISPLAY_LEN  = 48
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
MAX_MESSAGE_LEN  = 2000
MAX_LINE_BYTES   = 65536    # biggest single wire message we'll accept

# firewall
ALLOWED_HOSTS                 = {"127.0.0.1"}
FW_WINDOW_SECONDS             = 10
FW_MAX_CONNS_PER_WINDOW       = 30   # per ip
FW_MAX_LOGIN_FAILS_PER_WINDOW = 10   # per ip
FW_IP_BLOCK_SECONDS           = 30   # how long a bad ip sits in timeout
