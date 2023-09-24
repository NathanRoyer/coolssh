Pure-rust SSH 2.0 Client

### Example: Initiating a fetch from github

```rust
use std::net::TcpStream;
use coolssh::{create_ed25519_keypair, dump_ed25519_pk_openssh, Connection};

let hex_keypair: String = create_ed25519_keypair();
println!("Key Pair (private): {}", hex_keypair);

let github_account_id = "john.doe@gmail.com";
let openssh_encoded_pubkey = dump_ed25519_pk_openssh(&hex_keypair, github_account_id);
println!("OpenSSH-Encoded Public Key {}", openssh_encoded_pubkey);
// Add the public key to `authorized_keys` on your server
// -> https://github.com/settings/keys

let stream = TcpStream::connect("github.com:22").unwrap();
let mut conn = Connection::new(stream, ("git", hex_keypair.as_str()).into()).unwrap();

// set appropriate read timeout (preferably after authentication):
conn.mutate_stream(|stream| {
    let timeout = std::time::Duration::from_millis(200);
    stream.set_read_timeout(Some(timeout)).unwrap()
});

let env = [];
let run = conn.run("git-upload-pack rust-lang/rust.git", &env).unwrap();
```

### Supported SSH Algorithms

- Key Exchange: curve25519-sha256
- Public Keys: ssh-ed25519
- Encryption: aes256-ctr
- MAC: hmac-sha2-256
- Compression: none

### Future improvements

- no_std compatibility
- allow multiple commands to run simultaneously (API change)
- server mode

Feel free to submit pull request for these.
