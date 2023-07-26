Pure-rust SSH 2.0 Client

### Example: Initiating a fetch from github

```rust
use std::net::TcpStream;
use coolssh::{create_ed25519_keypair, Connection};

let github_account_id = "john.doe@gmail.com";
let (openssh_encoded_pubkey, keypair) = create_ed25519_keypair(github_account_id);

println!("{}", openssh_encoded_pubkey);
// Add this public key to `authorized_keys` on your server
// -> https://github.com/settings/keys

let stream = TcpStream::connect("github.com:22").unwrap();
let mut conn = Connection::new(stream, ("git", &keypair).into()).unwrap();

// set appropriate read timeout (preferably after authentication):
conn.mutate_stream(|stream| {
    let timeout = std::time::Duration::from_millis(200);
    stream.set_read_timeout(Some(timeout)).unwrap()
});

let run = conn.run("git-upload-pack rust-lang/rust.git").unwrap();
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
