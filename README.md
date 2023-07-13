SSH 2.0 Client

### Supported SSH Algorithms

- Key Exchange: curve25519-sha256
- Public Keys: ssh-ed25519
- Encryption: aes256-ctr
- MAC: hmac-sha2-256
- Compression: none

### Example: Initiating a fetch from github

```rust
let github_account_id = "john.doe@gmail.com";
let (openssh_encoded_pubkey, keypair) = create_ed25519_keypair(github_account_id);

println!("{}", openssh_encoded_pubkey);
// Add this public key to `authorized_keys` on your server
// -> https://github.com/settings/keys

let stream = TcpStream::connect("github.com:22").unwrap();
let mut conn = Connection::new(stream, ("git", &keypair).into()).unwrap();

// set appropriate timeout (preferably after authentication):
conn.mutate_stream(|stream| {
    let duration = std::time::Duration::from_millis(200);
    stream.set_read_timeout(Some(duration)).unwrap()
});

let run = conn.run("git-upload-pack rust-lang/rust.git").unwrap();
```

### Note

With few modifications, you can implement a server from this code.