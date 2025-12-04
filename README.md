# Multi-Party Diffie-Hellman (mp-dh)
`mp-dh` is a Go application that demonstrates a 2-party Diffie-Hellman key exchange protocol involving a Sender, a Recipient, and a Cloud provider. It uses the NIST P-256 elliptic curve.
## Protocol Overview
The protocol splits the recipient's private key between the recipient (Alice) and the cloud (Chuck).
1.  **Key Generation**: Alice and Chuck generate random scalars $a_1$ and $a_2$. The effective public key is $P = (a_1 + a_2)G$.
2.  **Encryption (Sender)**: The sender uses the public key $P$ to perform a standard ECDH, generating an ephemeral key pair $(b, bG)$ and a shared secret $S = bP$.
3.  **Decryption (Recipient)**: The recipient receives $bG$. To recover $S$, they compute $a_1(bG)$ and obtain $a_2(bG)$ from the cloud. The sum is $(a_1 + a_2)bG = b(a_1+a_2)G = bP = S$.
## Usage
Build the application:
```bash
go build -o mp-dh mp-dh.go
```
### 1. Generate Keys
Generates the split private shares and the combined public key.
```bash
./mp-dh generate <pubkey_file> <chuck_share_file> <alice_share_file>
```
Example:
```bash
./mp-dh generate pk.pem chuck.key alice.key
```
### 2. Send (Sender)
Simulates a sender performing the Diffie-Hellman exchange.
```bash
./mp-dh send <pubkey_input_file> <ephemeral_pubkey_output_file>
```
Example:
```bash
./mp-dh send pk.pem ephemeral.pem
```
This outputs the sender's computed shared secret to stdout.
### 3. Recover (Recipient)
Simulates the recipient recovering the shared secret using their share and the cloud's share.
```bash
./mp-dh recover <ephemeral_pubkey_input_file> <chuck_share_file> <alice_share_file> <output_secret_file>
```
Example:
```bash
./mp-dh recover ephemeral.pem chuck.key alice.key secret.bin
```
## Helper Scripts
For convenience, the following shell scripts are provided to automate the flow:
*   `./keygen.sh`: Runs the `generate` command.
*   `./send.sh`: Runs the `send` command and logs the secret.
*   `./recover.sh`: Runs the `recover` command.
*   `./verify.sh`: Compares the sender's secret with the recovered secret to verify correctness.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
