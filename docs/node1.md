⚡ Node1 QUIC Integration Guide

Minimum tip: 0.001 SOL
Node1 applies a tip-amount-based prioritization policy. Requests are ranked by the tip amount provided. Higher tip amount leads to higher priority and faster landing speed.

ndpoints and Configuration
Nodes and Tip Address
Nodes
New York
https://ny.node1.me, http://ny.node1.me
Amsterdam
https://ams.node1.me, http://ams.node1.me
Frankurt
https://fra.node1.me, http://fra.node1.me
London
https://lon.node1.me, http://lon.node1.me
Tokyo
https://tk.node1.me, http://tk.node1.me
Singapore
https://sgp.node1.me, http://sgp.node1.me
Recommended to use long connection Keep Alive
Tip Address
To ensure your transaction is processed, include a tip of at least 0.001 SOL to one of our tip wallets (6 available addresses are listed below). You may randomly select an address from the list for your transfer, which helps distribute the load and improves system efficiency.

•
node1PqAa3BWWzUnTHVbw8NJHC874zn9ngAkXjgWEej
•
node1UzzTxAAeBTpfZkQPJXBAqixsbdth11ba1NXLBG
•
node1Qm1bV4fwYnCurP8otJ9s5yrkPq7SPZ5uhj3Tsv
•
node1PUber6SFmSQgvf2ECmXsHP5o3boRSGhvJyPMX1
•
node1AyMbeqiVN6eoQzEAwCA6Pk826hrdqdAHR7cdJ3
•
node1YtWCoTwwVYTFLfS19zquRQzYX332hs1HEuRBjC
The higher the tip you give, the higher the success rate of going on chain


This document is for clients integrating with the node1 QUIC service. It covers available endpoints, authentication flow, request format, response format, and a Rust example.

Endpoints
Available regional endpoints:

ny.node1.me:16666
fra.node1.me:16666
ams.node1.me:16666
lon.node1.me:16666
tk.node1.me:16666
sgp.node1.me:16666
Recommendations:

Use the region closest to your workload
Set server_name to the same hostname as the endpoint you connect to
Example:

Address: ny.node1.me:16666
server_name: ny.node1.me
Protocol Overview
A QUIC connection has two stages:

Authentication
Transaction submission
Protocol rules:

The first bidirectional stream is used for authentication
Each transaction uses a new bidirectional stream
After authentication succeeds, clients should always reuse the same authenticated connection for subsequent transactions
The request body has no length prefix
One transaction stream carries exactly one transaction
The client must call finish() after writing the request
Authentication Flow
After establishing a QUIC connection:

Open the first stream with open_bi()
Send the raw 16-byte UUID for the API key
Call finish()
Read the server reply
The authentication payload is not the UUID string. It is the 16-byte binary UUID value.

Authentication also has a timeout:

The client should complete authentication promptly after establishing the connection
If the client does not start auth within 5 seconds, or does not finish sending the 16-byte UUID within 5 seconds, the server closes the connection immediately
Example:

let api_key_uuid = Uuid::parse_str(api_key)?;
send.write_all(&api_key_uuid.into_bytes()).await?;
send.finish()?;
On success, the server replies with one byte:

0: authentication passed
On failure, the server may:

reply with 1
or close the connection with a QUIC application error code
Transaction Submission Flow
After authentication succeeds, each transaction is sent as follows:

Open a new stream with open_bi()
Write the raw transaction bytes
Call finish()
Read the response frame
Request body notes:

The payload is the raw transaction bytes
The current server parses it as a serialized Solana VersionedTransaction
Clients only need to send the result of bincode::serialize(&versioned_tx)
Example:

let tx_bytes = bincode::serialize(&versioned_tx)?;
send.write_all(&tx_bytes).await?;
send.finish()?;
Important:

Do not prepend a data len
The server uses stream EOF as the end-of-request marker
If the client still has not called finish() after 5 seconds, the server discards that request, returns 408 Request Timeout, and keeps the connection open
Response Format
The server returns a binary response frame with the following format.

Header
status: 2 bytes, unsigned integer, big-endian
msg_len: 4 bytes, unsigned integer, big-endian
Body
msg: UTF-8 bytes, length = msg_len
Full layout:

+---------+---------+------------------+
| status  | msg_len | msg              |
| 2 bytes | 4 bytes | msg_len bytes    |
+---------+---------+------------------+
Notes:

There is no extra body field in the current response format
Clients should read the 6-byte header first, then read msg_len bytes for the message
Response Handling
On successful transaction submission:

status = 200
msg is a JSON string
Example msg format:

{"jsonrpc":"2.0","id":1,"result":"<transaction_signature>"}
Client-side recommendation:

inspect status first
when status = 200, parse msg as the success payload
On failed transaction submission:

status != 200
msg contains the corresponding error message
For the complete error code list and error meanings, refer to the error code reference page on the website.

Long-Lived Connection Guidance
After authentication succeeds, clients should keep reusing the same QUIC connection for subsequent transactions. Do not reconnect and re-authenticate for every transaction.

Recommended:

keep one authenticated long-lived connection
use a new bidirectional stream for each transaction
set client-side timeouts for connect, auth, and each transaction send
configure keep_alive_interval
configure a reasonable max_idle_timeout
Not recommended:

reconnect for every transaction
re-authenticate for every transaction
Why:

QUIC and TLS handshakes both add extra cost
frequent reconnects increase latency jitter
this mode is clearly worse under higher concurrency or higher request frequency
Recommended pattern:

establish the connection when the client starts
complete authentication once
use open_bi() repeatedly on the same connection for all subsequent transactions
reconnect and re-authenticate only after the connection is confirmed to be closed
Example keepalive settings:

keep_alive_interval = 15s
max_idle_timeout = 60s
If your deployment path goes through NAT, a load balancer, or edge network devices, keepalive is recommended so idle connections are less likely to be reclaimed.

Client Timeout Guidance
Clients should not wait forever for connection establishment.

Why:

the server may be down
the upstream LB, firewall, or network path may be blackholed
without client-side timeouts, the client may hang indefinitely without a result and without failing promptly
It is recommended to add timeouts for these three phases:

connection establishment connect
initial authentication auth
single transaction send send_transaction
Idle Connections and Resource Reclamation
If the client neither actively closes the connection nor sends any business traffic or keepalive traffic, the connection is automatically closed by QUIC once max_idle_timeout is exceeded.

Important:

max_idle_timeout is a connection-level timeout, not a stream-level timeout
if the client is still sending keepalives, the connection is not considered idle
non-idle connections continue to be kept alive
How To Detect That the Connection Is Closed
Clients are encouraged to use both of the following:

proactively check connection.close_reason()
handle connection errors returned by open_bi() / send / recv during actual transaction submission
Example:

if let Some(reason) = connection.close_reason() {
    eprintln!("connection closed: {:?}", reason);
    // reconnect + authenticate again
}
And:

let (mut send, mut recv) = match connection.open_bi().await {
    Ok(stream) => stream,
    Err(err) => {
        eprintln!("connection unusable: {:?}", err);
        // reconnect + authenticate again
        return Err(err.into());
    }
};
Common cases that require reconnecting include:

ConnectionError::TimedOut
ConnectionError::LocallyClosed
ConnectionError::ApplicationClosed
any ConnectionLost(...)
Rust Example
This example shows the full flow:

connect to a regional endpoint
send the 16-byte UUID for authentication
keep reusing the same authenticated connection
encode a VersionedTransaction with bincode
send the transaction
parse the status + msg response
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint, TransportConfig};
use quinn::crypto::rustls::QuicClientConfig;
use solana_sdk::transaction::VersionedTransaction;
use solana_tls_utils::SkipServerVerification;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use uuid::Uuid;

async fn connect_quic(server_addr: &str, server_name: &str) -> Result<(Endpoint, Connection)> {
    let socket_addr = server_addr
        .to_socket_addrs()
        .context("resolve server addr failed")?
        .next()
        .context("server addr resolved to no socket address")?;

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    let client_crypto = QuicClientConfig::try_from(crypto)
        .context("build quic tls config failed")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    let mut transport = TransportConfig::default();
    let idle_timeout = quinn::IdleTimeout::try_from(Duration::from_secs(60)).unwrap();
    transport.max_idle_timeout(Some(idle_timeout));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
        .context("create quic endpoint failed")?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(socket_addr, server_name)
        .context("start quic handshake failed")?
        .await
        .context("finish quic handshake failed")?;

    Ok((endpoint, connection))
}

async fn authenticate(connection: &Connection, api_key: &str) -> Result<()> {
    let api_key_uuid = Uuid::parse_str(api_key).context("invalid api key uuid")?;

    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&api_key_uuid.into_bytes()).await?;
    send.finish()?;

    let auth_reply = recv.read_to_end(8).await?;
    match auth_reply.first().copied() {
        Some(0) => Ok(()),
        Some(code) => anyhow::bail!("auth rejected, reply={code}"),
        None => anyhow::bail!("auth failed, empty reply"),
    }
}

async fn read_response(recv: &mut quinn::RecvStream) -> Result<(u16, String)> {
    let mut header = [0u8; 6];
    recv.read_exact(&mut header).await?;

    let status = u16::from_be_bytes(header[0..2].try_into().unwrap());
    let msg_len = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;

    let mut msg = vec![0u8; msg_len];
    if msg_len > 0 {
        recv.read_exact(&mut msg).await?;
    }

    Ok((status, String::from_utf8_lossy(&msg).into_owned()))
}

async fn send_transaction(connection: &Connection, tx_bytes: &[u8]) -> Result<(u16, String)> {
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(tx_bytes).await?;
    send.finish()?;
    read_response(&mut recv).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let server_addr = "ny.node1.me:16666";
    let server_name = "ny.node1.me";
    let api_key = std::env::var("NODE1_API_KEY_UUID")
        .context("set NODE1_API_KEY_UUID")?;

    let (endpoint, connection) = timeout(
        Duration::from_secs(5),
        connect_quic(server_addr, server_name),
    )
    .await
    .context("connect timeout")??;

    timeout(Duration::from_secs(5), authenticate(&connection, &api_key))
        .await
        .context("auth timeout")??;

    // After authentication succeeds, keep reusing this connection for subsequent transactions.
    // Do not reconnect and re-authenticate for every transaction.
    // For each new transaction, just call send_transaction(&connection, &tx_bytes) again.

    let versioned_tx: VersionedTransaction = /* your signed transaction */;
    let tx_bytes = bincode::serialize(&versioned_tx)
        .context("serialize tx failed")?;

    let (status, msg) = timeout(
        Duration::from_secs(5),
        send_transaction(&connection, &tx_bytes),
    )
    .await
    .context("send timeout")??;
    println!("status: {}", status);
    println!("msg: {}", msg);

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}