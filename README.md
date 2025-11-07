# Yamabiko

[![NuGet package](https://img.shields.io/nuget/v/Kanawanagasaki.Yamabiko.svg)](https://www.nuget.org/packages/Kanawanagasaki.Yamabiko)

Yamabiko is a .NET rendezvous server and client library for Peer-to-Peer (P2P) communication. It provides built‑in encryption, peer discovery/advertising, and reliable transport using the KCP protocol over UDP.

## Server

### Download

Grab the correct platform executable from the [Releases page](https://github.com/Kanawanagasaki/Kanawanagasaki.Yamabiko/releases)

### Command line arguments

The server supports the following options:

- `Domain` - domain name used for certificates (default: `example.com`)
- `Port` - UDP port to listen on (default: `9999`)
- `MTU` - Maximum Transmission Unit for UDP datagrams (default: `1400`)
- `CertificatePath` - path to the server certificate
- `PrivKeyPath` - path to the certificate private key
- `MaxClients` - maximum number of concurrent clients (default: `1024`)
- `MaxClientsPerRemoteNetwork` - maximum number of concurrent clients from a single remote network (default: `8`)
- `MaxInactivitySeconds` - seconds of inactivity before the server treats a client as disconnected (default: `90`)

### Example (Linux)

```
Yamabiko-Server-1.0.0-linux-x64 \
	-Domain=example.com \
	-Port=9999 \
	-MTU=1400 \
	-CertificatePath=/path/to/cert.pem \
	-PrivKeyPath=/path/to/privkey.pem \
	-MaxClients=1024 \
	-MaxClientsPerRemoteNetwork=8 \
	-MaxInactivitySeconds=90
```

## Client

Each project must generate a persistent Project ID that uniquely identifies it. This ID will be used by the server to differentiate connected clients belonging to different projects. For example, all chat clients will share the same static Project ID, which will be distinct from Tic-Tac-Toe clients Project ID.

### YamabikoClient

`YamabikoClient` is responsible for communication with the rendezvous server, advertising the local peer, listening for other peers, and initiating P2P connections.

```csharp
var client = new YamabikoClient(serverEndpoint, projectId)
{
    ValidateCertificatesCallback = (X509Certificate2[] certificates) => true, // You can provide custom callback function to verify certificates
    CertificateDomain = "example.com", // or you can use built-in function that will check certificates against a domain
    PingInterval = TimeSpan.FromSeconds(3), // heartbeat frequency
    ResendInterval = TimeSpan.FromSeconds(1), // retransmission interval for lost packets
    Timeout = TimeSpan.FromSeconds(90) // seconds of inactivity before the server treated as disconnected
};

await client.StartAsync();
```

### Subscribe

Listen for new peer advertisements:

```csharp
client.OnPeerAdvertisement += (PeerPacket peerPacket) => { };
client.OnPeerExtraAdvertisement += (PeerExtraPacket peerExtraPacket) => { };
await client.SubscribeAsync();

// to stop listening:
await client.UnsubscribeAsync();
```

### Advertise

When advertising a peer you can include:
- `Name` - UTF‑8 string, used for human identification. Max length: 253 characters.
- `Password` - UTF‑8 string used to protect IP/port information on the server. Connecting clients must present the same password to retrieve the peer's address. Max length: 253 characters.
- `Flags` - 64‑bit filterable flags.
- `Tags` - up to 256 key->byte[] entries (255 max byte array size). Tags are transmitted to the server as raw byte arrays. Used for filtering and associating data with peers.

```csharp
var advertisement = new Advertisement
{
    Name = "Peer 1",
    Flags = 0b000000001,
    Password = password,
    Tags =
    [
        new ByteArrayTag(1, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }),
        new StringTag(2, "foo"),
        new ByteTag(3, 42),
        new ShortTag(4, 10000),
        new IntTag(5, 48879),
        new LongTag(6, 6148914691236517205),
        new FloatTag(7, 9.876f),
        new DoubleTag(8, 0.123),
    ]
};
await client.AdvertiseAsync(advertisement);

// stop advertising
await client.StopAdvertisingAsync();
```

### Query

You can query the server for peers using filters:
- `Flags` - server applies `(peer.Flags & query.Flags) == query.Flags` to filter out peers (default: `0`)
- ProtectionLevel - filter peers that require a password, don't require one, or any (default: `ANY`)
- Tag - operate on the raw bytes of tags. Supported operations: `LESS`, `LESS_OR_EQUALS`, `EQUALS`, `GREATER_OR_EQUALS`, `GREATER`, `CONTAINS`

> When tags are reaches the server, they are represented as raw byte arrays, with no knowledge of their underlying data types. Types are converted as follows:
> - `string` -> UTF‑8 bytes
> - `byte` -> single-byte array
> - `short`, `int`, `long` -> big‑endian integer bytes
> - `float`, `double` -> sortable byte representations
> - `byte[]` -> transmitted as is

Sorting options: `NAME_ASC`, `NAME_DESC`, `TIME_ASC`, `TIME_DESC`, `RANDOM` (default: `NAME_ASC`)

Pagination: use `Skip` and `Count`.

```csharp
var query = new Query
{
    Flags = 0,
    ProtectionLevel = EProtectionLevel.ANY,
    FilterTag = new StringTag(2, "bar"),
    FilterOperation = EFilterOperation.CONTAINS,
    OrderBy = EOrderBy.RANDOM,
    Skip = 0,
    Count = 24
};
var queryRes = await client.QueryAsync(query);
```

### Connect

Once you obtain `PeerInfo` from a query, connect with:

```csharp
var peer2 = await client.ConnectAsync(peerInfo);
// or if the peer requires a password:
var peer2 = await client.ConnectAsync(peerInfo, "password");
// or with extra data (mind the UDP MTU):
var peer2 = await client.ConnectAsync(peerInfo, extra: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
```

If the remote peer rejects the connection (for example bad password), the server will return a `ConnectDeny` packet and `ConnectAsync` will throw a `ConnectionDeniedException`.

To accept an incoming connection on the remote side:

```csharp
var acceptedPeer = await client.AcceptPeerAsync();
```

You can provide an approval callback to perform custom validation on incoming connect requests:

```csharp
var acceptedPeer = await client.AcceptPeerAsync((PeerConnectPacket peerConnect, CancellationToken ct) =>
{
    if (peerConnect.Extra is null)
        return Task.FromResult(PeerConnectResult.Deny("Peer must provide extra bytes"));
    if (peerConnect.Extra.Length != 4)
        return Task.FromResult(PeerConnectResult.Deny("Peer must provide 4 extra bytes"));
    if (peerConnect.Extra[0] != 0xDE && peerConnect.Extra[1] != 0xAD && peerConnect.Extra[2] != 0xBE && peerConnect.Extra[3] != 0xEF)
        return Task.FromResult(PeerConnectResult.Deny("Extra is not deadbeef"));
    if(peerConnect.Ip.ToString() != "192.168.0.100")
        return Task.FromResult(PeerConnectResult.Deny("Unexpected ip address"));
    if (peerConnect.Port != 55555)
        return Task.FromResult(PeerConnectResult.Deny("Unexpected port"));

    return Task.FromResult(PeerConnectResult.Accept());
});
```

After `ConnectAsync` and `AcceptPeerAsync` complete, peers have exchanged addresses but are not necessarily directly connected yet, they need to perform a hole punching.

```csharp
// Check the connection state:
if (peer.ConnectionState is EPeerConnectionState.CONNECTED)
{
    // peers are directly connected
}

// or wait until connected:
await peer.WaitUntilConnectedAsync(TimeSpan.FromSeconds(90));
```

### Communication

Once peers are connected there are three communication modes

#### Unreliable (fire-and-forget)

```csharp
await peer.SendUnreliableAsync(buffer);
var receivedBuffer = await peer.ReceiveUnreliableAsync();
```

#### Reliable

Yamabiko uses the [KCP protocol](https://github.com/Kanawanagasaki/Kanawanagasaki.KCP) for reliable, ordered delivery

```csharp
peer.SendReliable(buffer);
var receivedBuffer = await peer.ReceiveReliableAsync();
```

#### Stream

```csharp
var stream = peer.GetStream();
await stream.WriteAsync(buffer);
await stream.ReadAsync(buffer);
```

## Connection Diagram

![Connection Diagram](https://raw.githubusercontent.com/Kanawanagasaki/Kanawanagasaki.Yamabiko/refs/heads/master/images/ConnectionDiagram.png)
