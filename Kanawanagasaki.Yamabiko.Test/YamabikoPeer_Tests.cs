namespace Kanawanagasaki.Yamabiko.Test;

using Kanawanagasaki.Yamabiko.Server;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Channels;
using Xunit.Abstractions;

public class YamabikoPeer_Tests : IAsyncLifetime, IDisposable
{
    private readonly ITestOutputHelper _output;

    private readonly Dictionary<IPEndPoint, ClientTransport> _clients;

    private readonly Settings _settings;
    private readonly ProjectsService _projectsService;
    private readonly ServerTransport _serverTransport;
    private readonly ClientsService _clientsService;
    private readonly ReceiverService _receiveService;

    private readonly CancellationTokenSource _cts;
    private readonly Task _clientsClearTask;
    private readonly Task _receiveServiceTask;

    public YamabikoPeer_Tests(ITestOutputHelper output)
    {
        _output = output;

        _clients = [];

        _settings = new Settings();
        _projectsService = new ProjectsService();
        _serverTransport = new ServerTransport(_clients);
        _clientsService = new ClientsService(_settings, _serverTransport, _projectsService);
        _receiveService = new ReceiverService(_clientsService, _serverTransport);

        _cts = new CancellationTokenSource();
        _clientsClearTask = _clientsService.RunClearTimerAsync(_cts.Token);
        _receiveServiceTask = _receiveService.RunAsync(_cts.Token);
    }

    public Task InitializeAsync()
        => Task.CompletedTask;

    [Theory]
    [InlineData(1.0)]
    [InlineData(0.9)]
    [InlineData(0.8)]
    [InlineData(0.7)]
    [InlineData(0.6)]
    public async Task SuccessfulConnection(double successChance)
    {
        var projectId = Guid.NewGuid();

        var client1transport = new ClientTransport(_serverTransport, _clients, successChance);
        _clients[client1transport.Endpoint] = client1transport;
        await using var client1 = new YamabikoClient(ServerTransport.Endpoint, projectId, client1transport)
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client1.StartAsync();

        var client2transport = new ClientTransport(_serverTransport, _clients, successChance);
        _clients[client2transport.Endpoint] = client2transport;
        var client2 = new YamabikoClient(ServerTransport.Endpoint, projectId, client2transport)
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client2.StartAsync();

        var ad = new Advertisement { Name = "Peer1" };
        await client1.AdvertiseAsync(ad);

        var query = new Query()
        {
            Skip = 0,
            Count = 1
        };
        var queryRes = await client2.QueryAsync(query);

        var peerInfo = Assert.Single(queryRes.Peers.Values);

        var connectTask = client2.ConnectAsync(peerInfo);
        var acceptTask = client1.AcceptPeerAsync();

        using var peer1 = await connectTask;
        using var peer2 = await acceptTask;
        Assert.NotNull(peer2);

        await Task.WhenAll(peer1.WaitUntilConnectedAsync(TimeSpan.FromSeconds(90)), peer2.WaitUntilConnectedAsync(TimeSpan.FromSeconds(90)));

        Assert.Equal(EConnectionState.CONNECTED, peer1.ConnectionState);
        Assert.Equal(EConnectionState.CONNECTED, peer2.ConnectionState);

        await peer1.DisconnectAsync();
        await peer2.DisconnectAsync();

        await client1.StopAsync();
        await client2.StopAsync();
    }

    [Fact]
    public async Task UnreliableSendReceive()
    {
        var projectId = Guid.NewGuid();

        var client1transport = new ClientTransport(_serverTransport, _clients, 1.0);
        _clients[client1transport.Endpoint] = client1transport;
        var client1 = new YamabikoClient(ServerTransport.Endpoint, projectId, client1transport)
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client1.StartAsync();

        var client2transport = new ClientTransport(_serverTransport, _clients, 1.0);
        _clients[client2transport.Endpoint] = client2transport;
        var client2 = new YamabikoClient(ServerTransport.Endpoint, projectId, client2transport)
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client2.StartAsync();

        var ad = new Advertisement { Name = "Peer1" };
        await client1.AdvertiseAsync(ad);

        var query = new Query()
        {
            Skip = 0,
            Count = 1
        };
        var queryRes = await client2.QueryAsync(query);

        var peerInfo = Assert.Single(queryRes.Peers.Values);

        var connectTask = client2.ConnectAsync(peerInfo);
        var acceptTask = client1.AcceptPeerAsync();

        using var peer1 = await connectTask;
        using var peer2 = await acceptTask;
        Assert.NotNull(peer2);

        await Task.WhenAll(peer1.WaitUntilConnectedAsync(TimeSpan.FromSeconds(90)), peer2.WaitUntilConnectedAsync(TimeSpan.FromSeconds(90)));

        Assert.Equal(EConnectionState.CONNECTED, peer1.ConnectionState);
        Assert.Equal(EConnectionState.CONNECTED, peer2.ConnectionState);

        var data1 = RandomNumberGenerator.GetBytes(Random.Shared.Next(100, 1000));
        await peer1.SendUnreliableAsync(data1);
        var receivedData1 = await peer2.ReceiveUnreliableAsync();
        Assert.Equal(data1, receivedData1);

        var data2 = RandomNumberGenerator.GetBytes(Random.Shared.Next(100, 1000));
        await peer2.SendUnreliableAsync(data2);
        var receivedData2 = await peer1.ReceiveUnreliableAsync();
        Assert.Equal(data2, receivedData2);

        await peer1.DisconnectAsync();
        await peer2.DisconnectAsync();

        await client1.StopAsync();
        await client2.StopAsync();
    }

    [Theory]
    [InlineData(1.0)]
    [InlineData(0.9)]
    [InlineData(0.8)]
    [InlineData(0.7)]
    [InlineData(0.6)]
    public async Task ReliableSendReceive(double successChance)
    {
        var projectId = Guid.NewGuid();

        var client1transport = new ClientTransport(_serverTransport, _clients, successChance);
        _clients[client1transport.Endpoint] = client1transport;
        var client1 = new YamabikoClient(ServerTransport.Endpoint, projectId, client1transport)
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client1.StartAsync();

        var client2transport = new ClientTransport(_serverTransport, _clients, successChance);
        _clients[client2transport.Endpoint] = client2transport;
        var client2 = new YamabikoClient(ServerTransport.Endpoint, projectId, client2transport)
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client2.StartAsync();

        var ad = new Advertisement { Name = "Peer1" };
        await client1.AdvertiseAsync(ad);

        var query = new Query()
        {
            Skip = 0,
            Count = 1
        };
        var queryRes = await client2.QueryAsync(query);

        var peerInfo = Assert.Single(queryRes.Peers.Values);

        var connectTask = client2.ConnectAsync(peerInfo);
        var acceptTask = client1.AcceptPeerAsync();

        await using var peer1 = await connectTask;
        await using var peer2 = await acceptTask;
        Assert.NotNull(peer2);

        await Task.WhenAll(peer1.WaitUntilConnectedAsync(TimeSpan.FromSeconds(90)), peer2.WaitUntilConnectedAsync(TimeSpan.FromSeconds(90)));

        Assert.Equal(EConnectionState.CONNECTED, peer1.ConnectionState);
        Assert.Equal(EConnectionState.CONNECTED, peer2.ConnectionState);

        var data1 = Enumerable.Range(0, 4096).Select(x => (byte)x).ToArray();
        peer1.SendReliable(data1);
        var receivedData1 = await peer2.ReceiveReliableAsync();
        Assert.Equal(data1, receivedData1);

        var data2 = RandomNumberGenerator.GetBytes(Random.Shared.Next(4096, 8192));
        peer2.SendReliable(data2);
        var receivedData2 = await peer1.ReceiveReliableAsync();
        Assert.Equal(data2, receivedData2);

        await peer1.DisconnectAsync();
        await peer2.DisconnectAsync();

        await client1.StopAsync();
        await client2.StopAsync();
    }

    [Fact]
    public async Task StreamSendReceive()
    {
        var projectId = Guid.NewGuid();

        var client1transport = new ClientTransport(_serverTransport, _clients, 1.0, 10240);
        var client2transport = new ClientTransport(_serverTransport, _clients, 1.0, 10240);

        _clients[client1transport.Endpoint] = client1transport;
        _clients[client2transport.Endpoint] = client2transport;

        var client1 = new YamabikoClient
        (
            ServerTransport.Endpoint,
            projectId,
            new YamabikoKcpOptions
            {
                StreamNoCongestionControl = true
            },
            client1transport
        //LoggerFactory.Create(builder =>
        //{
        //    builder.AddFilter(_ => true);
        //    builder.AddProvider(new TestLoggerProvider(_output, ">"));
        //})
        )
        {
            ValidateCertificatesCallback = (_) => true
        };
        var client2 = new YamabikoClient
        (
            ServerTransport.Endpoint,
            projectId,
            new YamabikoKcpOptions
            {
                StreamNoCongestionControl = true
            },
            client2transport
        //LoggerFactory.Create(builder =>
        //{
        //    builder.AddFilter(_ => true);
        //    builder.AddProvider(new TestLoggerProvider(_output, "<"));
        //})
        )
        {
            ValidateCertificatesCallback = (_) => true
        };

        await client1.StartAsync();
        await client2.StartAsync();

        var ad = new Advertisement { Name = "Peer1" };
        await client1.AdvertiseAsync(ad);

        var query = new Query()
        {
            Skip = 0,
            Count = 1
        };
        var queryRes = await client2.QueryAsync(query);

        var peerInfo = Assert.Single(queryRes.Peers.Values);

        var connectTask = client2.ConnectAsync(peerInfo);
        var acceptTask = client1.AcceptPeerAsync();

        using var peer1 = await connectTask;
        using var peer2 = await acceptTask;
        Assert.NotNull(peer2);

        await Task.WhenAll(peer1.WaitUntilConnectedAsync(TimeSpan.FromSeconds(90)), peer2.WaitUntilConnectedAsync(TimeSpan.FromSeconds(90)));

        Assert.Equal(EConnectionState.CONNECTED, peer1.ConnectionState);
        Assert.Equal(EConnectionState.CONNECTED, peer2.ConnectionState);

        var stream1 = peer1.GetStream();
        var stream2 = peer2.GetStream();

        var data1 = Enumerable.Range(0, 32 * 1024 * 1024).Select(x => (byte)x).ToArray();
        var data1Read = new byte[data1.Length];

        var sendTask1 = Task.Run(async () =>
        {
            int offset = 0;
            while (offset < data1.Length)
            {
                var len = Math.Min(Random.Shared.Next(512, 4096), data1.Length - offset);
                await stream1.WriteAsync(data1.AsMemory(offset, len)).ConfigureAwait(false);
                offset += len;
            }
        });
        var receiveTask1 = Task.Run(async () =>
        {
            int offset = 0;
            while (offset < data1Read.Length)
            {
                var read = await stream2.ReadAsync(data1Read.AsMemory(offset, Math.Min(1024, data1Read.Length - offset))).ConfigureAwait(false);
                offset += read;
            }
        });

        await sendTask1;
        await receiveTask1;

        Assert.Equal(data1, data1Read);

        var data2 = RandomNumberGenerator.GetBytes(32 * 1024 * 1024);
        var data2Read = new byte[data2.Length];

        var sendTask2 = Task.Run(async () =>
        {
            await stream2.WriteAsync(data2).ConfigureAwait(false);
        });
        var receiveTask2 = Task.Run(async () =>
        {
            //await stream1.ReadExactlyAsync(data2Read).ConfigureAwait(false);
            int offset = 0;
            while (offset < data2Read.Length)
            {
                var read = await stream1.ReadAsync(data2Read.AsMemory(offset, Math.Min(1024, data2Read.Length - offset))).ConfigureAwait(false);
                offset += read;
            }
        });

        await sendTask2;
        await receiveTask2;

        Assert.Equal(data2, data2Read);

        await peer1.DisconnectAsync();
        await peer2.DisconnectAsync();

        await client1.StopAsync();
        await client2.StopAsync();
    }

    public async Task DisposeAsync()
    {
        _cts.Cancel();

        await _receiveServiceTask;
        await _clientsClearTask;
    }

    public void Dispose()
    {
        _serverTransport.Dispose();
        _cts.Dispose();
    }

    public class ClientTransport : YamabikoTransport
    {
        private static int Port = 12345;

        public IPEndPoint Endpoint { get; }
        public Channel<(IPEndPoint, ReadOnlyMemory<byte>)> Channel { get; }
            = System.Threading.Channels.Channel.CreateUnbounded<(IPEndPoint, ReadOnlyMemory<byte>)>();

        private double _successChance;
        private ServerTransport _serverTransport;
        private Dictionary<IPEndPoint, ClientTransport> _clients;

        public ClientTransport(ServerTransport serverTransport, Dictionary<IPEndPoint, ClientTransport> clients, double successChance, int recvWindow = 128) : base(recvWindow)
        {
            Endpoint = new IPEndPoint(IPAddress.Loopback, Port++);

            _successChance = successChance;
            _serverTransport = serverTransport;
            _clients = clients;
        }

        protected override void Init() { }

        public override async Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
        {
            if (Random.Shared.NextDouble() <= _successChance)
            {
                var byteArr = buffer.ToArray();
                if (endpoint.Equals(ServerTransport.Endpoint))
                    await _serverTransport.Channel.Writer.WriteAsync((Endpoint, byteArr), ct).ConfigureAwait(false);
                else if (_clients.TryGetValue(endpoint, out var client))
                {
                    if (!client.Channel.Writer.TryWrite((Endpoint, byteArr)))
                        await client.Channel.Writer.WriteAsync((Endpoint, byteArr), ct).ConfigureAwait(false);
                }
            }
        }

        protected override async Task<YamabikoReceiveResult> ReceiveAsync(CancellationToken ct)
        {
            (IPEndPoint, ReadOnlyMemory<byte>) result;
            if (Channel.Reader.TryRead(out result))
                return new YamabikoReceiveResult(result.Item2, result.Item1);

            result = await Channel.Reader.ReadAsync(ct).ConfigureAwait(false);
            return new YamabikoReceiveResult(result.Item2, result.Item1);
        }
    }

    public class ServerTransport : ITransport
    {
        public static IPEndPoint Endpoint { get; } = new IPEndPoint(IPAddress.Loopback, 59999);
        public Channel<(IPEndPoint, ReadOnlyMemory<byte>)> Channel { get; } = System.Threading.Channels.Channel.CreateUnbounded<(IPEndPoint, ReadOnlyMemory<byte>)>();

        public Dictionary<IPEndPoint, ClientTransport> _clients;

        public ServerTransport(Dictionary<IPEndPoint, ClientTransport> clients)
        {
            _clients = clients;
        }

        public async Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
        {
            if (_clients.TryGetValue(endpoint, out var client))
                await client.Channel.Writer.WriteAsync((Endpoint, buffer.ToArray()), ct).ConfigureAwait(false);
        }

        public async Task<TransportReceiveResult> ReceiveAsync(CancellationToken ct)
        {
            var result = await Channel.Reader.ReadAsync(ct).ConfigureAwait(false);
            return new TransportReceiveResult(result.Item2, result.Item1);
        }

        public void Dispose() { }
    }
}

public class TestLogger : ILogger
{
    private static int _maxCategoryNameLength = 0;
    private static readonly Lock _lock = new();

    private readonly ITestOutputHelper _output;
    private readonly string _delimeter;
    private readonly string _categoryName;
    private readonly long _startTimestamp;

    public TestLogger(ITestOutputHelper output, string delimeter, string categoryName, long startTimestamp)
    {
        _output = output;
        _delimeter = delimeter;
        _categoryName = categoryName.Split(".")[^1];
        _startTimestamp = startTimestamp;

        _maxCategoryNameLength = Math.Max(_maxCategoryNameLength, _categoryName.Length);
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        => new NoopDisposable();

    public bool IsEnabled(LogLevel logLevel)
        => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var elapsed = Stopwatch.GetElapsedTime(_startTimestamp);
        var elapsedStr = $"{elapsed.TotalSeconds,12:0.0000}s";
        var logLevelStr = logLevel switch
        {
            LogLevel.Trace => "Trace",
            LogLevel.Debug => "Debug",
            LogLevel.Information => " Info",
            LogLevel.Warning => " Warn",
            LogLevel.Error => "Error",
            LogLevel.Critical => " Crit",
            _ => "     "
        };
        var text = formatter(state, exception);
        if (256 < text.Length)
            text = text.Substring(0, 253) + "...";

        var catName = _categoryName.PadLeft(_maxCategoryNameLength, ' ');
        var log = $"{elapsedStr} {logLevelStr} {catName} {_delimeter} {text}";

        lock (_lock)
        {
            _output.WriteLine(log);
            Console.WriteLine(log);
            if (exception is not null)
            {
                _output.WriteLine(exception.Message);
                Console.WriteLine(exception.Message);
            }
        }
    }

    private class NoopDisposable : IDisposable
    {
        public void Dispose()
        {
        }
    }
}

public class TestLoggerProvider(ITestOutputHelper _output, string delimeter) : ILoggerProvider
{
    private long _startTimestamp = Stopwatch.GetTimestamp();

    public ILogger CreateLogger(string categoryName)
        => new TestLogger(_output, delimeter, categoryName, _startTimestamp);

    public void Dispose() { }
}
