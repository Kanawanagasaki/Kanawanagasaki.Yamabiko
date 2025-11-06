namespace Kanawanagasaki.Yamabiko.Test;

using Kanawanagasaki.Yamabiko.Server;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using Kanawanagasaki.Yamabiko.Tags;
using System;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Xunit.Abstractions;

public class YamabikoClient_Tests : IAsyncLifetime, IDisposable
{
    private readonly ITestOutputHelper _output;

    private readonly Settings _settings;
    private readonly ProjectsService _projectsService;
    private readonly ServerTransport _serverTransport;
    private readonly ClientsService _clientsService;
    private readonly ReceiverService _receiveService;

    private readonly CancellationTokenSource _cts;
    private readonly Task _clientsClearTask;
    private readonly Task _receiveServiceTask;

    public YamabikoClient_Tests(ITestOutputHelper output)
    {
        _output = output;

        _settings = new Settings();
        _projectsService = new ProjectsService();
        _serverTransport = new ServerTransport();
        _clientsService = new ClientsService(_settings, _serverTransport, _projectsService);
        _receiveService = new ReceiverService(_clientsService, _serverTransport);

        _cts = new CancellationTokenSource();
        _clientsClearTask = _clientsService.RunClearTimerAsync(_cts.Token);
        _receiveServiceTask = _receiveService.RunAsync(_cts.Token);
    }

    public Task InitializeAsync()
        => Task.CompletedTask;

    [Fact]
    public async Task StopServerWithinASecond()
    {
        _cts.Cancel();

        var timeoutTask = Task.Delay(TimeSpan.FromSeconds(1));
        var first = Task.WhenAny(_receiveServiceTask, timeoutTask);
        Assert.NotEqual(timeoutTask, first);
        var second = Task.WhenAny(_clientsClearTask, timeoutTask);
        Assert.NotEqual(timeoutTask, second);

        await _receiveServiceTask;
        await _clientsClearTask;

        await timeoutTask;
    }

    [Theory]
    [InlineData(1.0)]
    [InlineData(0.95)]
    [InlineData(0.9)]
    [InlineData(0.85)]
    [InlineData(0.8)]
    [InlineData(0.75)]
    public async Task Client_StartAndStop_HandshakeCompleted(double successChance)
    {
        Assert.Empty(_clientsService.Clients);

        var projectId = Guid.NewGuid();
        var client = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, successChance))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client.StartAsync(_cts.Token);

        Assert.Single(_clientsService.Clients);

        await client.StopAsync();
        await Task.Delay(100);

        if (successChance == 1.0)
            Assert.Empty(_clientsService.Clients);
    }

    [Theory]
    [InlineData(1.0)]
    [InlineData(0.95)]
    [InlineData(0.9)]
    [InlineData(0.85)]
    [InlineData(0.8)]
    [InlineData(0.75)]
    public async Task Client_StartAndStop_Multiple(double successChance)
    {
        Assert.Empty(_clientsService.Clients);

        const int clientsNum = 5;
        var projectId = Guid.NewGuid();

        var clients = new List<YamabikoClient>();
        for (int i = 0; i < clientsNum; i++)
        {
            var client = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, successChance))
            {
                ValidateCertificatesCallback = (_) => true
            };
            await client.StartAsync(_cts.Token);
            clients.Add(client);

            Assert.Equal(i + 1, _clientsService.Clients.Count());
        }

        Assert.Equal(clientsNum, _clientsService.Clients.Count());

        foreach (var client in clients.OrderBy(_ => Random.Shared.NextDouble()).ToArray())
        {
            await client.StopAsync();
            clients.Remove(client);
            await Task.Delay(100);

            if (successChance == 1.0)
                Assert.Equal(clients.Count, _clientsService.Clients.Count());
        }
    }

    [Theory]
    [InlineData(1.0)]
    [InlineData(0.95)]
    [InlineData(0.9)]
    [InlineData(0.85)]
    [InlineData(0.8)]
    [InlineData(0.75)]
    public async Task StartAndStopAdvertisement(double successChance)
    {
        var projectId = Guid.NewGuid();
        var client = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, successChance))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client.StartAsync(_cts.Token);

        var advertisement = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55))
        };
        await client.AdvertiseAsync(advertisement);

        var clientOnServer = Assert.Single(_clientsService.Clients);
        var project = _projectsService.GetProject(projectId);
        Assert.NotNull(project);

        var peerOnServer = Assert.Single(project.Peers);

        Assert.Equal(advertisement.Name, peerOnServer.Name);
        Assert.Equal(advertisement.Flags, peerOnServer.Flags);
        Assert.Equal(advertisement.Password, peerOnServer.Password);
        Assert.Empty(peerOnServer.Tags);

        await client.StopAdvertisingAsync();
        await Task.Delay(100);

        Assert.Single(_clientsService.Clients);
        Assert.Empty(project.Peers);
        Assert.Null(_projectsService.GetProject(projectId));

        await client.StopAsync();
        await Task.Delay(100);

        if (successChance == 1.0)
            Assert.Empty(_clientsService.Clients);
    }

    [Theory]
    [InlineData(1.0)]
    [InlineData(0.95)]
    [InlineData(0.9)]
    [InlineData(0.85)]
    [InlineData(0.8)]
    [InlineData(0.75)]
    public async Task StartAndStopAdvertisementWithTags(double successChance)
    {
        var projectId = Guid.NewGuid();
        var client = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, successChance))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client.StartAsync(_cts.Token);

        var byteArrayAdTag = new ByteArrayTag(1, RandomNumberGenerator.GetBytes(Random.Shared.Next(5, 200)));
        var byteAdTag = new ByteTag(2, (byte)Random.Shared.Next(0, byte.MaxValue));
        var doubleAdTag = new DoubleTag(3, Random.Shared.NextDouble());
        var floatAdTag = new FloatTag(4, (float)Random.Shared.NextDouble());
        var intAdTag = new IntTag(5, Random.Shared.Next());
        var longAdTag = new LongTag(6, ((long)Random.Shared.Next() << 32) | (long)Random.Shared.Next());
        var shortAdTag = new ShortTag(7, (short)Random.Shared.Next(short.MinValue, short.MaxValue));
        var stringAdTag = new StringTag(8, RandomAsciiString(Random.Shared.Next(5, 55)));

        var advertisement = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55)),
            Tags =
            [
                byteArrayAdTag,
                byteAdTag,
                doubleAdTag,
                floatAdTag,
                intAdTag,
                longAdTag,
                shortAdTag,
                stringAdTag
            ]
        };
        await client.AdvertiseAsync(advertisement);

        var clientOnServer = Assert.Single(_clientsService.Clients);
        var project = _projectsService.GetProject(projectId);
        Assert.NotNull(project);

        var peerOnServer = Assert.Single(project.Peers);

        Assert.Equal(advertisement.Name, peerOnServer.Name);
        Assert.Equal(advertisement.Flags, peerOnServer.Flags);
        Assert.Equal(advertisement.Password, peerOnServer.Password);

        Assert.True(peerOnServer.Tags.TryGetValue(1, out var byteArrayBytes));
        var byteArrayTag = ByteArrayTag.Parse(1, byteArrayBytes);
        Assert.Equal(byteArrayAdTag.Val, byteArrayTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(2, out var byteBytes));
        var byteTag = ByteTag.Parse(2, byteBytes);
        Assert.Equal(byteAdTag.Val, byteTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(3, out var doubleBytes));
        var doubleTag = DoubleTag.Parse(3, doubleBytes);
        Assert.Equal(doubleAdTag.Val, doubleTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(4, out var floatBytes));
        var floatTag = FloatTag.Parse(4, floatBytes);
        Assert.Equal(floatAdTag.Val, floatTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(5, out var intBytes));
        var intTag = IntTag.Parse(5, intBytes);
        Assert.Equal(intAdTag.Val, intTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(6, out var longBytes));
        var longTag = LongTag.Parse(6, longBytes);
        Assert.Equal(longAdTag.Val, longTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(7, out var shortBytes));
        var shortTag = ShortTag.Parse(7, shortBytes);
        Assert.Equal(shortAdTag.Val, shortTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(8, out var stringBytes));
        var stringTag = StringTag.Parse(8, stringBytes);
        Assert.Equal(stringAdTag.Val, stringTag.Val);

        await client.ClearTagsAsync([1, 3, 5, 7]);
        await Task.Delay(100);

        project = _projectsService.GetProject(projectId);
        Assert.NotNull(project);
        peerOnServer = Assert.Single(project.Peers);

        Assert.False(peerOnServer.Tags.TryGetValue(1, out _));
        Assert.True(peerOnServer.Tags.TryGetValue(2, out _));
        Assert.False(peerOnServer.Tags.TryGetValue(3, out _));
        Assert.True(peerOnServer.Tags.TryGetValue(4, out _));
        Assert.False(peerOnServer.Tags.TryGetValue(5, out _));
        Assert.True(peerOnServer.Tags.TryGetValue(6, out _));
        Assert.False(peerOnServer.Tags.TryGetValue(7, out _));
        Assert.True(peerOnServer.Tags.TryGetValue(8, out _));

        await client.StopAdvertisingAsync();
        await Task.Delay(100);

        Assert.Single(_clientsService.Clients);
        Assert.Empty(project.Peers);
        Assert.Null(_projectsService.GetProject(projectId));

        await client.StopAsync();
        await Task.Delay(100);

        if (successChance == 1.0)
            Assert.Empty(_clientsService.Clients);
    }

    [Theory]
    [InlineData(1.0)]
    [InlineData(0.95)]
    [InlineData(0.9)]
    [InlineData(0.85)]
    [InlineData(0.8)]
    [InlineData(0.75)]
    public async Task StartUpdateAndStopAdvertisement(double successChance)
    {
        var projectId = Guid.NewGuid();
        var client = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, successChance))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client.StartAsync(_cts.Token);

        var advertisement = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55))
        };
        await client.AdvertiseAsync(advertisement);

        Assert.Single(_clientsService.Clients);
        var project = _projectsService.GetProject(projectId);
        Assert.NotNull(project);

        var peerOnServer = Assert.Single(project.Peers);

        Assert.Equal(advertisement.Name, peerOnServer.Name);
        Assert.Equal(advertisement.Flags, peerOnServer.Flags);
        Assert.Equal(advertisement.Password, peerOnServer.Password);
        Assert.Empty(peerOnServer.Tags);

        var advertisement2 = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55))
        };
        await client.AdvertiseAsync(advertisement2);

        var peerOnServer2 = Assert.Single(project.Peers);
        Assert.Equal(peerOnServer, peerOnServer2);

        Assert.Equal(advertisement2.Name, peerOnServer2.Name);
        Assert.Equal(advertisement2.Flags, peerOnServer2.Flags);
        Assert.Equal(advertisement2.Password, peerOnServer2.Password);
        Assert.Empty(peerOnServer2.Tags);

        await client.StopAdvertisingAsync();
        await Task.Delay(100);

        Assert.Single(_clientsService.Clients);
        Assert.Empty(project.Peers);
        Assert.Null(_projectsService.GetProject(projectId));

        var advertisement3 = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55))
        };
        await client.AdvertiseAsync(advertisement3);

        project = _projectsService.GetProject(projectId);
        Assert.NotNull(project);
        var peerOnServer3 = Assert.Single(project.Peers);
        Assert.NotEqual(peerOnServer, peerOnServer3);
        Assert.NotEqual(peerOnServer2, peerOnServer3);

        Assert.Equal(advertisement3.Name, peerOnServer3.Name);
        Assert.Equal(advertisement3.Flags, peerOnServer3.Flags);
        Assert.Equal(advertisement3.Password, peerOnServer3.Password);
        Assert.Empty(peerOnServer3.Tags);

        await client.StopAdvertisingAsync();
        await Task.Delay(100);

        Assert.Single(_clientsService.Clients);
        Assert.Empty(project.Peers);
        Assert.Null(_projectsService.GetProject(projectId));

        await client.StopAsync();
        await Task.Delay(100);

        if (successChance == 1.0)
            Assert.Empty(_clientsService.Clients);
    }

    [Theory]
    [InlineData(1.0)]
    [InlineData(0.95)]
    [InlineData(0.9)]
    [InlineData(0.85)]
    [InlineData(0.8)]
    [InlineData(0.75)]
    public async Task StartAndStopAdvertisementWithUpdatingTags(double successChance)
    {
        var projectId = Guid.NewGuid();
        var client = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, successChance))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client.StartAsync(_cts.Token);

        var byteArrayAdTag = new ByteArrayTag(1, RandomNumberGenerator.GetBytes(Random.Shared.Next(5, 200)));
        var byteAdTag = new ByteTag(2, (byte)Random.Shared.Next(0, byte.MaxValue));
        var doubleAdTag = new DoubleTag(3, Random.Shared.NextDouble());
        var floatAdTag = new FloatTag(4, (float)Random.Shared.NextDouble());
        var intAdTag = new IntTag(5, Random.Shared.Next());
        var longAdTag = new LongTag(6, ((long)Random.Shared.Next() << 32) | (long)Random.Shared.Next());
        var shortAdTag = new ShortTag(7, (short)Random.Shared.Next(short.MinValue, short.MaxValue));
        var stringAdTag = new StringTag(8, RandomAsciiString(Random.Shared.Next(5, 55)));

        var advertisement = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55)),
            Tags =
            [
                byteArrayAdTag,
                byteAdTag,
                doubleAdTag,
                floatAdTag,
                intAdTag,
                longAdTag,
                shortAdTag,
                stringAdTag
            ]
        };
        await client.AdvertiseAsync(advertisement);

        var clientOnServer = Assert.Single(_clientsService.Clients);
        var project = _projectsService.GetProject(projectId);
        Assert.NotNull(project);

        var peerOnServer = Assert.Single(project.Peers);

        Assert.Equal(advertisement.Name, peerOnServer.Name);
        Assert.Equal(advertisement.Flags, peerOnServer.Flags);
        Assert.Equal(advertisement.Password, peerOnServer.Password);

        Assert.True(peerOnServer.Tags.TryGetValue(1, out var byteArrayBytes));
        var byteArrayTag = ByteArrayTag.Parse(1, byteArrayBytes);
        Assert.Equal(byteArrayAdTag.Val, byteArrayTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(2, out var byteBytes));
        var byteTag = ByteTag.Parse(2, byteBytes);
        Assert.Equal(byteAdTag.Val, byteTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(3, out var doubleBytes));
        var doubleTag = DoubleTag.Parse(3, doubleBytes);
        Assert.Equal(doubleAdTag.Val, doubleTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(4, out var floatBytes));
        var floatTag = FloatTag.Parse(4, floatBytes);
        Assert.Equal(floatAdTag.Val, floatTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(5, out var intBytes));
        var intTag = IntTag.Parse(5, intBytes);
        Assert.Equal(intAdTag.Val, intTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(6, out var longBytes));
        var longTag = LongTag.Parse(6, longBytes);
        Assert.Equal(longAdTag.Val, longTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(7, out var shortBytes));
        var shortTag = ShortTag.Parse(7, shortBytes);
        Assert.Equal(shortAdTag.Val, shortTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(8, out var stringBytes));
        var stringTag = StringTag.Parse(8, stringBytes);
        Assert.Equal(stringAdTag.Val, stringTag.Val);

        var newByteArrayAdTag = new ByteArrayTag(1, RandomNumberGenerator.GetBytes(Random.Shared.Next(5, 200)));
        var newByteAdTag = new ByteTag(2, (byte)Random.Shared.Next(0, byte.MaxValue));
        var newDoubleAdTag = new DoubleTag(3, Random.Shared.NextDouble());
        var newFloatAdTag = new FloatTag(4, (float)Random.Shared.NextDouble());
        var newIntAdTag = new IntTag(5, Random.Shared.Next());
        var newLongAdTag = new LongTag(6, ((long)Random.Shared.Next() << 32) | (long)Random.Shared.Next());
        var newShortAdTag = new ShortTag(7, (short)Random.Shared.Next(short.MinValue, short.MaxValue));
        var newStringAdTag = new StringTag(8, RandomAsciiString(Random.Shared.Next(5, 55)));

        await client.AdvertiseTagsAsync(
            [
                newByteArrayAdTag,
                newByteAdTag,
                newDoubleAdTag,
                newFloatAdTag,
                newIntAdTag,
                newLongAdTag,
                newShortAdTag,
                newStringAdTag
            ]
        );

        var peerOnServer2 = Assert.Single(project.Peers);
        Assert.Equal(peerOnServer, peerOnServer2);

        Assert.Equal(advertisement.Name, peerOnServer.Name);
        Assert.Equal(advertisement.Flags, peerOnServer.Flags);
        Assert.Equal(advertisement.Password, peerOnServer.Password);

        Assert.True(peerOnServer.Tags.TryGetValue(1, out var newByteArrayBytes));
        var newByteArrayTag = ByteArrayTag.Parse(1, newByteArrayBytes);
        Assert.Equal(newByteArrayAdTag.Val, newByteArrayTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(2, out var newByteBytes));
        var newByteTag = ByteTag.Parse(2, newByteBytes);
        Assert.Equal(newByteAdTag.Val, newByteTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(3, out var newDoubleBytes));
        var newDoubleTag = DoubleTag.Parse(3, newDoubleBytes);
        Assert.Equal(newDoubleAdTag.Val, newDoubleTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(4, out var newFloatBytes));
        var newFloatTag = FloatTag.Parse(4, newFloatBytes);
        Assert.Equal(newFloatAdTag.Val, newFloatTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(5, out var newIntBytes));
        var newIntTag = IntTag.Parse(5, newIntBytes);
        Assert.Equal(newIntAdTag.Val, newIntTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(6, out var newLongBytes));
        var newLongTag = LongTag.Parse(6, newLongBytes);
        Assert.Equal(newLongAdTag.Val, newLongTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(7, out var newShortBytes));
        var newShortTag = ShortTag.Parse(7, newShortBytes);
        Assert.Equal(newShortAdTag.Val, newShortTag.Val);

        Assert.True(peerOnServer.Tags.TryGetValue(8, out var newStringBytes));
        var newStringTag = StringTag.Parse(8, newStringBytes);
        Assert.Equal(newStringAdTag.Val, newStringTag.Val);

        await client.StopAdvertisingAsync();
        await Task.Delay(100);

        Assert.Single(_clientsService.Clients);
        Assert.Empty(project.Peers);
        Assert.Null(_projectsService.GetProject(projectId));

        await client.StopAsync();
        await Task.Delay(100);

        if (successChance == 1.0)
            Assert.Empty(_clientsService.Clients);
    }

    [Theory]
    [InlineData(1.0)]
    [InlineData(0.95)]
    [InlineData(0.9)]
    [InlineData(0.85)]
    [InlineData(0.8)]
    [InlineData(0.75)]
    public async Task SubscribeAndUnsubscribe(double successChance)
    {
        var projectId = Guid.NewGuid();
        var client = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, successChance))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client.StartAsync(_cts.Token);

        var clientOnServer = Assert.Single(_clientsService.Clients);
        var project = _projectsService.GetProject(projectId);
        Assert.Null(project);

        await client.SubscribeAsync();

        project = _projectsService.GetProject(projectId);
        Assert.NotNull(project);
        var subscriberOnServer = Assert.Single(project.Subscribers);
        Assert.Equal(clientOnServer, subscriberOnServer);

        await client.UnsubscribeAsync();

        Assert.Empty(project.Subscribers);

        project = _projectsService.GetProject(projectId);
        Assert.Null(project);

        await client.StopAsync();
        await Task.Delay(100);

        if (successChance == 1.0)
            Assert.Empty(_clientsService.Clients);
    }

    [Fact]
    public async Task SubscribeAndListenToNotifications()
    {
        var projectId = Guid.NewGuid();

        var client1 = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, 1.0))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client1.StartAsync(_cts.Token);

        PeerInfo? peerInfo = null;
        client1.OnPeerAdvertisement += peerPacket => peerInfo = new PeerInfo(peerPacket);

        await client1.SubscribeAsync();

        var client2 = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, 1.0))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client2.StartAsync(_cts.Token);

        var advertisement1 = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55))
        };
        await client2.AdvertiseAsync(advertisement1);

        await Task.Delay(100);

        Assert.NotNull(peerInfo);
        Assert.Equal(advertisement1.Name, peerInfo.Name);
        Assert.Equal(advertisement1.Flags, peerInfo.Flags);

        await client1.UnsubscribeAsync();

        var advertisement2 = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55))
        };
        await client2.AdvertiseAsync(advertisement2);

        await Task.Delay(100);

        Assert.NotNull(peerInfo);
        Assert.Equal(advertisement1.Name, peerInfo.Name);
        Assert.Equal(advertisement1.Flags, peerInfo.Flags);

        await client1.SubscribeAsync();

        var advertisement3 = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55))
        };
        await client2.AdvertiseAsync(advertisement3);

        await Task.Delay(100);

        Assert.NotNull(peerInfo);
        Assert.Equal(advertisement3.Name, peerInfo.Name);
        Assert.Equal(advertisement3.Flags, peerInfo.Flags);

        await client1.UnsubscribeAsync();
        await client1.StopAsync();

        await client2.StopAsync();
    }

    [Fact]
    public async Task SubscribeAndListenToNotificationsWithTags()
    {
        var projectId = Guid.NewGuid();

        var client1 = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, 1.0))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client1.StartAsync(_cts.Token);

        PeerInfo? peerInfo = null;
        client1.OnPeerAdvertisement += peerPacket => peerInfo = new PeerInfo(peerPacket);
        client1.OnPeerExtraAdvertisement += peerExtraPacket =>
        {
            if (peerInfo is null)
                return;

            if (peerExtraPacket.Data is null)
                peerInfo.ClearTag(peerExtraPacket.TagId);
            else
                peerInfo.SetTag(peerExtraPacket.TagId, peerExtraPacket.Data);
        };

        await client1.SubscribeAsync();

        var client2 = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, 1.0))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client2.StartAsync(_cts.Token);

        var byteArrayAdTag = new ByteArrayTag(1, RandomNumberGenerator.GetBytes(Random.Shared.Next(5, 200)));
        var byteAdTag = new ByteTag(2, (byte)Random.Shared.Next(0, byte.MaxValue));
        var doubleAdTag = new DoubleTag(3, Random.Shared.NextDouble());
        var floatAdTag = new FloatTag(4, (float)Random.Shared.NextDouble());
        var intAdTag = new IntTag(5, Random.Shared.Next());
        var longAdTag = new LongTag(6, ((long)Random.Shared.Next() << 32) | (long)Random.Shared.Next());
        var shortAdTag = new ShortTag(7, (short)Random.Shared.Next(short.MinValue, short.MaxValue));
        var stringAdTag = new StringTag(8, RandomAsciiString(Random.Shared.Next(5, 55)));
        var advertisement = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55)),
            Tags =
            [
                byteArrayAdTag,
                byteAdTag,
                doubleAdTag,
                floatAdTag,
                intAdTag,
                longAdTag,
                shortAdTag,
                stringAdTag
            ]
        };
        await client2.AdvertiseAsync(advertisement);

        await Task.Delay(100);

        Assert.NotNull(peerInfo);
        Assert.Equal(advertisement.Name, peerInfo.Name);
        Assert.Equal(advertisement.Flags, peerInfo.Flags);
        Assert.Equal(advertisement.Tags.Count(), peerInfo.Tags.Count);

        var byteArrayTag = peerInfo.GetTag<ByteArrayTag>(1);
        Assert.NotNull(byteArrayTag);
        Assert.Equal(byteArrayAdTag.Val, byteArrayTag.Val);

        var byteTag = peerInfo.GetTag<ByteTag>(2);
        Assert.NotNull(byteTag);
        Assert.Equal(byteAdTag.Val, byteTag.Val);

        var doubleTag = peerInfo.GetTag<DoubleTag>(3);
        Assert.NotNull(doubleTag);
        Assert.Equal(doubleAdTag.Val, doubleTag.Val);

        var floatTag = peerInfo.GetTag<FloatTag>(4);
        Assert.NotNull(floatTag);
        Assert.Equal(floatAdTag.Val, floatTag.Val);

        var intTag = peerInfo.GetTag<IntTag>(5);
        Assert.NotNull(intTag);
        Assert.Equal(intAdTag.Val, intTag.Val);

        var longTag = peerInfo.GetTag<LongTag>(6);
        Assert.NotNull(longTag);
        Assert.Equal(longAdTag.Val, longTag.Val);

        var shortTag = peerInfo.GetTag<ShortTag>(7);
        Assert.NotNull(shortTag);
        Assert.Equal(shortAdTag.Val, shortTag.Val);

        var stringTag = peerInfo.GetTag<StringTag>(8);
        Assert.NotNull(stringTag);
        Assert.Equal(stringAdTag.Val, stringTag.Val);

        var byteArrayAdTag2 = new ByteArrayTag(1, RandomNumberGenerator.GetBytes(Random.Shared.Next(5, 200)));
        var byteAdTag2 = new ByteTag(2, (byte)Random.Shared.Next(0, byte.MaxValue));
        var doubleAdTag2 = new DoubleTag(3, Random.Shared.NextDouble());
        var floatAdTag2 = new FloatTag(4, (float)Random.Shared.NextDouble());
        var intAdTag2 = new IntTag(5, Random.Shared.Next());
        var longAdTag2 = new LongTag(6, ((long)Random.Shared.Next() << 32) | (long)Random.Shared.Next());
        var shortAdTag2 = new ShortTag(7, (short)Random.Shared.Next(short.MinValue, short.MaxValue));
        var stringAdTag2 = new StringTag(8, RandomAsciiString(Random.Shared.Next(5, 55)));
        await client2.AdvertiseTagsAsync
        (
            [
                byteArrayAdTag2,
                byteAdTag2,
                doubleAdTag2,
                floatAdTag2,
                intAdTag2,
                longAdTag2,
                shortAdTag2,
                stringAdTag2
            ]
        );

        await Task.Delay(100);

        var byteArrayTag2 = peerInfo.GetTag<ByteArrayTag>(1);
        Assert.NotNull(byteArrayTag2);
        Assert.Equal(byteArrayAdTag2.Val, byteArrayTag2.Val);

        var byteTag2 = peerInfo.GetTag<ByteTag>(2);
        Assert.NotNull(byteTag2);
        Assert.Equal(byteAdTag2.Val, byteTag2.Val);

        var doubleTag2 = peerInfo.GetTag<DoubleTag>(3);
        Assert.NotNull(doubleTag2);
        Assert.Equal(doubleAdTag2.Val, doubleTag2.Val);

        var floatTag2 = peerInfo.GetTag<FloatTag>(4);
        Assert.NotNull(floatTag2);
        Assert.Equal(floatAdTag2.Val, floatTag2.Val);

        var intTag2 = peerInfo.GetTag<IntTag>(5);
        Assert.NotNull(intTag2);
        Assert.Equal(intAdTag2.Val, intTag2.Val);

        var longTag2 = peerInfo.GetTag<LongTag>(6);
        Assert.NotNull(longTag2);
        Assert.Equal(longAdTag2.Val, longTag2.Val);

        var shortTag2 = peerInfo.GetTag<ShortTag>(7);
        Assert.NotNull(shortTag2);
        Assert.Equal(shortAdTag2.Val, shortTag2.Val);

        var stringTag2 = peerInfo.GetTag<StringTag>(8);
        Assert.NotNull(stringTag2);
        Assert.Equal(stringAdTag2.Val, stringTag2.Val);

        await client1.UnsubscribeAsync();
        await client1.StopAsync();

        await client2.StopAsync();
    }


    [Theory]
    [InlineData(1.0)]
    [InlineData(0.95)]
    [InlineData(0.9)]
    [InlineData(0.85)]
    [InlineData(0.8)]
    [InlineData(0.75)]
    [InlineData(0.5)]
    public async Task Query(double successChance)
    {
        var projectId = Guid.NewGuid();

        var client1 = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, successChance))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client1.StartAsync(_cts.Token);

        var advertisement = new Advertisement
        {
            Name = RandomAsciiString(Random.Shared.Next(5, 55)),
            Flags = (ulong)Random.Shared.Next(),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(5, 55))
        };
        await client1.AdvertiseAsync(advertisement);

        var client2 = new YamabikoClient(ServerTransport.Endpoint, projectId, new ClientTransport(_serverTransport, successChance))
        {
            ValidateCertificatesCallback = (_) => true
        };
        await client2.StartAsync(_cts.Token);

        var query = new Query
        {
            Skip = 0,
            Count = 1
        };
        var queryRes = await client2.QueryAsync(query);

        var (peerId, peerInfo) = Assert.Single(queryRes.Peers);

        Assert.Equal(advertisement.Name, peerInfo.Name);
        Assert.Equal(advertisement.Flags, peerInfo.Flags);

        await client1.StopAdvertisingAsync();
        await Task.Delay(100);

        queryRes = await client2.QueryAsync(query);
        Assert.Empty(queryRes.Peers);

        await client2.StopAsync();
        await client1.StopAsync();
        await Task.Delay(100);

        if (successChance == 1.0)
            Assert.Empty(_clientsService.Clients);
    }

    private static string RandomAsciiString(int length)
    {
        var chars = new char[length];
        for (int i = 0; i < length; i++)
            chars[i] = (char)Random.Shared.Next(32, 127);
        return new string(chars);
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
        public ServerTransport? ServerTransport { get; }
        public Channel<ReadOnlyMemory<byte>> Channel { get; } = System.Threading.Channels.Channel.CreateUnbounded<ReadOnlyMemory<byte>>();

        private double _successChance;

        public ClientTransport(ServerTransport serverTransport, double successChance)
        {
            Endpoint = new IPEndPoint(IPAddress.Loopback, Port++);
            ServerTransport = serverTransport;
            ServerTransport.Clients[Endpoint] = this;
            _successChance = successChance;
        }

        public override async Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
        {
            if (ServerTransport is not null && Random.Shared.NextDouble() <= _successChance)
                await ServerTransport.Channel.Writer.WriteAsync((Endpoint, buffer), ct);
        }

        protected override async Task<YamabikoReceiveResult> ReceiveAsync(CancellationToken ct)
        {
            var result = await Channel.Reader.ReadAsync(ct);
            if (Random.Shared.NextDouble() <= _successChance)
                return new YamabikoReceiveResult(result, ServerTransport.Endpoint);
            else
                return new YamabikoReceiveResult(Array.Empty<byte>(), ServerTransport.Endpoint);
        }
    }

    public class ServerTransport : ITransport
    {
        public static IPEndPoint Endpoint { get; } = new IPEndPoint(IPAddress.Loopback, 59999);
        public Dictionary<IPEndPoint, ClientTransport> Clients { get; } = [];
        public Channel<(IPEndPoint, ReadOnlyMemory<byte>)> Channel { get; } = System.Threading.Channels.Channel.CreateUnbounded<(IPEndPoint, ReadOnlyMemory<byte>)>();

        public async Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
        {
            if (Clients.TryGetValue(endpoint, out var client))
                await client.Channel.Writer.WriteAsync(buffer, ct);
        }

        public async Task<TransportReceiveResult> ReceiveAsync(CancellationToken ct)
        {
            var result = await Channel.Reader.ReadAsync(ct);
            return new TransportReceiveResult(result.Item2, result.Item1);
        }

        public void Dispose() { }
    }
}
