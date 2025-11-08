using Kanawanagasaki.Yamabiko;
using Kanawanagasaki.Yamabiko.Shared.Enums;
using System.Diagnostics;
using System.Net;
using System.Text;

var projectId = Guid.Parse("7029bc66-f478-44cf-aaea-94d55d2365fb");
var rendezvousEndpoint = new IPEndPoint(IPAddress.Loopback, 9999);
var cts = new CancellationTokenSource();

Console.OutputEncoding = Encoding.UTF8;
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

try
{
    var isCreateRoom = IsCreateRoom();

    await using var client = new YamabikoClient(rendezvousEndpoint, projectId)
    {
        ValidateCertificatesCallback = _ => true
    };

    Console.Clear();
    Console.WriteLine("Connecting to rendezvous server...");

    await client.StartAsync();

    if (client.ConnectionState is not EConnectionState.CONNECTED)
        throw new Exception($"Failed to connect: {client.ConnectionState}");

    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("Successfully connected to rendezvous server");
    Console.ResetColor();

    var peer = isCreateRoom ? await CreateRoomAsync(client) : await JoinRoomAsync(client);

    var (localName, remoteName) = await InitializeChatNamesAsync(peer);

    await StartChatSessionAsync(peer, localName, remoteName);
}
catch (OperationCanceledException)
{
    Console.WriteLine("\nOperation canceled by user.");
}
catch (Exception ex)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Critical error: {ex.Message}");
    Console.ResetColor();
}
finally
{
    cts.Cancel();
    cts.Dispose();
}

bool IsCreateRoom()
{
    var isCreateRoom = true;
    while (true)
    {
        Console.Clear();
        Console.WriteLine("Yamabiko P2P Chat");
        Console.WriteLine(new string('-', 30));
        Console.WriteLine();

        Console.Write(isCreateRoom ? "→ " : "  ");
        Console.WriteLine("Create New Room");

        Console.Write(!isCreateRoom ? "→ " : "  ");
        Console.WriteLine("Join Existing Room");

        Console.WriteLine("\nUse arrow keys to navigate, Enter to select");

        var keyInfo = Console.ReadKey(true);
        switch (keyInfo.Key)
        {
            case ConsoleKey.UpArrow:
                isCreateRoom = true;
                break;
            case ConsoleKey.DownArrow:
                isCreateRoom = false;
                break;
            case ConsoleKey.Enter:
                return isCreateRoom;
            case ConsoleKey.Escape:
                throw new OperationCanceledException();
        }
    }
}

async Task<YamabikoPeer> CreateRoomAsync(YamabikoClient client)
{
    Console.Clear();
    Console.WriteLine("Create New Room");
    Console.WriteLine(new string('=', 40));

    Console.Write("Room name: ");
    var roomName = Console.ReadLine() ?? $"Room_{Random.Shared.Next(10000, 99999)}";

    Console.Write("Password (leave blank for no password): ");
    var password = Console.ReadLine();

    var advertisement = new Advertisement
    {
        Name = roomName,
        Password = string.IsNullOrWhiteSpace(password) ? null : password
    };

    Console.WriteLine();
    Console.WriteLine("Advertising room... ");
    await client.AdvertiseAsync(advertisement);

    Console.WriteLine("Waiting for connection...");
    var peer = await client.AcceptPeerAsync();

    if (peer is null)
        throw new Exception("Failed to accept peer");

    await CompletePeerConnectionAsync(peer);
    return peer;
}

async Task<YamabikoPeer> JoinRoomAsync(YamabikoClient client)
{
    const int pageSize = 5;
    ushort skip = 0;
    QueryResult? queryResult = null;
    int selection = 0;

    while (true)
    {
        Console.Clear();
        Console.WriteLine("Join Existing Room");
        Console.WriteLine(new string('-', 30));

        if (queryResult is null)
            queryResult = await client.QueryAsync(new Query { Skip = skip, Count = pageSize });

        if (queryResult.Total == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("No rooms found. Press any key to refresh or ESC to cancel");
            Console.ResetColor();

            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Escape)
                throw new OperationCanceledException();
            queryResult = null;
            continue;
        }

        for (int i = 0; i < queryResult.Count; i++)
        {
            var room = queryResult[i];

            if (room is null)
                Console.WriteLine();
            else
            {
                Console.Write((selection == i) ? "→ " : "  ");
                Console.Write($"{room.Index}. {room.Name}");
                Console.WriteLine(room.ProtectionLevel is EProtectionLevel.PASSWORD_PROTECTED ? " 🔒" : "");
            }
        }

        int optionIndex = queryResult.Count;
        bool hasPrevious = 0 < skip;
        bool hasNext = skip + pageSize < queryResult.Total;

        if (hasPrevious)
        {
            Console.WriteLine(selection == optionIndex ? "→ Previous Page" : "  Previous Page");
            optionIndex++;
        }

        if (hasNext)
        {
            Console.WriteLine(selection == optionIndex ? "→ Next Page" : "  Next Page");
            optionIndex++;
        }

        Console.WriteLine(selection == optionIndex ? "→ Refresh List" : "  Refresh List");
        Console.WriteLine("\nUse arrow keys to navigate, Enter to select, ESC to cancel");

        var keyInfo = Console.ReadKey(true);
        switch (keyInfo.Key)
        {
            case ConsoleKey.UpArrow:
                selection = Math.Max(0, selection - 1);
                break;
            case ConsoleKey.DownArrow:
                selection = Math.Min(optionIndex, selection + 1);
                break;
            case ConsoleKey.Enter:
                if (selection < queryResult.Count)
                {
                    var selectedRoom = queryResult[selection];
                    if (selectedRoom is not null)
                        return await ConnectToRoomAsync(client, selectedRoom);
                }
                else if (hasPrevious && selection == queryResult.Count)
                {
                    skip = (ushort)Math.Max(0, skip - pageSize);
                    queryResult = null;
                }
                else if (hasNext && selection == (queryResult.Count + (hasPrevious ? 1 : 0)))
                {
                    skip += pageSize;
                    queryResult = null;
                }
                else
                {
                    queryResult = null;
                }
                selection = 0;
                break;
            case ConsoleKey.Escape:
                throw new OperationCanceledException();
        }
    }
}

async Task<YamabikoPeer> ConnectToRoomAsync(YamabikoClient client, PeerInfo room)
{
    string? password = null;
    if (room.ProtectionLevel is EProtectionLevel.PASSWORD_PROTECTED)
    {
        Console.Write("\nEnter password for room: ");
        password = Console.ReadLine();
    }

    Console.WriteLine("\nResolving peer endpoint...");
    var peer = await client.ConnectAsync(room, password);
    await CompletePeerConnectionAsync(peer);
    return peer;
}

async Task CompletePeerConnectionAsync(YamabikoPeer peer)
{
    Console.WriteLine("Establishing connection...");
    await peer.WaitUntilConnectedAsync(TimeSpan.FromSeconds(30));

    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("Connection established successfully!");
    Console.ResetColor();
}

async Task<(string local, string remote)> InitializeChatNamesAsync(YamabikoPeer peer)
{
    Console.Clear();
    Console.WriteLine("Chat Session Started");
    Console.WriteLine(new string('-', 30));

    Console.Write("Name: ");
    var localName = Console.ReadLine() ?? "Anonymous";

    Console.WriteLine("\nExchanging participant names...");
    peer.SendReliable(Encoding.UTF8.GetBytes(localName));

    var remoteNameBytes = await peer.ReceiveReliableAsync();
    var remoteName = Encoding.UTF8.GetString(remoteNameBytes.Span);

    Console.WriteLine($"Connected with: {remoteName}\n");
    await Task.Delay(500);
    return (localName, remoteName);
}

async Task StartChatSessionAsync(YamabikoPeer peer, string localName, string remoteName)
{
    var messages = new List<(bool isLocal, string message)>();
    var currentInput = new StringBuilder();
    var renderLock = new object();

    RenderChatWindow(messages, currentInput.ToString(), localName, remoteName);

    var receiveTask = Task.Run(async () =>
    {
        while (!cts.IsCancellationRequested)
        {
            try
            {
                var buffer = await peer.ReceiveReliableAsync();
                var message = Encoding.UTF8.GetString(buffer.Span);

                lock (messages)
                {
                    messages.Add((false, message));
                    while (128 < messages.Count)
                        messages.RemoveAt(0);
                }

                lock (renderLock)
                    RenderChatWindow(messages, currentInput.ToString(), localName, remoteName);
            }
            catch
            {
                break;
            }
        }
    });

    try
    {
        Console.CursorVisible = false;
        while (!cts.IsCancellationRequested)
        {
            if (!Console.KeyAvailable)
            {
                await Task.Delay(10);
                continue;
            }

            var keyInfo = Console.ReadKey(true);
            switch (keyInfo.Key)
            {
                case ConsoleKey.Enter when 0 < currentInput.Length:
                    var message = currentInput.ToString();
                    peer.SendReliable(Encoding.UTF8.GetBytes(message));
                    lock (messages)
                    {
                        messages.Add((true, message));
                        while (128 < messages.Count)
                            messages.RemoveAt(0);
                    }
                    currentInput.Clear();
                    break;

                case ConsoleKey.Backspace when currentInput.Length > 0:
                    currentInput.Length--;
                    break;

                case ConsoleKey.Escape:
                    cts.Cancel();
                    break;

                default:
                    if (!char.IsControl(keyInfo.KeyChar) && keyInfo.KeyChar != '\0')
                        currentInput.Append(keyInfo.KeyChar);
                    break;
            }

            lock (renderLock)
                RenderChatWindow(messages, currentInput.ToString(), localName, remoteName);
        }
    }
    finally
    {
        Console.CursorVisible = true;
        await receiveTask;
    }
}

void RenderChatWindow(List<(bool isLocal, string message)> messages, string currentInput, string localName, string remoteName)
{
    int w = Console.WindowWidth;
    int h = Console.WindowHeight;
    var messageAreaHeight = h - 5;

    Console.SetCursorPosition(0, 0);
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.Write($" Chat with {remoteName} ".PadRight(w));
    Console.ResetColor();

    var lines = new List<string>();
    int lineIndex = 0;

    lock (messages)
    {
        for (int i = messages.Count - 1; 0 <= i && lineIndex < messageAreaHeight; i--)
        {
            var (isLocal, text) = messages[i];
            string name = isLocal ? localName : remoteName;
            string colorPrefix = isLocal ? $"\x1b[32m{name}\x1b[0m" : $"\x1b[36m{name}\x1b[0m";
            string line = $"{colorPrefix}: {text}";

            int visibleLineLength = name.Length + 2 + text.Length;

            while (visibleLineLength > w && lineIndex < messageAreaHeight)
            {
                int sublineVisibleLength = visibleLineLength;
                while (w < sublineVisibleLength)
                    sublineVisibleLength -= w;

                int count = 0;
                int actualSplitIndex = 0;

                while (actualSplitIndex < line.Length && count < sublineVisibleLength)
                {
                    if (line[actualSplitIndex] == '\x1b' && actualSplitIndex + 1 < line.Length && line[actualSplitIndex + 1] == '[')
                    {
                        int end = line.IndexOf('m', actualSplitIndex);
                        if (end == -1)
                            end = line.Length - 1;
                        actualSplitIndex = end + 1;
                    }
                    else
                    {
                        count++;
                        actualSplitIndex++;
                    }
                }

                string subline = line[^actualSplitIndex..];
                line = line[..^actualSplitIndex];
                visibleLineLength -= sublineVisibleLength;

                lines.Add(subline.PadRight(w));
                lineIndex++;
            }

            if (lineIndex < messageAreaHeight)
            {
                lines.Add(line.PadRight(w));
                lineIndex++;
            }
        }
    }

    while (lineIndex < messageAreaHeight)
    {
        lines.Add(new string(' ', w));
        lineIndex++;
    }

    lines.Reverse();

    for (int i = 0; i < messageAreaHeight; i++)
    {
        int y = i + 2;
        if (y >= h - 3) break;

        Console.SetCursorPosition(0, y);
        Console.Write(lines[i]);
    }

    Console.SetCursorPosition(0, h - 3);
    Console.Write(new string('─', w));

    Console.SetCursorPosition(0, h - 2);
    Console.ForegroundColor = ConsoleColor.Green;
    Console.Write($"{localName}: ");
    Console.ResetColor();
    if (currentInput.Length < w - localName.Length - 3)
        Console.Write(currentInput.PadRight(w - localName.Length - 3));
    else
        Console.Write(currentInput[^(w - localName.Length - 3)..]);

    Console.SetCursorPosition(0, h - 1);
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.Write(" ESC: Exit | ENTER: Send | BACKSPACE: Delete ".PadRight(w));
    Console.ResetColor();
}
