namespace Kanawanagasaki.Yamabiko.Sample;

using Kanawanagasaki.Yamabiko;
using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Tags;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;

public static class AppUi
{
    private enum EAppState
    {
        MainMenu,
        HostConfig,
        JoinConfig,
        JoinHostList,
        JoinName,
        Connected
    }

    private static EAppState _state = EAppState.MainMenu;
    private static EAppState _previousRenderState = (EAppState)(-1);
    private static bool _running = true;

    private static int _menuSelection;

    private static int _hostConfigFocusIndex;
    private static readonly List<Focusable> _hostConfigFocusables = [];
    private static InputField? _fieldHostName;
    private static InputField? _fieldServerIp, _fieldServerPort, _fieldProjectId, _fieldServerDomain;
    private static InputField? _fieldHostPassword;

    private static CheckBox? _checkReliableNoDelay, _checkStreamNoDelay;
    private static CheckBox? _checkReliableNoCwnd, _checkStreamNoCwnd;
    private static InputField? _fieldReliableInterval, _fieldReliableFastResend, _fieldReliableMtu;
    private static InputField? _fieldReliableSendWindow, _fieldReliableRecvWindow;
    private static InputField? _fieldStreamInterval, _fieldStreamFastResend, _fieldStreamMtu;
    private static InputField? _fieldStreamSendWindow, _fieldStreamRecvWindow;
    private static Button? _btnHostStart;

    private static int _joinConfigFocusIndex;
    private static readonly List<Focusable> _joinConfigFocusables = [];
    private static InputField? _fieldJoinServerIp, _fieldJoinServerPort, _fieldJoinProjectId, _fieldJoinServerDomain;
    private static Button? _btnJoinConnect;

    private static InputField? _fieldJoinPassword;

    private static int _hostListSelection;
    private static QueryResult? _queryResult;
    private static ushort _querySkip;
    private static bool _queryLoading;
    private static YamabikoClient? _joinClient;
    private static PeerInfo? _selectedHost;
    private static InputField? _fieldJoinName;
    private static int _joinNameFocusIndex;
    private static readonly List<Focusable> _joinNameFocusables = [];

    private static YamabikoPeer? _peer;
    private static YamabikoClient? _hostClient;
    private static bool _isHost;
    private static string _localName = "";
    private static string _remoteName = "";
    private static YamabikoKcpOptions _activeKcpOptions = new();
    private static int _connectedFocusIndex;
    private static readonly List<Focusable> _connectedFocusables = [];

    private static readonly List<string> _logLines = [];
    private static readonly Lock _logLock = new();
    private static int _logLineCount;
    private static readonly List<string> _pendingLogs = [];
    private static readonly Lock _pendingLogsLock = new();
    private static int _unreadLogCount;

    private static LogViewElement? _logView;
    private static CommandInputElement? _commandInput;
    private static Button? _btnQuit;

    private static bool _cursorVisible = true;
    private static long _lastCursorToggle;

    private static readonly List<string> _commandHistory = [];
    private static int _commandHistoryIndex = -1;
    private static string _currentSavedInput = "";
    private static string _hintText = "";

    private static long _transmittedMessages;
    private static long _receivedMessages;
    private static long _transmittedBytes;
    private static long _receivedBytes;
    private static DateTime _connectedSince;

    private const byte FrameTypeText = 0x01;
    private const byte FrameTypeStream = 0x03;
    private const int FrameHeaderSize = 1 + 4;
    private const int FrameHashSize = 32;

    private static CancellationTokenSource? _streamReceiveCts;
    private static Task? _streamReceiveTask;

    private static readonly (string Command, string Hint, string Usage)[] CommandHints =
    [
        ("/send", "Send text message", "/send <text>"),
        ("/stream", "Stream data for throughput test", "/stream <size>"),
        ("/ping", "Measure round-trip time", "/ping"),
        ("/disconnect", "Disconnect from peer", "/disconnect"),
        ("/help", "Show help", "/help"),
    ];

    private const int FullLayoutMinWidth = 96;
    private const int FullLayoutMinHeight = 26;
    private const int TopSectionHeight = 14;
    private const int ConfigFrameWidth = 64;

    private static AppSettings _settings = AppSettings.Load();



    private abstract class Focusable
    {
        public Func<bool> VisibilityCheck = () => true;
        public bool IsVisible => VisibilityCheck();
        public abstract void Draw(bool focused);
        public abstract bool HandleKey(ConsoleKeyInfo key);
    }

    private class InputField : Focusable
    {
        public int X, Y, Width;
        public string Text = "";
        public int CursorPos;
        private int _viewStart;

        private void EnsureCursorVisible()
        {
            if (Text.Length < Width) { _viewStart = 0; return; }
            if (CursorPos < _viewStart) _viewStart = CursorPos;
            else if (_viewStart + Width <= CursorPos) _viewStart = CursorPos - Width + 1;
            _viewStart = Math.Max(0, Math.Min(_viewStart, Text.Length - Width + 1));
        }

        public override void Draw(bool focused)
        {
            EnsureCursorVisible();
            var visibleText = _viewStart < Text.Length ? Text[_viewStart..] : "";
            var display = PadField(visibleText, Width);
            if (focused)
            {
                ConsoleBuffer.Write(X, Y, display, ConsoleColor.White, ConsoleColor.DarkCyan);
                var screenCursor = CursorPos - _viewStart;
                if (_cursorVisible && 0 <= screenCursor && screenCursor < Width)
                    ConsoleBuffer.Write(X + screenCursor, Y, "|", ConsoleColor.White, ConsoleColor.DarkCyan);
            }
            else
            {
                ConsoleBuffer.Write(X, Y, display, ConsoleColor.Gray, ConsoleColor.Black);
            }
        }

        public override bool HandleKey(ConsoleKeyInfo key)
        {
            switch (key.Key)
            {
                case ConsoleKey.LeftArrow:
                    if (0 < CursorPos) CursorPos--;
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.RightArrow:
                    if (CursorPos < Text.Length) CursorPos++;
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.Home:
                    CursorPos = 0;
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.End:
                    CursorPos = Text.Length;
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.Backspace:
                    if (0 < CursorPos) { Text = Text[..(CursorPos - 1)] + Text[CursorPos..]; CursorPos--; }
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.Delete:
                    if (CursorPos < Text.Length) Text = Text[..CursorPos] + Text[(CursorPos + 1)..];
                    ResetCursorBlink();
                    return true;
                default:
                    if (!char.IsControl(key.KeyChar))
                    {
                        if (CursorPos < Text.Length) { Text = Text[..CursorPos] + key.KeyChar + Text[(CursorPos + 1)..]; CursorPos++; }
                        else { Text += key.KeyChar; CursorPos++; }
                    }
                    ResetCursorBlink();
                    return key.KeyChar != '\0';
            }
        }

        private static string PadField(string text, int width)
        {
            if (width < text.Length) return text[..width];
            return text.PadRight(width);
        }
    }

    private class CheckBox : Focusable
    {
        public int X, Y;
        public string Label = "";
        public bool IsChecked;

        public override void Draw(bool focused)
        {
            var mark = IsChecked ? "V" : " ";
            var text = $"[{mark}]{Label}";
            if (focused)
                ConsoleBuffer.Write(X, Y, text, ConsoleColor.Yellow, ConsoleColor.DarkCyan);
            else
                ConsoleBuffer.Write(X, Y, text, ConsoleColor.Gray, ConsoleColor.Black);
        }

        public override bool HandleKey(ConsoleKeyInfo key)
        {
            if (key.Key == ConsoleKey.Spacebar || key.Key == ConsoleKey.Enter)
            {
                IsChecked = !IsChecked;
                return true;
            }
            return false;
        }
    }

    private class Button : Focusable
    {
        public int X, Y;
        public string Label = "";
        public Action? OnActivate;

        public override void Draw(bool focused)
        {
            var text = $"[{Label}]";
            var fg = focused ? ConsoleColor.Black : ConsoleColor.White;
            var bg = focused ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
            ConsoleBuffer.Write(X, Y, text, fg, bg);
        }

        public override bool HandleKey(ConsoleKeyInfo key)
        {
            if (key.Key == ConsoleKey.Enter || key.Key == ConsoleKey.Spacebar)
            {
                OnActivate?.Invoke();
                return true;
            }
            return false;
        }
    }

    private class LogViewElement : Focusable
    {
        public int X, Y, Width, Height;
        public int ScrollOffset;

        public override void Draw(bool focused)
        {
            ClampScrollOffset();
            var fg = focused ? ConsoleColor.Cyan : ConsoleColor.Gray;
            ConsoleBuffer.DrawBox(X, Y, Width, Height, fg);
            ConsoleBuffer.Write(X + 2, Y, " Log ", fg);

            var contentX = X + 1;
            var contentY = Y + 1;
            var contentWidth = Width - 2;
            var contentHeight = Height - 2;

            List<string> lines;
            lock (_logLock) lines = [.. _logLines];

            var totalLines = lines.Count;
            var visibleLines = contentHeight;
            var startLine = totalLines <= visibleLines ? 0 : Math.Max(0, totalLines - visibleLines - ScrollOffset);
            var endLine = Math.Min(totalLines, startLine + visibleLines);

            for (int i = 0; i < contentHeight; i++)
            {
                var lineIndex = startLine + i;
                string line;
                if (lineIndex < endLine && lineIndex < totalLines)
                {
                    var rawLine = lines[lineIndex];
                    line = contentWidth < rawLine.Length ? rawLine[..contentWidth] : rawLine.PadRight(contentWidth);
                }
                else
                {
                    line = new string(' ', contentWidth);
                }

                var lineFg = ConsoleColor.Gray;
                if (line.Contains("[SENT]") || line.Contains("[STREAM TX]")) lineFg = ConsoleColor.Green;
                else if (line.Contains("[RECV]") || line.Contains("[STREAM RX]")) lineFg = ConsoleColor.Cyan;
                else if (line.Contains("MISMATCH")) lineFg = ConsoleColor.Red;
                else if (line.Contains("ERR") || line.Contains("FAIL") || line.Contains("DENY")) lineFg = ConsoleColor.Red;
                else if (line.Contains("CONNECTED")) lineFg = ConsoleColor.Green;
                else if (line.Contains("DISCONNECT")) lineFg = ConsoleColor.Yellow;

                ConsoleBuffer.Write(contentX, contentY + i, line, lineFg, ConsoleColor.Black);
            }

            if (0 < _unreadLogCount && 0 < ScrollOffset)
            {
                var counterText = $" {_unreadLogCount} new ";
                var counterX = X + Width - counterText.Length - 2;
                var counterY = Y + Height - 1;
                if (X + 6 < counterX)
                    ConsoleBuffer.Write(counterX, counterY, counterText, ConsoleColor.Black, ConsoleColor.Yellow);
            }
        }

        public void ClampScrollOffset()
        {
            int visibleLines = Height - 2;
            int maxScroll;
            lock (_logLock) maxScroll = Math.Max(0, _logLines.Count - visibleLines);
            if (maxScroll < ScrollOffset) ScrollOffset = maxScroll;
        }

        public override bool HandleKey(ConsoleKeyInfo key)
        {
            int visibleLines = Height - 2;
            int maxScroll;
            lock (_logLock) maxScroll = Math.Max(0, _logLines.Count - visibleLines);

            switch (key.Key)
            {
                case ConsoleKey.UpArrow:
                    if (ScrollOffset < maxScroll) ScrollOffset++;
                    return true;
                case ConsoleKey.DownArrow:
                    if (0 < ScrollOffset) ScrollOffset--;
                    if (ScrollOffset == 0) _unreadLogCount = 0;
                    return true;
                case ConsoleKey.PageUp:
                    ScrollOffset = Math.Min(ScrollOffset + visibleLines, maxScroll);
                    return true;
                case ConsoleKey.PageDown:
                    ScrollOffset = Math.Max(ScrollOffset - visibleLines, 0);
                    if (ScrollOffset == 0) _unreadLogCount = 0;
                    return true;
                case ConsoleKey.Home:
                    ScrollOffset = maxScroll;
                    return true;
                case ConsoleKey.End:
                    ScrollOffset = 0;
                    _unreadLogCount = 0;
                    return true;
            }
            return false;
        }
    }

    private class CommandInputElement : Focusable
    {
        public int X, Y, Width;
        public string Text = "";
        public int CursorPos;
        public Action? OnSubmit;
        private int _viewStart;

        public int FieldWidth => Width - 12;

        private void EnsureCursorVisible()
        {
            var fw = FieldWidth;
            if (Text.Length < fw) { _viewStart = 0; return; }
            if (CursorPos < _viewStart) _viewStart = CursorPos;
            else if (_viewStart + fw <= CursorPos) _viewStart = CursorPos - fw + 1;
            _viewStart = Math.Max(0, Math.Min(_viewStart, Text.Length - fw + 1));
        }

        public override void Draw(bool focused)
        {
            EnsureCursorVisible();
            ConsoleBuffer.Write(X, Y, "Cmd> ", ConsoleColor.Yellow, ConsoleColor.Black);
            var fieldX = X + 5;
            var fw = FieldWidth;
            var visibleText = _viewStart < Text.Length ? Text[_viewStart..] : "";
            var display = fw <= visibleText.Length ? visibleText[..fw] : visibleText.PadRight(fw);

            if (focused)
            {
                ConsoleBuffer.Write(fieldX, Y, display, ConsoleColor.White, ConsoleColor.DarkCyan);
                var screenCursor = CursorPos - _viewStart;
                if (_cursorVisible && 0 <= screenCursor && screenCursor < fw)
                    ConsoleBuffer.Write(fieldX + screenCursor, Y, "|", ConsoleColor.White, ConsoleColor.DarkCyan);
            }
            else
            {
                ConsoleBuffer.Write(fieldX, Y, display, ConsoleColor.Gray, ConsoleColor.Black);
            }

            var sendX = X + Width - 7;
            var sendFg = focused ? ConsoleColor.Black : ConsoleColor.White;
            var sendBg = focused ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
            ConsoleBuffer.Write(sendX, Y, "[Send]", sendFg, sendBg);
        }

        public override bool HandleKey(ConsoleKeyInfo key)
        {
            if (key.Key == ConsoleKey.Enter) { OnSubmit?.Invoke(); return true; }
            var fw = FieldWidth;

            switch (key.Key)
            {
                case ConsoleKey.UpArrow:
                    if (0 < _commandHistory.Count)
                    {
                        if (_commandHistoryIndex < 0) { _currentSavedInput = Text; _commandHistoryIndex = _commandHistory.Count - 1; }
                        else if (0 < _commandHistoryIndex) _commandHistoryIndex--;
                        Text = _commandHistory[_commandHistoryIndex];
                        CursorPos = Text.Length;
                    }
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.DownArrow:
                    if (0 <= _commandHistoryIndex)
                    {
                        _commandHistoryIndex++;
                        if (_commandHistory.Count <= _commandHistoryIndex) { _commandHistoryIndex = -1; Text = _currentSavedInput; }
                        else Text = _commandHistory[_commandHistoryIndex];
                        CursorPos = Text.Length;
                    }
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.LeftArrow:
                    _commandHistoryIndex = -1;
                    if (0 < CursorPos) CursorPos--;
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.RightArrow:
                    _commandHistoryIndex = -1;
                    if (CursorPos < Text.Length) CursorPos++;
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.Home:
                    _commandHistoryIndex = -1; CursorPos = 0; ResetCursorBlink();
                    return true;
                case ConsoleKey.End:
                    _commandHistoryIndex = -1; CursorPos = Text.Length; ResetCursorBlink();
                    return true;
                case ConsoleKey.Backspace:
                    _commandHistoryIndex = -1;
                    if (0 < CursorPos) { Text = Text[..(CursorPos - 1)] + Text[CursorPos..]; CursorPos--; }
                    ResetCursorBlink();
                    return true;
                case ConsoleKey.Delete:
                    _commandHistoryIndex = -1;
                    if (CursorPos < Text.Length) Text = Text[..CursorPos] + Text[(CursorPos + 1)..];
                    ResetCursorBlink();
                    return true;
                default:
                    if (!char.IsControl(key.KeyChar))
                    {
                        _commandHistoryIndex = -1;
                        if (CursorPos < Text.Length) { Text = Text[..CursorPos] + key.KeyChar + Text[(CursorPos + 1)..]; CursorPos++; }
                        else { Text += key.KeyChar; CursorPos++; }
                    }
                    ResetCursorBlink();
                    return key.KeyChar != '\0';
            }
        }
    }



    public static async Task RunAsync()
    {
        ConsoleBuffer.Initialize();
        ConsoleBuffer.Clear();
        _lastCursorToggle = Environment.TickCount64;

        try
        {
            while (_running)
            {
                try
                {
                    ConsoleBuffer.CheckResize();

                    var now = Environment.TickCount64;
                    if (530 < now - _lastCursorToggle) { _cursorVisible = !_cursorVisible; _lastCursorToggle = now; }

                    while (Console.KeyAvailable)
                    {
                        try
                        {
                            var key = Console.ReadKey(true);
                            HandleKey(key);
                        }
                        catch (InvalidOperationException)
                        {
                            // Console input can fail during resize
                        }
                    }

                    FlushPendingLogs();

                    try
                    {
                        RenderAll();
                        ConsoleBuffer.Render();
                    }
                    catch (Exception)
                    {
                        ConsoleBuffer.CheckResize();
                    }
                }
                catch (Exception)
                {
                    // Catch any transient errors (resize, console not available, etc.)
                    // and keep the loop alive
                    try { ConsoleBuffer.CheckResize(); } catch { }
                }

                await Task.Delay(50);
            }
        }
        finally
        {
            ConsoleBuffer.ResetColors();
            Console.CursorVisible = true;
        }

        // Cleanup
        if (_peer is not null)
        {
            try { await _peer.DisconnectAsync(); } catch { }
            await _peer.DisposeAsync();
        }
        if (_hostClient is not null) { try { await _hostClient.DisposeAsync(); } catch { } }
        if (_joinClient is not null) { try { await _joinClient.DisposeAsync(); } catch { } }
    }

    private static void ResetCursorBlink()
    {
        _cursorVisible = true;
        _lastCursorToggle = Environment.TickCount64;
    }



    private static void HandleKey(ConsoleKeyInfo key)
    {
        if (key.Modifiers.HasFlag(ConsoleModifiers.Control) && !key.Modifiers.HasFlag(ConsoleModifiers.Alt))
        {
            if (key.Key == ConsoleKey.Q) { _running = false; return; }
            if (key.Key == ConsoleKey.L) { ClearLog(); return; }
        }

        if (key.Key == ConsoleKey.Escape)
        {
            if (_state == EAppState.Connected)
            {
                _ = DisconnectAndReturnToMenuAsync();
                return;
            }
            if (_state == EAppState.HostConfig || _state == EAppState.JoinConfig ||
                _state == EAppState.JoinHostList || _state == EAppState.JoinName)
            {
                // If we have an active join client, clean it up
                if (_state == EAppState.JoinHostList || _state == EAppState.JoinName)
                {
                    if (_joinClient is not null)
                    {
                        try { _joinClient.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(2)); } catch { }
                        _joinClient = null;
                    }
                }
                _state = EAppState.MainMenu;
                return;
            }
        }

        switch (_state)
        {
            case EAppState.MainMenu: HandleMainMenuKey(key); break;
            case EAppState.HostConfig: HandleHostConfigKey(key); break;
            case EAppState.JoinConfig: HandleJoinConfigKey(key); break;
            case EAppState.JoinHostList: HandleJoinHostListKey(key); break;
            case EAppState.JoinName: HandleJoinNameKey(key); break;
            case EAppState.Connected: HandleConnectedKey(key); break;
        }
    }

    private static void HandleMainMenuKey(ConsoleKeyInfo key)
    {
        switch (key.Key)
        {
            case ConsoleKey.UpArrow:
                _menuSelection = Math.Max(0, _menuSelection - 1);
                break;
            case ConsoleKey.DownArrow:
                _menuSelection = Math.Min(2, _menuSelection + 1);
                break;
            case ConsoleKey.Enter:
                switch (_menuSelection)
                {
                    case 0: StartHostConfig(); break;
                    case 1: StartJoinConfig(); break;
                    case 2: _running = false; break;
                }
                break;
        }
    }

    private static void HandleHostConfigKey(ConsoleKeyInfo key)
    {
        if (key.Key == ConsoleKey.Tab)
        {
            var direction = key.Modifiers.HasFlag(ConsoleModifiers.Shift) ? -1 : 1;
            NavigateFocus(_hostConfigFocusables, ref _hostConfigFocusIndex, direction);
            return;
        }

        if (0 <= _hostConfigFocusIndex && _hostConfigFocusIndex < _hostConfigFocusables.Count)
        {
            var focused = _hostConfigFocusables[_hostConfigFocusIndex];
            if (focused.IsVisible) focused.HandleKey(key);
        }
    }

    private static void HandleJoinConfigKey(ConsoleKeyInfo key)
    {
        if (key.Key == ConsoleKey.Tab)
        {
            var direction = key.Modifiers.HasFlag(ConsoleModifiers.Shift) ? -1 : 1;
            NavigateFocus(_joinConfigFocusables, ref _joinConfigFocusIndex, direction);
            return;
        }

        if (0 <= _joinConfigFocusIndex && _joinConfigFocusIndex < _joinConfigFocusables.Count)
        {
            var focused = _joinConfigFocusables[_joinConfigFocusIndex];
            if (focused.IsVisible) focused.HandleKey(key);
        }
    }

    private static void HandleJoinHostListKey(ConsoleKeyInfo key)
    {
        if (_queryResult is null || _queryResult.Total == 0)
        {
            if (key.Key == ConsoleKey.Enter || key.Key == ConsoleKey.F5)
                _ = RefreshHostListAsync();
            return;
        }

        var totalOptions = _queryResult.Count;
        var hasPrevious = 0 < _querySkip;
        var hasNext = _querySkip + 5 < _queryResult.Total;
        if (hasPrevious) totalOptions++;
        if (hasNext) totalOptions++;
        totalOptions++; // Refresh

        switch (key.Key)
        {
            case ConsoleKey.UpArrow:
                _hostListSelection = Math.Max(0, _hostListSelection - 1);
                break;
            case ConsoleKey.DownArrow:
                _hostListSelection = Math.Min(totalOptions - 1, _hostListSelection + 1);
                break;
            case ConsoleKey.Enter:
                _ = SelectHostAsync(_hostListSelection);
                break;
            case ConsoleKey.F5:
                _ = RefreshHostListAsync();
                break;
        }
    }

    private static void HandleJoinNameKey(ConsoleKeyInfo key)
    {
        if (key.Key == ConsoleKey.Tab)
        {
            NavigateFocus(_joinNameFocusables, ref _joinNameFocusIndex, 1);
            return;
        }

        if (0 <= _joinNameFocusIndex && _joinNameFocusIndex < _joinNameFocusables.Count)
        {
            var focused = _joinNameFocusables[_joinNameFocusIndex];
            if (focused.IsVisible) focused.HandleKey(key);
        }
    }

    private static void HandleConnectedKey(ConsoleKeyInfo key)
    {
        if (key.Key == ConsoleKey.Tab)
        {
            var direction = key.Modifiers.HasFlag(ConsoleModifiers.Shift) ? -1 : 1;
            NavigateFocus(_connectedFocusables, ref _connectedFocusIndex, direction);
            return;
        }

        if (0 <= _connectedFocusIndex && _connectedFocusIndex < _connectedFocusables.Count)
        {
            var focused = _connectedFocusables[_connectedFocusIndex];
            if (focused.IsVisible) focused.HandleKey(key);
        }

        if (_commandInput is not null)
            UpdateCommandHint(_commandInput.Text);
    }

    private static void NavigateFocus(List<Focusable> focusables, ref int focusIndex, int direction)
    {
        if (focusables.Count == 0) return;
        var startIndex = focusIndex;
        var tries = focusables.Count;
        do
        {
            focusIndex = (focusIndex + direction + focusables.Count) % focusables.Count;
            if (focusables[focusIndex].IsVisible) return;
            tries--;
        }
        while (0 < tries && focusIndex != startIndex);
    }



    private static void StartHostConfig()
    {
        _hostConfigFocusables.Clear();
        _hostConfigFocusIndex = 0;

        var baseX = 1;
        var baseY = 2;
        int row = 0;

        // Row 0: Server heading (drawn in render, not focusable)
        // Row 1: IP + Port
        row = 1;
        _fieldServerIp = new InputField { X = baseX + 12, Y = baseY + row, Width = 20, Text = _settings.ServerIp };
        _hostConfigFocusables.Add(_fieldServerIp);

        _fieldServerPort = new InputField { X = baseX + 40, Y = baseY + row, Width = 6, Text = _settings.ServerPort.ToString() };
        _hostConfigFocusables.Add(_fieldServerPort);

        // Row 2: Domain
        row = 2;
        _fieldServerDomain = new InputField { X = baseX + 12, Y = baseY + row, Width = 32, Text = _settings.ServerDomain };
        _hostConfigFocusables.Add(_fieldServerDomain);

        // Row 3: ProjectID
        row = 3;
        _fieldProjectId = new InputField { X = baseX + 12, Y = baseY + row, Width = 36, Text = _settings.ProjectId };
        _hostConfigFocusables.Add(_fieldProjectId);

        // Row 4: HostName
        row = 4;
        var defaultHostName = string.IsNullOrEmpty(_settings.HostName) ? string.Empty : _settings.HostName;
        _fieldHostName = new InputField { X = baseX + 12, Y = baseY + row, Width = 36, Text = defaultHostName };
        _hostConfigFocusables.Add(_fieldHostName);

        // Row 5: Password (optional, for password-protected rooms)
        row = 5;
        _fieldHostPassword = new InputField { X = baseX + 12, Y = baseY + row, Width = 36, Text = _settings.HostPassword };
        _hostConfigFocusables.Add(_fieldHostPassword);

        // Row 7: KCP Reliable heading (drawn in render)
        // Row 8: Reliable checkboxes
        row = 8;
        _checkReliableNoDelay = new CheckBox { X = baseX + 1, Y = baseY + row, Label = "RND", IsChecked = _settings.ReliableNoDelay };
        _hostConfigFocusables.Add(_checkReliableNoDelay);
        _checkReliableNoCwnd = new CheckBox { X = baseX + 14, Y = baseY + row, Label = "RNoCwnd", IsChecked = _settings.ReliableNoCongestionControl };
        _hostConfigFocusables.Add(_checkReliableNoCwnd);

        // Row 9: Reliable params
        row = 9;
        _fieldReliableInterval = new InputField { X = baseX + 4, Y = baseY + row, Width = 6, Text = _settings.ReliableIntervalMs.ToString() };
        _hostConfigFocusables.Add(_fieldReliableInterval);
        _fieldReliableFastResend = new InputField { X = baseX + 16, Y = baseY + row, Width = 4, Text = _settings.ReliableFastResend.ToString() };
        _hostConfigFocusables.Add(_fieldReliableFastResend);
        _fieldReliableMtu = new InputField { X = baseX + 27, Y = baseY + row, Width = 6, Text = _settings.ReliableMtu.ToString() };
        _hostConfigFocusables.Add(_fieldReliableMtu);
        _fieldReliableSendWindow = new InputField { X = baseX + 41, Y = baseY + row, Width = 5, Text = _settings.ReliableSendWindowSize.ToString() };
        _hostConfigFocusables.Add(_fieldReliableSendWindow);
        _fieldReliableRecvWindow = new InputField { X = baseX + 53, Y = baseY + row, Width = 5, Text = _settings.ReliableRecvWindowSize.ToString() };
        _hostConfigFocusables.Add(_fieldReliableRecvWindow);

        // Row 11: KCP Stream heading (drawn in render)
        // Row 12: Stream checkboxes
        row = 12;
        _checkStreamNoDelay = new CheckBox { X = baseX + 1, Y = baseY + row, Label = "SND", IsChecked = _settings.StreamNoDelay };
        _hostConfigFocusables.Add(_checkStreamNoDelay);
        _checkStreamNoCwnd = new CheckBox { X = baseX + 14, Y = baseY + row, Label = "SNoCwnd", IsChecked = _settings.StreamNoCongestionControl };
        _hostConfigFocusables.Add(_checkStreamNoCwnd);

        // Row 13: Stream params
        row = 13;
        _fieldStreamInterval = new InputField { X = baseX + 4, Y = baseY + row, Width = 6, Text = _settings.StreamIntervalMs.ToString() };
        _hostConfigFocusables.Add(_fieldStreamInterval);
        _fieldStreamFastResend = new InputField { X = baseX + 16, Y = baseY + row, Width = 4, Text = _settings.StreamFastResend.ToString() };
        _hostConfigFocusables.Add(_fieldStreamFastResend);
        _fieldStreamMtu = new InputField { X = baseX + 27, Y = baseY + row, Width = 6, Text = _settings.StreamMtu.ToString() };
        _hostConfigFocusables.Add(_fieldStreamMtu);
        _fieldStreamSendWindow = new InputField { X = baseX + 41, Y = baseY + row, Width = 5, Text = _settings.StreamSendWindowSize.ToString() };
        _hostConfigFocusables.Add(_fieldStreamSendWindow);
        _fieldStreamRecvWindow = new InputField { X = baseX + 53, Y = baseY + row, Width = 5, Text = _settings.StreamRecvWindowSize.ToString() };
        _hostConfigFocusables.Add(_fieldStreamRecvWindow);

        // Row 15: Start Hosting button
        row = 15;
        _btnHostStart = new Button { X = baseX + 1, Y = baseY + row, Label = "Start Hosting", OnActivate = () => _ = StartHostingAsync() };
        _hostConfigFocusables.Add(_btnHostStart);

        _state = EAppState.HostConfig;
    }

    private static void StartJoinConfig()
    {
        _joinConfigFocusables.Clear();
        _joinConfigFocusIndex = 0;

        var baseX = 1;
        var baseY = 2;
        int row = 1;

        _fieldJoinServerIp = new InputField { X = baseX + 12, Y = baseY + row, Width = 20, Text = _settings.ServerIp };
        _joinConfigFocusables.Add(_fieldJoinServerIp);

        _fieldJoinServerPort = new InputField { X = baseX + 40, Y = baseY + row, Width = 6, Text = _settings.ServerPort.ToString() };
        _joinConfigFocusables.Add(_fieldJoinServerPort);

        row = 2;
        _fieldJoinServerDomain = new InputField { X = baseX + 12, Y = baseY + row, Width = 32, Text = _settings.ServerDomain };
        _joinConfigFocusables.Add(_fieldJoinServerDomain);

        row = 3;
        _fieldJoinProjectId = new InputField { X = baseX + 12, Y = baseY + row, Width = 36, Text = _settings.ProjectId };
        _joinConfigFocusables.Add(_fieldJoinProjectId);

        row = 5;
        _btnJoinConnect = new Button { X = baseX + 1, Y = baseY + row, Label = "Connect to Server", OnActivate = () => _ = StartJoinHostListAsync() };
        _joinConfigFocusables.Add(_btnJoinConnect);

        _state = EAppState.JoinConfig;
    }

    private static YamabikoKcpOptions BuildKcpOptionsFromFields()
    {
        return new YamabikoKcpOptions
        {
            ReliableNoDelay = _checkReliableNoDelay?.IsChecked ?? _settings.ReliableNoDelay,
            ReliableIntervalMs = GetFieldInt(_fieldReliableInterval, _settings.ReliableIntervalMs),
            ReliableFastResend = GetFieldInt(_fieldReliableFastResend, _settings.ReliableFastResend),
            ReliableNoCongestionControl = _checkReliableNoCwnd?.IsChecked ?? _settings.ReliableNoCongestionControl,
            ReliableSendWindowSize = GetFieldInt(_fieldReliableSendWindow, _settings.ReliableSendWindowSize),
            ReliableRecvWindowSize = GetFieldInt(_fieldReliableRecvWindow, _settings.ReliableRecvWindowSize),
            ReliableMtu = GetFieldInt(_fieldReliableMtu, _settings.ReliableMtu),
            StreamNoDelay = _checkStreamNoDelay?.IsChecked ?? _settings.StreamNoDelay,
            StreamIntervalMs = GetFieldInt(_fieldStreamInterval, _settings.StreamIntervalMs),
            StreamFastResend = GetFieldInt(_fieldStreamFastResend, _settings.StreamFastResend),
            StreamNoCongestionControl = _checkStreamNoCwnd?.IsChecked ?? _settings.StreamNoCongestionControl,
            StreamSendWindowSize = GetFieldInt(_fieldStreamSendWindow, _settings.StreamSendWindowSize),
            StreamRecvWindowSize = GetFieldInt(_fieldStreamRecvWindow, _settings.StreamRecvWindowSize),
            StreamMtu = GetFieldInt(_fieldStreamMtu, _settings.StreamMtu),
        };
    }

    private static async Task StartHostingAsync()
    {
        var kcpOptions = BuildKcpOptionsFromFields();
        var serverIp = GetFieldValue(_fieldServerIp, _settings.ServerIp).Trim();
        var serverPort = GetFieldInt(_fieldServerPort, _settings.ServerPort);
        var serverDomain = GetFieldValue(_fieldServerDomain, _settings.ServerDomain).Trim();
        var projectIdStr = GetFieldValue(_fieldProjectId, _settings.ProjectId);
        var hostName = GetFieldValue(_fieldHostName, $"Host_{Random.Shared.Next(1000, 9999)}");
        var hostPassword = GetFieldValue(_fieldHostPassword, "").Trim();

        if (!Guid.TryParse(projectIdStr, out var projectId))
        {
            Log("Invalid Project ID format");
            return;
        }

        // Resolve IP address: use direct IP if provided, otherwise resolve domain
        string? certificateDomain = string.IsNullOrWhiteSpace(serverDomain) ? null : serverDomain;
        IPAddress ipAddr;

        if (!string.IsNullOrWhiteSpace(serverIp) && IPAddress.TryParse(serverIp, out var parsedIp))
        {
            ipAddr = parsedIp;
        }
        else if (!string.IsNullOrWhiteSpace(serverDomain))
        {
            Log($"Resolving domain '{serverDomain}'...");
            try
            {
                var addresses = await System.Net.Dns.GetHostAddressesAsync(serverDomain);
                if (addresses.Length == 0)
                {
                    Log($"Failed to resolve domain '{serverDomain}': no addresses found");
                    return;
                }
                ipAddr = addresses[0];
                Log($"Resolved to {ipAddr}");
            }
            catch (Exception ex)
            {
                Log($"Failed to resolve domain '{serverDomain}': {ex.Message}");
                return;
            }
        }
        else
        {
            Log("Either IP address or Domain must be provided");
            return;
        }

        // Save settings before connecting
        _settings = AppSettings.FromKcpOptions(kcpOptions, serverIp, serverPort, serverDomain, projectIdStr, hostName, _settings.JoinName, hostPassword);
        _settings.Save();

        var serverEndpoint = new IPEndPoint(ipAddr, serverPort);
        _localName = hostName;
        _isHost = true;
        _activeKcpOptions = kcpOptions;

        Log($"Connecting to rendezvous server {serverEndpoint}...");

        try
        {
            _hostClient = new YamabikoClient(serverEndpoint, projectId, kcpOptions)
            {
                CertificateDomain = certificateDomain,
                ValidateCertificatesCallback = _ => true
            };

            await _hostClient.StartAsync();

            if (_hostClient.ConnectionState is not EConnectionState.CONNECTED)
            {
                Log($"Failed to connect to rendezvous server: {_hostClient.ConnectionState}");
                try { await _hostClient.DisposeAsync(); } catch { }
                _hostClient = null;
                return;
            }

            Log("Connected to rendezvous server");

            var advertisement = new Advertisement
            {
                Name = hostName,
                Password = string.IsNullOrWhiteSpace(hostPassword) ? null : hostPassword,
                Tags = KcpTagCodec.ToTags(kcpOptions).ToList()
            };

            await _hostClient.AdvertiseAsync(advertisement);
            Log($"Advertising as '{hostName}' with KCP settings...");

            await _hostClient.SubscribeAsync();

            // Transition to connected state and wait for peer
            BuildConnectedLayout();
            _state = EAppState.Connected;

            _ = Task.Run(async () =>
            {
                try
                {
                    Log("Waiting for incoming connection...");
                    var peer = await _hostClient.AcceptPeerAsync();
                    if (peer is null)
                    {
                        Log("Failed to accept peer");
                        return;
                    }

                    await peer.WaitUntilConnectedAsync(TimeSpan.FromSeconds(30));
                    _peer = peer;
                    _connectedSince = DateTime.Now;

                    Log("Peer connected! Exchanging names...");

                    // Exchange names
                    peer.SendReliable(Encoding.UTF8.GetBytes(_localName));
                    var remoteNameBytes = await peer.ReceiveReliableAsync();
                    _remoteName = Encoding.UTF8.GetString(remoteNameBytes.Span);

                    Log($"Connected with: {_remoteName}");

                    // Start receive loops
                    _ = ReceiveLoopAsync();
                    StartStreamReceiveLoop();
                }
                catch (Exception ex)
                {
                    Log($"Host accept error: {ex.Message}");
                }
            });
        }
        catch (Exception ex)
        {
            Log($"Connection error: {ex.Message}");
            if (_hostClient is not null)
            {
                try { await _hostClient.DisposeAsync(); } catch { }
                _hostClient = null;
            }
            // Stay on HostConfig screen so user can retry
        }
    }

    private static async Task StartJoinHostListAsync()
    {
        // Read server details from join config fields
        var serverIp = GetFieldValue(_fieldJoinServerIp, _settings.ServerIp).Trim();
        var serverPort = GetFieldInt(_fieldJoinServerPort, _settings.ServerPort);
        var serverDomain = GetFieldValue(_fieldJoinServerDomain, _settings.ServerDomain).Trim();
        var projectIdStr = GetFieldValue(_fieldJoinProjectId, _settings.ProjectId);

        if (!Guid.TryParse(projectIdStr, out var projectId))
        {
            Log("Invalid Project ID format");
            return;
        }

        // Resolve IP address: use direct IP if provided, otherwise resolve domain
        string? certificateDomain = string.IsNullOrWhiteSpace(serverDomain) ? null : serverDomain;
        IPAddress ipAddr;

        if (!string.IsNullOrWhiteSpace(serverIp) && IPAddress.TryParse(serverIp, out var parsedIp))
        {
            ipAddr = parsedIp;
        }
        else if (!string.IsNullOrWhiteSpace(serverDomain))
        {
            Log($"Resolving domain '{serverDomain}'...");
            try
            {
                var addresses = await System.Net.Dns.GetHostAddressesAsync(serverDomain);
                if (addresses.Length == 0)
                {
                    Log($"Failed to resolve domain '{serverDomain}': no addresses found");
                    return;
                }
                ipAddr = addresses[0];
                Log($"Resolved to {ipAddr}");
            }
            catch (Exception ex)
            {
                Log($"Failed to resolve domain '{serverDomain}': {ex.Message}");
                return;
            }
        }
        else
        {
            Log("Either IP address or Domain must be provided");
            return;
        }

        // Save server settings before connecting
        _settings.ServerIp = serverIp;
        _settings.ServerPort = serverPort;
        _settings.ServerDomain = serverDomain;
        _settings.ProjectId = projectIdStr;
        _settings.Save();

        _hostListSelection = 0;
        _querySkip = 0;
        _queryResult = null;
        _queryLoading = false;

        var serverEndpoint = new IPEndPoint(ipAddr, serverPort);

        Log($"Connecting to rendezvous server {serverEndpoint}...");

        try
        {
            _joinClient = new YamabikoClient(serverEndpoint, projectId)
            {
                CertificateDomain = certificateDomain,
                ValidateCertificatesCallback = _ => true
            };

            await _joinClient.StartAsync();

            if (_joinClient.ConnectionState is not EConnectionState.CONNECTED)
            {
                Log($"Failed to connect to rendezvous server: {_joinClient.ConnectionState}");
                try { await _joinClient.DisposeAsync(); } catch { }
                _joinClient = null;
                return;
            }

            Log("Connected to rendezvous server");
            _state = EAppState.JoinHostList;

            await _joinClient.SubscribeAsync();
            await RefreshHostListAsync();
        }
        catch (Exception ex)
        {
            Log($"Connection error: {ex.Message}");
            if (_joinClient is not null)
            {
                try { await _joinClient.DisposeAsync(); } catch { }
                _joinClient = null;
            }
            // Stay on JoinConfig screen so user can retry
        }
    }

    private static async Task RefreshHostListAsync()
    {
        if (_joinClient is null) return;
        _queryLoading = true;
        _hostListSelection = 0;
        try
        {
            _queryResult = await _joinClient.QueryAsync(new Query { Skip = _querySkip, Count = 5 });
            _queryLoading = false;
        }
        catch (Exception ex)
        {
            Log($"Query error: {ex.Message}");
            _queryLoading = false;
        }
    }

    private static async Task SelectHostAsync(int selection)
    {
        if (_queryResult is null || _queryResult.Total == 0) return;

        var hasPrevious = 0 < _querySkip;
        var hasNext = _querySkip + 5 < _queryResult.Total;

        if (selection < _queryResult.Count)
        {
            var host = _queryResult[selection];
            if (host is null) return;
            _selectedHost = host;

            // Extract KCP options from tags
            var kcpOptions = KcpTagCodec.FromTags(host.Tags);
            _activeKcpOptions = kcpOptions;

            Log($"Selected host: {host.Name}");
            Log($"KCP settings loaded from host tags");

            // Show name entry
            _joinNameFocusables.Clear();
            _joinNameFocusIndex = 0;

            var defaultJoinName = string.IsNullOrEmpty(_settings.JoinName) ? string.Empty : _settings.JoinName;
            _fieldJoinName = new InputField { X = 14, Y = 6, Width = 36, Text = defaultJoinName };
            _joinNameFocusables.Add(_fieldJoinName);

            // Add password field if host is password-protected
            if (host.ProtectionLevel is EProtectionLevel.PASSWORD_PROTECTED)
            {
                _fieldJoinPassword = new InputField { X = 14, Y = 8, Width = 36, Text = "" };
                _joinNameFocusables.Add(_fieldJoinPassword);
            }
            else
            {
                _fieldJoinPassword = null;
            }

            var btnY = host.ProtectionLevel is EProtectionLevel.PASSWORD_PROTECTED ? 10 : 8;
            var btnConnect = new Button { X = 14, Y = btnY, Label = "Connect", OnActivate = () => _ = ConnectToHostAsync() };
            _joinNameFocusables.Add(btnConnect);

            _state = EAppState.JoinName;
        }
        else
        {
            var optionIndex = _queryResult.Count;
            if (hasPrevious && selection == optionIndex)
            {
                _querySkip = (ushort)Math.Max(0, _querySkip - 5);
                await RefreshHostListAsync();
            }
            else if (hasNext && selection == optionIndex + (hasPrevious ? 1 : 0))
            {
                _querySkip += 5;
                await RefreshHostListAsync();
            }
            else
            {
                await RefreshHostListAsync();
            }
        }
    }

    private static async Task ConnectToHostAsync()
    {
        if (_joinClient is null || _selectedHost is null) return;

        var defaultJoinName = string.IsNullOrEmpty(_settings.JoinName) ? $"Player_{Random.Shared.Next(1000, 9999)}" : _settings.JoinName;
        _localName = GetFieldValue(_fieldJoinName, defaultJoinName);
        _isHost = false;

        // Save join name
        _settings.JoinName = _localName;
        _settings.Save();

        var kcpOptions = _activeKcpOptions;

        // We need to create a new client with the host's KCP options
        // since YamabikoKcpOptions is set at construction time.
        // Get the server endpoint from the current join client.
        var serverEndpoint = _joinClient.ServerEndPoint;

        try
        {
            // Get project ID from the original config
            var projectIdStr = GetFieldValue(_fieldJoinProjectId, _settings.ProjectId);
            if (!Guid.TryParse(projectIdStr, out var projectId))
                projectId = Guid.Parse(_settings.ProjectId);

            // Dispose old client and create new one with host's KCP options
            try { await _joinClient.DisposeAsync(); } catch { }
            _joinClient = null;

            _joinClient = new YamabikoClient(serverEndpoint, projectId, kcpOptions)
            {
                CertificateDomain = string.IsNullOrWhiteSpace(_settings.ServerDomain) ? null : _settings.ServerDomain,
                ValidateCertificatesCallback = _ => true
            };

            await _joinClient.StartAsync();

            if (_joinClient.ConnectionState is not EConnectionState.CONNECTED)
            {
                Log($"Failed to reconnect to rendezvous server: {_joinClient.ConnectionState}");
                try { await _joinClient.DisposeAsync(); } catch { }
                _joinClient = null;
                return;
            }

            Log($"Connecting to host '{_selectedHost.Name}'...");

            string? password = null;
            if (_selectedHost.ProtectionLevel is EProtectionLevel.PASSWORD_PROTECTED)
            {
                password = GetFieldValue(_fieldJoinPassword, "").Trim();
                if (string.IsNullOrEmpty(password))
                {
                    Log("This room requires a password. Enter a password and try again.");
                    return;
                }
            }

            var peer = await _joinClient.ConnectAsync(_selectedHost, password);
            await peer.WaitUntilConnectedAsync(TimeSpan.FromSeconds(30));

            _peer = peer;
            _connectedSince = DateTime.Now;

            Log("Connected! Exchanging names...");

            // Exchange names
            var remoteNameBytes = await peer.ReceiveReliableAsync();
            _remoteName = Encoding.UTF8.GetString(remoteNameBytes.Span);
            peer.SendReliable(Encoding.UTF8.GetBytes(_localName));

            Log($"Connected with: {_remoteName}");

            BuildConnectedLayout();
            _state = EAppState.Connected;

            _ = ReceiveLoopAsync();
            StartStreamReceiveLoop();
        }
        catch (Exception ex)
        {
            Log($"Connect error: {ex.Message}");
            if (_joinClient is not null)
            {
                try { await _joinClient.DisposeAsync(); } catch { }
                _joinClient = null;
            }
            // Return to join config so user can retry
            _state = EAppState.JoinConfig;
        }
    }

    private static async Task DisconnectAndReturnToMenuAsync()
    {
        Log("Disconnecting...");

        StopStreamReceiveLoop();

        if (_peer is not null)
        {
            try { await _peer.DisconnectAsync(); } catch { }
            try { await _peer.DisposeAsync(); } catch { }
            _peer = null;
        }
        if (_hostClient is not null)
        {
            try { await _hostClient.StopAdvertisingAsync(); } catch { }
            try { await _hostClient.DisposeAsync(); } catch { }
            _hostClient = null;
        }
        if (_joinClient is not null)
        {
            try { await _joinClient.DisposeAsync(); } catch { }
            _joinClient = null;
        }

        _transmittedMessages = 0;
        _receivedMessages = 0;
        _transmittedBytes = 0;
        _receivedBytes = 0;
        _selectedHost = null;
        _queryResult = null;
        _logView = null;
        _commandInput = null;
        _btnQuit = null;
        _state = EAppState.MainMenu;
    }

    private static void BuildConnectedLayout()
    {
        _connectedFocusables.Clear();

        var w = ConsoleBuffer.Width;
        var h = ConsoleBuffer.Height;

        var logY = TopSectionHeight + 1;
        var logHeight = h - logY - 3;
        if (logHeight < 3) logHeight = 3;

        _logView = new LogViewElement { X = 0, Y = logY, Width = w, Height = logHeight };
        _connectedFocusables.Add(_logView);

        _commandInput = new CommandInputElement
        {
            X = 0,
            Y = h - 3,
            Width = w,
            OnSubmit = OnCommandSubmit
        };
        _connectedFocusables.Add(_commandInput);

        _btnQuit = new Button { X = 1, Y = h - 1, Label = "Quit ^Q/ESC", OnActivate = () => _ = DisconnectAndReturnToMenuAsync() };
        _connectedFocusables.Add(_btnQuit);

        _connectedFocusIndex = 1; // Focus on command input by default
    }

    private static void UpdateConnectedLayout(int w, int h)
    {
        if (_logView is not null)
        {
            var logY = TopSectionHeight + 1;
            var logHeight = h - logY - 3;
            if (logHeight < 3) logHeight = 3;
            _logView.X = 0;
            _logView.Y = logY;
            _logView.Width = w;
            _logView.Height = logHeight;
        }
        if (_commandInput is not null)
        {
            _commandInput.X = 0;
            _commandInput.Y = h - 3;
            _commandInput.Width = w;
        }
        if (_btnQuit is not null)
        {
            _btnQuit.X = 1;
            _btnQuit.Y = h - 1;
        }
    }



    private static async Task ReceiveLoopAsync()
    {
        while (_peer is not null && _peer.ConnectionState is EConnectionState.CONNECTED)
        {
            try
            {
                var buffer = await _peer.ReceiveReliableAsync();
                var message = Encoding.UTF8.GetString(buffer.Span);
                Interlocked.Increment(ref _receivedMessages);
                Log($"[{_remoteName}] {message}");
            }
            catch
            {
                break;
            }
        }

        if (_peer is not null && _peer.ConnectionState is not EConnectionState.CONNECTED)
        {
            Log("Peer disconnected");
        }
    }



    private static void OnCommandSubmit()
    {
        if (_commandInput is null) return;
        var input = _commandInput.Text.Trim();
        _commandInput.Text = "";
        _commandInput.CursorPos = 0;

        if (string.IsNullOrEmpty(input)) return;

        _commandHistory.Add(input);
        if (100 < _commandHistory.Count) _commandHistory.RemoveAt(0);
        _commandHistoryIndex = -1;
        _currentSavedInput = "";

        if (!input.StartsWith('/'))
        {
            if (_peer is not null && _peer.ConnectionState is EConnectionState.CONNECTED)
            {
                _peer.SendReliable(Encoding.UTF8.GetBytes(input));
                Interlocked.Increment(ref _transmittedMessages);
                Log($"[{_localName}] {input}");
            }
            else
            {
                Log("Not connected");
            }
            return;
        }

        var parts = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var command = parts[0].ToLowerInvariant();

        try
        {
            switch (command)
            {
                case "/send":
                    if (parts.Length < 2) { Log("Usage: /send <text>"); break; }
                    if (_peer is not null) { _peer.SendReliable(Encoding.UTF8.GetBytes(string.Join(' ', parts[1..]))); Interlocked.Increment(ref _transmittedMessages); Log($"[SENT] {string.Join(' ', parts[1..])}"); }
                    break;
                case "/stream":
                    if (parts.Length < 2 || !int.TryParse(parts[1], out var streamSize))
                    {
                        Log("Usage: /stream <size>");
                        break;
                    }
                    if (_peer is not null) { _ = StreamSendAsync(streamSize); }
                    else Log("Not connected");
                    break;
                case "/ping":
                    if (_peer is not null)
                    {
                        var pingMs = _peer.Ping.TotalMilliseconds;
                        Log(pingMs >= 0 ? $"Current ping: {pingMs:F1}ms" : "Ping: not yet measured");
                    }
                    else Log("Not connected");
                    break;
                case "/disconnect":
                    _ = DisconnectAndReturnToMenuAsync();
                    break;
                case "/help":
                    Log("/send <text>  /stream <size>  /ping  /disconnect  /help");
                    Log("Or just type text to send a message");
                    break;
                default:
                    Log($"Unknown: {command}. Try /help");
                    break;
            }
        }
        catch (Exception ex)
        {
            Log($"Command error: {ex.Message}");
        }
    }

    private static void UpdateCommandHint(string currentText)
    {
        if (string.IsNullOrEmpty(currentText) || !currentText.StartsWith('/'))
        {
            _hintText = "Type / for commands, or just type text to send";
            return;
        }

        var commandPart = currentText.Split(' ')[0];
        if (string.IsNullOrEmpty(commandPart) || commandPart == "/")
        {
            _hintText = "Commands: /send /stream /ping /disconnect /help";
            return;
        }

        var exactMatch = CommandHints.FirstOrDefault(c => c.Command.Equals(commandPart, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrEmpty(exactMatch.Command))
        {
            _hintText = $"{exactMatch.Command} - {exactMatch.Hint}  Usage: {exactMatch.Usage}";
            return;
        }

        var matches = CommandHints.Where(c => c.Command.StartsWith(commandPart, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length == 0) { _hintText = "Unknown command. Try /help"; return; }
        if (matches.Length == 1) { _hintText = $"{matches[0].Command} - {matches[0].Hint}  Usage: {matches[0].Usage}"; return; }
        _hintText = string.Join("  ", matches.Select(m => m.Command));
    }



    private static void RenderAll()
    {
        var w = ConsoleBuffer.Width;
        var h = ConsoleBuffer.Height;

        // Clear buffer on state change to prevent bleed-through
        if (_state != _previousRenderState)
        {
            ConsoleBuffer.Clear();
            _previousRenderState = _state;
        }

        switch (_state)
        {
            case EAppState.MainMenu: RenderMainMenu(w, h); break;
            case EAppState.HostConfig: RenderHostConfig(w, h); break;
            case EAppState.JoinConfig: RenderJoinConfig(w, h); break;
            case EAppState.JoinHostList: RenderJoinHostList(w, h); break;
            case EAppState.JoinName: RenderJoinName(w, h); break;
            case EAppState.Connected: RenderConnected(w, h); break;
        }
    }

    private static void RenderMainMenu(int w, int h)
    {
        ConsoleBuffer.Write(0, 0, " Yamabiko Sample - P2P Chat".PadRight(w), ConsoleColor.White, ConsoleColor.DarkBlue);

        var centerY = h / 2 - 4;
        ConsoleBuffer.Write(w / 2 - 8, centerY, "Yamabiko P2P Chat", ConsoleColor.Cyan);
        ConsoleBuffer.Write(w / 2 - 14, centerY + 2, new string('-', 28), ConsoleColor.DarkGray);

        string[] options = ["Host a Room", "Join a Room", "Quit"];
        for (int i = 0; i < options.Length; i++)
        {
            var prefix = (_menuSelection == i) ? "> " : "  ";
            var fg = (_menuSelection == i) ? ConsoleColor.Yellow : ConsoleColor.Gray;
            ConsoleBuffer.Write(w / 2 - 8, centerY + 4 + i * 2, $"{prefix}{options[i]}", fg);
        }

        ConsoleBuffer.Write(w / 2 - 18, h - 3, "Use arrow keys to navigate, Enter to select", ConsoleColor.DarkGray);
    }

    private static void RenderHostConfig(int w, int h)
    {
        ConsoleBuffer.Write(0, 0, " Yamabiko Sample - Host Configuration".PadRight(w), ConsoleColor.White, ConsoleColor.DarkBlue);

        var baseX = 1;
        var baseY = 2;

        // Row 0: Server heading
        ConsoleBuffer.Write(baseX + 1, baseY, "Server", ConsoleColor.Cyan);

        // Row 1: IP + Port (matches _fieldServerIp at Y=baseY+1)
        ConsoleBuffer.Write(baseX + 1, baseY + 1, "IP:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 34, baseY + 1, "Port:", ConsoleColor.Gray);

        // Row 2: Domain (matches _fieldServerDomain at Y=baseY+2)
        ConsoleBuffer.Write(baseX + 1, baseY + 2, "Domain:", ConsoleColor.Gray);

        // Row 3: ProjectID (matches _fieldProjectId at Y=baseY+3)
        ConsoleBuffer.Write(baseX + 1, baseY + 3, "ProjectID:", ConsoleColor.Gray);

        // Row 4: HostName (matches _fieldHostName at Y=baseY+4)
        ConsoleBuffer.Write(baseX + 1, baseY + 4, "HostName:", ConsoleColor.Gray);

        // Row 5: Password (matches _fieldHostPassword at Y=baseY+5)
        ConsoleBuffer.Write(baseX + 1, baseY + 5, "Password:", ConsoleColor.Gray);

        // Row 7: KCP Reliable heading
        ConsoleBuffer.Write(baseX + 1, baseY + 7, "KCP Reliable", ConsoleColor.Cyan);

        // Row 8: Checkboxes (same row as _checkReliableNoDelay at Y=baseY+8)

        // Row 9: Reliable param labels (matches fields at Y=baseY+9)
        ConsoleBuffer.Write(baseX + 1, baseY + 9, "Iv:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 13, baseY + 9, "FR:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 23, baseY + 9, "MTU:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 36, baseY + 9, "SndW:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 48, baseY + 9, "RcvW:", ConsoleColor.Gray);

        // Row 11: KCP Stream heading
        ConsoleBuffer.Write(baseX + 1, baseY + 11, "KCP Stream", ConsoleColor.Cyan);

        // Row 12: Checkboxes (same row as _checkStreamNoDelay at Y=baseY+12)

        // Row 13: Stream param labels (matches fields at Y=baseY+13)
        ConsoleBuffer.Write(baseX + 1, baseY + 13, "Iv:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 13, baseY + 13, "FR:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 23, baseY + 13, "MTU:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 36, baseY + 13, "SndW:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 48, baseY + 13, "RcvW:", ConsoleColor.Gray);

        // Row 15: Start Hosting button

        // Draw all focusable elements
        foreach (var f in _hostConfigFocusables)
        {
            if (f.IsVisible)
                f.Draw(_hostConfigFocusables[_hostConfigFocusIndex] == f);
        }

        // Draw log at bottom
        var logY = baseY + 17;
        var logHeight = h - logY - 2;
        if (3 <= logHeight)
        {
            if (_logView is null || _logView.Y != logY || _logView.Height != logHeight)
                _logView = new LogViewElement { X = 0, Y = logY, Width = w, Height = logHeight };
            _logView.Draw(false);
        }

        ConsoleBuffer.Write(0, h - 1, " Tab: Navigate  Enter/Space: Toggle  ESC: Back ", ConsoleColor.White, ConsoleColor.DarkGray);
    }

    private static void RenderJoinConfig(int w, int h)
    {
        ConsoleBuffer.Write(0, 0, " Yamabiko Sample - Join a Room".PadRight(w), ConsoleColor.White, ConsoleColor.DarkBlue);

        var baseX = 1;
        var baseY = 2;

        // Row 0: Server heading
        ConsoleBuffer.Write(baseX + 1, baseY, "Rendezvous Server", ConsoleColor.Cyan);

        // Row 1: IP + Port (matches _fieldJoinServerIp at Y=baseY+1)
        ConsoleBuffer.Write(baseX + 1, baseY + 1, "IP:", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 34, baseY + 1, "Port:", ConsoleColor.Gray);

        // Row 2: Domain (matches _fieldJoinServerDomain at Y=baseY+2)
        ConsoleBuffer.Write(baseX + 1, baseY + 2, "Domain:", ConsoleColor.Gray);

        // Row 3: ProjectID (matches _fieldJoinProjectId at Y=baseY+3)
        ConsoleBuffer.Write(baseX + 1, baseY + 3, "ProjectID:", ConsoleColor.Gray);

        // Row 5: Connect button

        // Draw all focusable elements
        foreach (var f in _joinConfigFocusables)
        {
            if (f.IsVisible)
                f.Draw(_joinConfigFocusables[_joinConfigFocusIndex] == f);
        }

        // Draw log at bottom
        var logY = baseY + 8;
        var logHeight = h - logY - 2;
        if (3 <= logHeight)
        {
            if (_logView is null || _logView.Y != logY || _logView.Height != logHeight)
                _logView = new LogViewElement { X = 0, Y = logY, Width = w, Height = logHeight };
            _logView.Draw(false);
        }

        ConsoleBuffer.Write(0, h - 1, " Tab: Navigate  Enter: Connect  ESC: Back ", ConsoleColor.White, ConsoleColor.DarkGray);
    }

    private static void RenderJoinHostList(int w, int h)
    {
        ConsoleBuffer.Write(0, 0, " Yamabiko Sample - Available Hosts".PadRight(w), ConsoleColor.White, ConsoleColor.DarkBlue);

        var baseY = 2;
        ConsoleBuffer.Write(2, baseY, "Available Hosts", ConsoleColor.Cyan);

        if (_queryLoading)
        {
            ConsoleBuffer.Write(2, baseY + 2, "Loading...", ConsoleColor.Yellow);
        }
        else if (_queryResult is null || _queryResult.Total == 0)
        {
            ConsoleBuffer.Write(2, baseY + 2, "No hosts found.", ConsoleColor.Yellow);
            ConsoleBuffer.Write(2, baseY + 3, "Press Enter or F5 to refresh", ConsoleColor.DarkGray);
        }
        else
        {
            for (int i = 0; i < _queryResult.Count; i++)
            {
                var room = _queryResult[i];
                if (room is null) continue;
                var prefix = (_hostListSelection == i) ? "> " : "  ";
                var fg = (_hostListSelection == i) ? ConsoleColor.Yellow : ConsoleColor.Gray;
                var lockIcon = room.ProtectionLevel is EProtectionLevel.PASSWORD_PROTECTED ? " [Locked]" : "";
                ConsoleBuffer.Write(2, baseY + 2 + i, $"{prefix}{room.Index}. {room.Name}{lockIcon}".PadRight(w - 4), fg);
            }

            int optionIndex = _queryResult.Count;
            var hasPrevious = 0 < _querySkip;
            var hasNext = _querySkip + 5 < _queryResult.Total;

            if (hasPrevious)
            {
                var prefix = (_hostListSelection == optionIndex) ? "> " : "  ";
                var fg = (_hostListSelection == optionIndex) ? ConsoleColor.Yellow : ConsoleColor.Gray;
                ConsoleBuffer.Write(2, baseY + 2 + optionIndex, $"{prefix}Previous Page", fg);
                optionIndex++;
            }
            if (hasNext)
            {
                var prefix = (_hostListSelection == optionIndex) ? "> " : "  ";
                var fg = (_hostListSelection == optionIndex) ? ConsoleColor.Yellow : ConsoleColor.Gray;
                ConsoleBuffer.Write(2, baseY + 2 + optionIndex, $"{prefix}Next Page", fg);
                optionIndex++;
            }
            {
                var prefix = (_hostListSelection == optionIndex) ? "> " : "  ";
                var fg = (_hostListSelection == optionIndex) ? ConsoleColor.Yellow : ConsoleColor.Gray;
                ConsoleBuffer.Write(2, baseY + 2 + optionIndex, $"{prefix}Refresh List", fg);
            }
        }

        // Draw log at bottom
        var logY = h - 8;
        var logHeight = 5;
        if (3 <= logHeight && logY > baseY + 10)
        {
            if (_logView is null || _logView.Y != logY || _logView.Height != logHeight)
                _logView = new LogViewElement { X = 0, Y = logY, Width = w, Height = logHeight };
            _logView.Draw(false);
        }

        ConsoleBuffer.Write(0, h - 1, " Arrow keys: Navigate  Enter: Select  F5: Refresh  ESC: Back ", ConsoleColor.White, ConsoleColor.DarkGray);
    }

    private static void RenderJoinName(int w, int h)
    {
        ConsoleBuffer.Write(0, 0, " Yamabiko Sample - Enter Your Name".PadRight(w), ConsoleColor.White, ConsoleColor.DarkBlue);

        ConsoleBuffer.Write(2, 4, $"Joining: {_selectedHost?.Name ?? "Unknown"}", ConsoleColor.Cyan);

        ConsoleBuffer.Write(2, 6, "Name:", ConsoleColor.Gray);

        // Show password label if host is password-protected
        if (_selectedHost?.ProtectionLevel is EProtectionLevel.PASSWORD_PROTECTED)
            ConsoleBuffer.Write(2, 8, "Password:", ConsoleColor.Gray);

        foreach (var f in _joinNameFocusables)
        {
            if (f.IsVisible)
                f.Draw(_joinNameFocusables[_joinNameFocusIndex] == f);
        }

        // Show KCP options from host
        var kcpStartY = _selectedHost?.ProtectionLevel is EProtectionLevel.PASSWORD_PROTECTED ? 12 : 10;
        ConsoleBuffer.Write(2, kcpStartY, "KCP Settings (from host):", ConsoleColor.Cyan);
        var kcp = _activeKcpOptions;
        ConsoleBuffer.Write(2, kcpStartY + 1, $"Reliable: ND={kcp.ReliableNoDelay} Iv={kcp.ReliableIntervalMs} FR={kcp.ReliableFastResend} NoCwnd={kcp.ReliableNoCongestionControl}", ConsoleColor.Gray);
        ConsoleBuffer.Write(2, kcpStartY + 2, $"  SndW={kcp.ReliableSendWindowSize} RcvW={kcp.ReliableRecvWindowSize} MTU={kcp.ReliableMtu}", ConsoleColor.Gray);
        ConsoleBuffer.Write(2, kcpStartY + 3, $"Stream:  ND={kcp.StreamNoDelay} Iv={kcp.StreamIntervalMs} FR={kcp.StreamFastResend} NoCwnd={kcp.StreamNoCongestionControl}", ConsoleColor.Gray);
        ConsoleBuffer.Write(2, kcpStartY + 4, $"  SndW={kcp.StreamSendWindowSize} RcvW={kcp.StreamRecvWindowSize} MTU={kcp.StreamMtu}", ConsoleColor.Gray);

        // Draw log at bottom
        var logY = h - 8;
        var logHeight = 5;
        if (3 <= logHeight)
        {
            if (_logView is null || _logView.Y != logY || _logView.Height != logHeight)
                _logView = new LogViewElement { X = 0, Y = logY, Width = w, Height = logHeight };
            _logView.Draw(false);
        }

        ConsoleBuffer.Write(0, h - 1, " Tab: Navigate  Enter: Connect  ESC: Back ", ConsoleColor.White, ConsoleColor.DarkGray);
    }

    private static void RenderConnected(int w, int h)
    {
        // Dynamically update layout positions to handle console resize
        UpdateConnectedLayout(w, h);

        var title = _isHost ? " Yamabiko Sample - Hosting" : " Yamabiko Sample - Connected";
        ConsoleBuffer.Write(0, 0, title.PadRight(w), ConsoleColor.White, ConsoleColor.DarkBlue);

        // Left panel: KCP Settings
        ConsoleBuffer.DrawBox(0, 1, ConfigFrameWidth, TopSectionHeight, ConsoleColor.Gray);
        ConsoleBuffer.Write(2, 1, " KCP Settings", ConsoleColor.Gray);

        var baseX = 1;
        var baseY = 2;
        var kcp = _activeKcpOptions;

        ConsoleBuffer.Write(baseX + 1, baseY, "Reliable Channel", ConsoleColor.Cyan);
        ConsoleBuffer.Write(baseX + 1, baseY + 1, $"NoDelay: {kcp.ReliableNoDelay}   Interval: {kcp.ReliableIntervalMs}ms   FastResend: {kcp.ReliableFastResend}", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 1, baseY + 2, $"NoCwnd: {kcp.ReliableNoCongestionControl}   SendWnd: {kcp.ReliableSendWindowSize}   RecvWnd: {kcp.ReliableRecvWindowSize}   MTU: {kcp.ReliableMtu}", ConsoleColor.Gray);

        ConsoleBuffer.Write(baseX + 1, baseY + 4, "Stream Channel", ConsoleColor.Cyan);
        ConsoleBuffer.Write(baseX + 1, baseY + 5, $"NoDelay: {kcp.StreamNoDelay}   Interval: {kcp.StreamIntervalMs}ms   FastResend: {kcp.StreamFastResend}", ConsoleColor.Gray);
        ConsoleBuffer.Write(baseX + 1, baseY + 6, $"NoCwnd: {kcp.StreamNoCongestionControl}   SendWnd: {kcp.StreamSendWindowSize}   RecvWnd: {kcp.StreamRecvWindowSize}   MTU: {kcp.StreamMtu}", ConsoleColor.Gray);

        // Right panel: Statistics
        var statsW = w - ConfigFrameWidth;
        if (2 < statsW)
        {
            ConsoleBuffer.DrawBox(ConfigFrameWidth, 1, statsW, TopSectionHeight, ConsoleColor.Gray);
            ConsoleBuffer.Write(ConfigFrameWidth + 2, 1, " Statistics ", ConsoleColor.Gray);

            var statsText = BuildStatisticsString();
            var statsLines = statsText.Split('\n');
            var contentX = ConfigFrameWidth + 1;
            var contentY = 2;
            var contentH = TopSectionHeight - 2;

            for (int i = 0; i < contentH; i++)
            {
                string line;
                if (i < statsLines.Length)
                {
                    var raw = statsLines[i].TrimEnd();
                    line = statsW - 2 < raw.Length ? raw[..(statsW - 2)] : raw.PadRight(statsW - 2);
                }
                else
                {
                    line = new string(' ', statsW - 2);
                }
                ConsoleBuffer.Write(contentX, contentY + i, line, ConsoleColor.Gray);
            }
        }

        // Hint line
        var hintText = w < _hintText.Length ? _hintText[..w] : _hintText.PadRight(w);
        ConsoleBuffer.Write(0, h - 2, hintText, ConsoleColor.DarkCyan, ConsoleColor.Black);

        // Bottom bar
        ConsoleBuffer.FillRect(0, h - 1, w, 1, ' ', ConsoleColor.White, ConsoleColor.DarkGray);
        _btnQuit?.Draw(_connectedFocusables.IndexOf(_btnQuit) == _connectedFocusIndex);

        // Log and command input
        if (_logView is not null)
            _logView.Draw(_connectedFocusables[_connectedFocusIndex] == _logView);
        if (_commandInput is not null)
            _commandInput.Draw(_connectedFocusables[_connectedFocusIndex] == _commandInput);
    }

    private static string BuildStatisticsString()
    {
        if (_peer is null)
            return "Waiting for peer connection...";

        var sb = new StringBuilder();
        sb.AppendLine($"State: {_peer.ConnectionState}   ConnId: {_peer.ConnectionId}");
        sb.AppendLine($"Local: {_localName}   Remote: {_remoteName}");
        sb.AppendLine($"Ping: {(_peer.Ping.Ticks < 0 ? "N/A" : $"{_peer.Ping.TotalMilliseconds:F1}ms")}");
        sb.AppendLine($"Remote EP: {_peer.RemoteEndpoint?.ToString() ?? "N/A"}");
        sb.AppendLine($"Sent: {Volatile.Read(ref _transmittedMessages)} msg / {FormatSize(Volatile.Read(ref _transmittedBytes))}   Recv: {Volatile.Read(ref _receivedMessages)} msg / {FormatSize(Volatile.Read(ref _receivedBytes))}");
        sb.AppendLine($"Connected: {(_connectedSince == default ? "N/A" : (DateTime.Now - _connectedSince).ToString(@"hh\:mm\:ss"))}");
        sb.AppendLine($"PeerId: {_peer.RemotePeerId}");
        sb.AppendLine($"IsHost: {_isHost}");

        return sb.ToString();
    }



    private static void Log(string message)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {message}";
        lock (_pendingLogsLock)
            _pendingLogs.Add(line);
    }

    private static void FlushPendingLogs()
    {
        List<string> toFlush;
        lock (_pendingLogsLock)
        {
            if (_pendingLogs.Count == 0) return;
            toFlush = [.. _pendingLogs];
            _pendingLogs.Clear();
        }

        var newCount = toFlush.Count;

        lock (_logLock)
        {
            foreach (var line in toFlush)
            {
                _logLineCount++;
                _logLines.Add(line);
                if (5000 < _logLineCount && 3000 < _logLines.Count)
                {
                    _logLines.RemoveRange(0, _logLines.Count - 2000);
                    _logLineCount = 2000;
                }
            }
        }

        if (_logView is not null && 0 < _logView.ScrollOffset)
        {
            _logView.ScrollOffset += newCount;
            _unreadLogCount += newCount;
        }
    }

    private static void ClearLog()
    {
        lock (_logLock) { _logLines.Clear(); _logLineCount = 0; }
        _unreadLogCount = 0;
    }



    private static async Task StreamSendAsync(int size)
    {
        if (_peer is null || _peer.ConnectionState is not EConnectionState.CONNECTED)
        {
            Log("Not connected");
            return;
        }

        if (size <= 0)
        {
            Log("Size must be positive");
            return;
        }

        var data = ArrayPool<byte>.Shared.Rent(size);
        try
        {
            Random.Shared.NextBytes(data.AsSpan(0, size));

            byte[] hash;
            using (var sha = SHA256.Create())
                hash = sha.ComputeHash(data, 0, size);

            Log($"Streaming {FormatSize(size)}...");
            var sw = Stopwatch.StartNew();

            try
            {
                var stream = _peer.GetStream();

                var header = new byte[FrameHeaderSize];
                header[0] = FrameTypeStream;
                BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(1), (uint)size);
                await stream.WriteAsync(header);
                await stream.WriteAsync(data.AsMemory(0, size));
                await stream.WriteAsync(hash);
            }
            catch (Exception ex)
            {
                Log($"Stream err: {ex.Message}");
                return;
            }

            sw.Stop();
            Interlocked.Add(ref _transmittedBytes, size);
            Interlocked.Increment(ref _transmittedMessages);

            var safeMs = Math.Max(1, sw.ElapsedMilliseconds);
            var hashStr = Convert.ToHexString(hash).ToLowerInvariant();
            Log($"[STREAM TX] {FormatSize(size)} in {sw.ElapsedMilliseconds}ms ({FormatSpeed((double)size / (safeMs / 1000.0))}) SHA256:{hashStr}");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(data);
        }
    }

    private static void StartStreamReceiveLoop()
    {
        StopStreamReceiveLoop();
        _streamReceiveCts = new CancellationTokenSource();
        var token = _streamReceiveCts.Token;
        _streamReceiveTask = Task.Run(() => StreamReceiveLoopAsync(token), token);
    }

    private static void StopStreamReceiveLoop()
    {
        _streamReceiveCts?.Cancel();
        try { if (_streamReceiveTask is not null) _streamReceiveTask.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _streamReceiveCts?.Dispose();
        _streamReceiveCts = null;
        _streamReceiveTask = null;
    }

    private static async Task StreamReceiveLoopAsync(CancellationToken token)
    {
        var headerBuf = new byte[FrameHeaderSize];
        var readBuf = ArrayPool<byte>.Shared.Rent(65536);

        try
        {
            while (!token.IsCancellationRequested && _peer is not null && _peer.ConnectionState is EConnectionState.CONNECTED)
            {
                try
                {
                    var stream = _peer.GetStream();
                    await stream.ReadExactlyAsync(headerBuf, token);
                    var frameType = headerBuf[0];
                    var payloadSize = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf.AsSpan(1));

                    switch (frameType)
                    {
                        case FrameTypeText:
                            {
                                var textBuf = ArrayPool<byte>.Shared.Rent((int)payloadSize);
                                try
                                {
                                    await stream.ReadExactlyAsync(textBuf.AsMemory(0, (int)payloadSize), token);
                                    var text = Encoding.UTF8.GetString(textBuf, 0, (int)payloadSize);
                                    Log($"[RECV] {payloadSize}B: \"{text}\"");
                                }
                                finally
                                {
                                    ArrayPool<byte>.Shared.Return(textBuf);
                                }
                                Interlocked.Add(ref _receivedBytes, FrameHeaderSize + payloadSize);
                                break;
                            }
                        case FrameTypeStream:
                            {
                                Log($"Receiving stream of {FormatSize(payloadSize)}...");
                                var sw = Stopwatch.StartNew();
                                using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                                {
                                    long remaining = payloadSize;
                                    while (0 < remaining)
                                    {
                                        int toRead = (int)Math.Min(remaining, readBuf.Length);
                                        await stream.ReadExactlyAsync(readBuf.AsMemory(0, toRead), token);
                                        hash.AppendData(readBuf.AsSpan(0, toRead));
                                        remaining -= toRead;
                                    }

                                    var hashBuf = new byte[FrameHashSize];
                                    await stream.ReadExactlyAsync(hashBuf, token);

                                    var computedHash = hash.GetHashAndReset();
                                    sw.Stop();
                                    var safeMs = Math.Max(1, sw.ElapsedMilliseconds);
                                    var hashStr = Convert.ToHexString(computedHash).ToLowerInvariant();
                                    var match = computedHash.SequenceEqual(hashBuf);
                                    Log($"[STREAM RX] {FormatSize(payloadSize)} in {sw.ElapsedMilliseconds}ms ({FormatSpeed(payloadSize / (safeMs / 1000.0))}) SHA256:{hashStr} {(match ? "OK" : "MISMATCH")}");
                                }
                                Interlocked.Add(ref _receivedBytes, FrameHeaderSize + payloadSize + FrameHashSize);
                                break;
                            }
                        default:
                            Log($"[FRAME ERR] Unknown stream frame type 0x{frameType:X2}");
                            break;
                    }
                    Interlocked.Increment(ref _receivedMessages);
                }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch (InvalidOperationException) { break; }
                catch (Exception ex)
                {
                    if (!token.IsCancellationRequested)
                    {
                        Log($"[STREAM RECV ERR] {ex.Message}");
                        await Task.Delay(100, token);
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(readBuf);
        }
    }

    private static string FormatSize(double bytes)
    {
        if (bytes < 1024) return $"{bytes:F0}B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024:F1}KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024 * 1024):F1}MB";
        return $"{bytes / (1024 * 1024 * 1024):F1}GB";
    }

    private static string FormatSpeed(double bytesPerSecond)
    {
        if (bytesPerSecond < 1024) return $"{bytesPerSecond:F0}B/s";
        if (bytesPerSecond < 1024 * 1024) return $"{bytesPerSecond / 1024:F1}KB/s";
        if (bytesPerSecond < 1024 * 1024 * 1024) return $"{bytesPerSecond / (1024 * 1024):F1}MB/s";
        return $"{bytesPerSecond / (1024 * 1024 * 1024):F1}GB/s";
    }



    private static string GetFieldValue(InputField? field, string defaultValue)
        => field?.Text.Trim() ?? defaultValue;

    private static int GetFieldInt(InputField? field, int defaultValue)
        => int.TryParse(field?.Text.Trim(), out var value) ? value : defaultValue;
}
