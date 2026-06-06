namespace Kanawanagasaki.Yamabiko.Sample;

public static class ConsoleBuffer
{
    private static readonly Lock _lock = new();
    private static char[,]? _currentBuffer;
    private static ConsoleColor[,]? _foregroundBuffer;
    private static ConsoleColor[,]? _backgroundBuffer;
    private static char[,]? _previousBuffer;
    private static ConsoleColor[,]? _previousForeground;
    private static ConsoleColor[,]? _previousBackground;

    private static int _width = 0;
    private static int _height = 0;
    private static bool _initialized = false;

    public static int Width => _width;
    public static int Height => _height;

    public static void Initialize()
    {
        lock (_lock)
        {
            if (_width <= 0 || _height <= 0)
            {
                try
                {
                    _width = Console.WindowWidth;
                    _height = Console.WindowHeight;
                }
                catch
                {
                    _width = 80;
                    _height = 24;
                }
            }

            if (_width < 1 || _height < 1)
            {
                _width = 80;
                _height = 24;
            }

            _currentBuffer = new char[_width, _height];
            _foregroundBuffer = new ConsoleColor[_width, _height];
            _backgroundBuffer = new ConsoleColor[_width, _height];
            _previousBuffer = new char[_width, _height];
            _previousForeground = new ConsoleColor[_width, _height];
            _previousBackground = new ConsoleColor[_width, _height];

            for (int x = 0; x < _width; x++)
            {
                for (int y = 0; y < _height; y++)
                {
                    _currentBuffer[x, y] = ' ';
                    _foregroundBuffer[x, y] = ConsoleColor.Gray;
                    _backgroundBuffer[x, y] = ConsoleColor.Black;
                    _previousBuffer[x, y] = '\0';
                    _previousForeground[x, y] = ConsoleColor.Black;
                    _previousBackground[x, y] = ConsoleColor.Black;
                }
            }

            _initialized = true;
            try
            {
                Console.CursorVisible = false;
            }
            catch { }
        }
    }

    public static void CheckResize()
    {
        lock (_lock)
        {
            try
            {
                var newWidth = Console.WindowWidth;
                var newHeight = Console.WindowHeight;

                if (newWidth < 1 || newHeight < 1)
                    return;

                if (newWidth != _width || newHeight != _height)
                {
                    _initialized = false;
                    _width = newWidth;
                    _height = newHeight;
                    Initialize();
                    Clear();
                }
            }
            catch { }
        }
    }

    public static void Clear()
    {
        lock (_lock)
        {
            if (!_initialized)
                return;

            for (int x = 0; x < _width; x++)
            {
                for (int y = 0; y < _height; y++)
                {
                    _currentBuffer![x, y] = ' ';
                    _foregroundBuffer![x, y] = ConsoleColor.Gray;
                    _backgroundBuffer![x, y] = ConsoleColor.Black;
                }
            }
        }
    }

    public static void Write(int x, int y, string text, ConsoleColor foreground = ConsoleColor.Gray, ConsoleColor background = ConsoleColor.Black)
    {
        lock (_lock)
        {
            if (!_initialized)
                return;

            for (int i = 0; i < text.Length && x + i < _width; i++)
            {
                if (0 <= x + i && 0 <= y && y < _height)
                {
                    _currentBuffer![x + i, y] = text[i];
                    _foregroundBuffer![x + i, y] = foreground;
                    _backgroundBuffer![x + i, y] = background;
                }
            }
        }
    }

    public static void Write(int x, int y, char c, ConsoleColor foreground = ConsoleColor.Gray, ConsoleColor background = ConsoleColor.Black)
    {
        lock (_lock)
        {
            if (!_initialized)
                return;

            if (0 <= x && x < _width && 0 <= y && y < _height)
            {
                _currentBuffer![x, y] = c;
                _foregroundBuffer![x, y] = foreground;
                _backgroundBuffer![x, y] = background;
            }
        }
    }

    public static void WriteRightAligned(int x, int y, string text, ConsoleColor foreground = ConsoleColor.Gray, ConsoleColor background = ConsoleColor.Black)
    {
        lock (_lock)
        {
            if (!_initialized)
                return;

            int startX = x - text.Length + 1;
            Write(startX, y, text, foreground, background);
        }
    }

    public static void FillRect(int x, int y, int width, int height, char fillChar = ' ', ConsoleColor foreground = ConsoleColor.Gray, ConsoleColor background = ConsoleColor.Black)
    {
        lock (_lock)
        {
            if (!_initialized)
                return;

            for (int iy = y; iy < y + height && iy < _height; iy++)
            {
                for (int ix = x; ix < x + width && ix < _width; ix++)
                {
                    if (0 <= ix && 0 <= iy)
                    {
                        _currentBuffer![ix, iy] = fillChar;
                        _foregroundBuffer![ix, iy] = foreground;
                        _backgroundBuffer![ix, iy] = background;
                    }
                }
            }
        }
    }

    public static void DrawHLine(int x, int y, int length, char c = '─', ConsoleColor foreground = ConsoleColor.Gray, ConsoleColor background = ConsoleColor.Black)
    {
        lock (_lock)
            Write(x, y, new string(c, length), foreground, background);
    }

    public static void DrawVLine(int x, int y, int length, char c = '│', ConsoleColor foreground = ConsoleColor.Gray, ConsoleColor background = ConsoleColor.Black)
    {
        lock (_lock)
        {
            for (int i = 0; i < length; i++)
                Write(x, y + i, c.ToString(), foreground, background);
        }
    }

    public static void DrawBox(int x, int y, int width, int height, ConsoleColor foreground = ConsoleColor.Gray, ConsoleColor background = ConsoleColor.Black)
    {
        Write(x, y, "┌", foreground, background);
        Write(x + width - 1, y, "┐", foreground, background);
        Write(x, y + height - 1, "└", foreground, background);
        Write(x + width - 1, y + height - 1, "┘", foreground, background);
        DrawHLine(x + 1, y, width - 2, '─', foreground, background);
        DrawHLine(x + 1, y + height - 1, width - 2, '─', foreground, background);
        DrawVLine(x, y + 1, height - 2, '│', foreground, background);
        DrawVLine(x + width - 1, y + 1, height - 2, '│', foreground, background);
    }

    public static void Render()
    {
        lock (_lock)
        {
            if (!_initialized)
                return;

            int actualWidth, actualHeight;
            try
            {
                actualWidth = Console.WindowWidth;
                actualHeight = Console.WindowHeight;
            }
            catch
            {
                return;
            }

            Console.ForegroundColor = ConsoleColor.Gray;
            Console.BackgroundColor = ConsoleColor.Black;

            var currentFore = ConsoleColor.Gray;
            var currentBack = ConsoleColor.Black;
            var scratch = new char[_width];

            for (int y = 0; y < _height; y++)
            {
                if (actualHeight <= y)
                    break;

                int x = 0;

                while (x < _width)
                {
                    int regionStart = -1;
                    int regionLength = 0;
                    ConsoleColor regionFore = ConsoleColor.Gray;
                    ConsoleColor regionBack = ConsoleColor.Black;

                    while (x < _width)
                    {
                        var ch = _currentBuffer![x, y];
                        var fore = _foregroundBuffer![x, y];
                        var back = _backgroundBuffer![x, y];

                        bool isDirty = ch != _previousBuffer![x, y] ||
                                       fore != _previousForeground![x, y] ||
                                       back != _previousBackground![x, y];

                        if (!isDirty)
                        {
                            x++;
                            continue;
                        }

                        regionStart = x;
                        regionFore = fore;
                        regionBack = back;

                        while (x < _width)
                        {
                            if (actualWidth <= x)
                                break;

                            var cch = _currentBuffer[x, y];
                            var cfore = _foregroundBuffer[x, y];
                            var cback = _backgroundBuffer[x, y];

                            bool cellDirty = cch != _previousBuffer[x, y] ||
                                             cfore != _previousForeground![x, y] ||
                                             cback != _previousBackground![x, y];

                            if (!cellDirty)
                            {
                                if (0 < regionLength)
                                    break;

                                x++;
                                continue;
                            }

                            if (cfore == regionFore && cback == regionBack)
                            {
                                scratch[regionLength++] = cch;
                                _previousBuffer[x, y] = cch;
                                _previousForeground![x, y] = cfore;
                                _previousBackground![x, y] = cback;
                                x++;
                            }
                            else if (regionLength == 0)
                            {
                                regionFore = cfore;
                                regionBack = cback;
                                scratch[regionLength++] = cch;
                                _previousBuffer[x, y] = cch;
                                _previousForeground![x, y] = cfore;
                                _previousBackground![x, y] = cback;
                                x++;
                            }
                            else break;
                        }

                        if (0 < regionLength)
                            break;
                    }

                    if (0 < regionLength)
                    {
                        if (0 <= regionStart && regionStart < actualWidth && 0 <= y && y < actualHeight)
                        {
                            try
                            {
                                Console.SetCursorPosition(regionStart, y);
                            }
                            catch
                            {
                                continue;
                            }

                            if (regionFore != currentFore)
                            {
                                Console.ForegroundColor = regionFore;
                                currentFore = regionFore;
                            }

                            if (regionBack != currentBack)
                            {
                                Console.BackgroundColor = regionBack;
                                currentBack = regionBack;
                            }

                            Console.Write(new string(scratch, 0, regionLength));
                        }
                    }
                }
            }
        }
    }

    public static void ResetColors()
    {
        Console.ResetColor();
    }

    public static string Truncate(string text, int maxLength)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= maxLength)
            return text ?? "";

        if (maxLength <= 3)
            return text.Substring(0, maxLength);

        return text.Substring(0, maxLength - 3) + "...";
    }

    public static string PadRight(string text, int length)
    {
        if (string.IsNullOrEmpty(text))
            return new string(' ', length);

        return text.PadRight(length).Substring(0, Math.Min(text.Length, length)).PadRight(length);
    }
}
