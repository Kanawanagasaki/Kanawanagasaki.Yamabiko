using Kanawanagasaki.Yamabiko.Sample;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

try
{
    await AppUi.RunAsync();
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
