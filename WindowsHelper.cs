using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Microsoft.WebTools.Shared.VS
{
    public class WindowHelper
    {
        /// <summary>
        /// Represents information about a window
        /// </summary>
        public class WindowInfo
        {
            public IntPtr Hwnd { get; set; }
            public string Title { get; set; }
            public uint ParentProcessId { get; set; }
            public string ParentProcessName { get; set; }
        }

        /// <summary>
        /// Gets information about all top-level windows
        /// </summary>
        /// <returns>List of WindowInfo objects</returns>
        public static List<WindowInfo> GetTopLevelWindows()
        {
            var windows = new List<WindowInfo>();
            
            NativeMethods.EnumWindows((hwnd, lParam) =>
            {
                // Only get visible windows
                if (!NativeMethods.IsWindowVisible(hwnd))
                    return true;

                // Get window title
                int length = NativeMethods.GetWindowTextLength(hwnd);
                if (length == 0)
                    return true;

                StringBuilder title = new StringBuilder(length + 1);
                NativeMethods.GetWindowText(hwnd, title, title.Capacity);

                // Get process info
                uint processId;
                NativeMethods.GetWindowThreadProcessId(hwnd, out processId);

                string processName = "";
                try
                {
                    using (var process = Process.GetProcessById((int)processId))
                    {
                        processName = process.ProcessName;
                    }
                }
                catch
                {
                    // Process may have exited
                    processName = "Unknown";
                }

                windows.Add(new WindowInfo
                {
                    Hwnd = hwnd,
                    Title = title.ToString(),
                    ParentProcessId = processId,
                    ParentProcessName = processName
                });

                return true;
            }, IntPtr.Zero);

            return windows;
        }

        /// <summary>
        /// Sends a close message to the specified window
        /// </summary>
        /// <param name="hwnd">Window handle to close</param>
        public static void SendCloseMessage(IntPtr hwnd)
        {
            if (NativeMethods.IsWindow(hwnd))
            {
                NativeMethods.SendMessage(hwnd, NativeMethods.WM_SYSCOMMAND, (IntPtr)NativeMethods.SC_CLOSE, IntPtr.Zero);
            }
        }

        public static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return 1;
            }

            switch (args[0].ToLowerInvariant())
            {
                case "list":
                    ListWindows();
                    return 0;

                case "close":
                    if (args.Length < 2)
                    {
                        Console.WriteLine("Error: Please provide a window handle");
                        PrintUsage();
                        return 1;
                    }

                    string handleStr = args[1].Replace("0x", "");  // Remove 0x prefix if present
                    if (!long.TryParse(handleStr, 
                        System.Globalization.NumberStyles.HexNumber, 
                        null, 
                        out long handleValue))
                    {
                        Console.WriteLine("Error: Invalid window handle format");
                        PrintUsage();
                        return 1;
                    }
                    
                    SendCloseMessage(new IntPtr(handleValue));
                    return 0;

                default:
                    Console.WriteLine($"Unknown command: {args[0]}");
                    PrintUsage();
                    return 1;
            }
        }

        private static void ListWindows()
        {
            var windows = GetTopLevelWindows();
            foreach (var window in windows)
            {
                Console.WriteLine($"Handle: 0x{window.Hwnd.ToInt64():X8}");
                Console.WriteLine($"Title: {window.Title}");
                Console.WriteLine($"Process: {window.ParentProcessName} (PID: {window.ParentProcessId})");
                Console.WriteLine();
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  WindowHelper list              - List all visible windows");
            Console.WriteLine("  WindowHelper close <handle>    - Close window by handle");
            Console.WriteLine();
            Console.WriteLine("Example:");
            Console.WriteLine("  WindowHelper close 0x00A3B4C5");
        }
    }
}