// Copyright (c) Microsoft Corporation. All rights reserved.

#nullable disable

using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.WebTools.Shared.VS;

/// <summary>
/// Pinvoke and other win32 declarations.
/// </summary>
internal static class NativeMethods
{
    public const int WM_SYSCOMMAND = 0x0112;
    public const int SC_CLOSE = 0xF060;

    [DllImport("USER32.DLL")]
    public static extern bool EnumWindows(EnumWindowsProc enumFunc, IntPtr lParam);

    [DllImport("USER32.DLL")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("USER32.DLL")]
    public static extern bool IsWindow(IntPtr hWnd);

    [DllImport("USER32.DLL", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("USER32.DLL")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    //WARN: Only for "Any CPU":
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int GetWindowThreadProcessId(IntPtr handle, out uint processId);

    [DllImport("user32")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PostMessage(HandleRef hwnd, int msg, IntPtr wparam, IntPtr lparam);

    [SuppressMessage("Microsoft.Portability", "CA1901:PInvokeDeclarationsShouldBePortable")]
    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    // POSTMESSAGE
    [SuppressMessage("Microsoft.Portability", "CA1901:PInvokeDeclarationsShouldBePortable")]
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
}

internal delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
