// Copyright (c) Microsoft Corporation. All rights reserved.

#nullable disable

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.WebTools.Shared.VS;

#pragma warning disable IDE1006 // Naming Styles
/// <summary>
/// Pinvoke and other win32 declarations.
/// </summary>
internal static class NativeMethods
{
    public const int WM_SYSCOMMAND = 0x0112;
    public const int SC_CLOSE = 0xF060;
    public const int STATE_SYSTEM_INVISIBLE = 0x00008000;
    public const int GWL_EXSTYLE = -0x14;
    public const int WS_EX_TOOLWINDOW = 0x0080;
    public const int BUFFER_E_RELOAD_OCCURRED = unchecked((int)0x80041009);
    public const int PROCESS_CREATE_PROCESS = (0x0080);
    public const int PROCESS_QUERY_LIMITED_INFORMATION = 0x001000;
    public const uint LOGON_NETCREDENTIALS_ONLY = 0x2;
    public const uint CREATE_NEW_PROCESS_GROUP = 0x200;
    internal const int MONITOR_DEFAULTTONEAREST = 0x00000002;


    public const int WM_KEYFIRST = 0x0100;
    public const int WM_KEYUP = 0x0101;
    public const int WM_SYSKEYUP = 0x0105;
    public const int WM_KEYLAST = 0x0108;
    public const int WM_MOUSEFIRST = 0x0200;
    public const int WM_MOUSELAST = 0x020A;

    public const uint VK_SHIFT = 0x10;
    public const uint VK_CONTROL = 0x11;
    public const uint VK_MENU = 0x12;

    public const int TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const int TOKEN_DUPLICATE = 0x0002;
    public const int TOKEN_QUERY = 0x0008;
    public const int TOKEN_ADJUST_DEFAULT = 0x0080;
    public const int TOKEN_ADJUST_SESSIONID = 0x0100;

    public const int SecurityAnonymous = 0x0;
    public const int TokenPrimary = 0x1;

    // ListView messages
    public const int LVM_EDITLABEL = (0x1000 + 118);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr OpenProcess(int dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public extern static bool DuplicateTokenEx(
         IntPtr hExistingToken,
         uint dwDesiredAccess,
         ref SECURITY_ATTRIBUTES lpTokenAttributes,
         int ImpersonationLevel,
         int TokenType,
         out IntPtr phNewToken);

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithToken(
        IntPtr hToken,
        uint dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("Kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern uint QueryFullProcessImageName(
        [In] IntPtr hProcess,
        [In] uint dwFlags,
        [Out] StringBuilder lpExeName,
        [In, Out] ref uint lpdwSize);


    [DllImport("user32.dll")]
    public static extern bool UnhookWinEvent(IntPtr hWinEventHook);

    [DllImport("USER32.DLL")]
    public static extern IntPtr GetShellWindow();

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

    [DllImport("psapi.dll", CharSet = CharSet.Auto)]
    internal static extern uint GetProcessImageFileName(IntPtr hProcess, [MarshalAs(UnmanagedType.LPWStr)]StringBuilder lpImageFileName, uint nSize);

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

    private const int GWL_STYLE = -16;
    private const int WS_SYSMENU = 0x80000;
    [DllImport("user32.dll", SetLastError = true)]
    public static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

    public static void HideCloseButtonOfWPFDialog(IntPtr hwnd)
    {
        SetWindowLong(hwnd, GWL_STYLE, GetWindowLong(hwnd, GWL_STYLE) & ~WS_SYSMENU);
    }

    [DllImport("user32.dll")]
    public static extern IntPtr GetSystemMenu(IntPtr hwnd, bool bRevert);

    // Menu modification constants
    public const uint MF_BYCOMMAND = 0;
    public const uint MF_BYPOSITION = 0x0400;
    public const uint MF_ENABLED = 0;
    public const uint MF_GRAYED = 1;
    public const uint MF_DISABLED = 2;

    public const int SC_SIZE = 0xF000;
    public const int SC_MINIMIZE = 0xF020;
    public const int SC_MAXIMIZE = 0xF030;
    public const int SC_RESTORE = 0xF120;

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnableMenuItem(IntPtr menu, uint uIDEnableItem, uint uEnable);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetTitleBarInfo(IntPtr hwnd, ref TITLEBARINFO pti);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    public static extern int SHGetKnownFolderPath(ref Guid rfid, int dwFlags, IntPtr hToken, out IntPtr lpszPath);

    [DllImport("user32.dll")]
    internal extern static IntPtr MonitorFromPoint(POINT pt, int dwFlags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal extern static bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class OSVersionInfoEx
    {
        public uint dwOSVersionInfoSize;
        public uint dwMajorVersion;
        public uint dwMinorVersion;
        public uint dwBuildNumber;
        public uint dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public ushort wServicePackMajor;
        public ushort wServicePackMinor;
        public ushort wSuiteMask;
        public byte bProductType;
        public byte bReserved;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Globalization", "CA2101:SpecifyMarshalingForPInvokeStringArguments", MessageId = "OSVersionInfoEx.szCSDVersion")]
    [DllImport("Kernel32.dll", EntryPoint = "GetVersionExW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool GetVersionEx([In, Out] OSVersionInfoEx ver);

    [Flags]
    public enum CREDUI_FLAGS
    {
        INCORRECT_PASSWORD = 0x1,
        DO_NOT_PERSIST = 0x2,
        REQUEST_ADMINISTRATOR = 0x4,
        EXCLUDE_CERTIFICATES = 0x8,
        REQUIRE_CERTIFICATE = 0x10,
        SHOW_SAVE_CHECK_BOX = 0x40,
        ALWAYS_SHOW_UI = 0x80,
        REQUIRE_SMARTCARD = 0x100,
        PASSWORD_ONLY_OK = 0x200,
        VALIDATE_USERNAME = 0x400,
        COMPLETE_USERNAME = 0x800,
        PERSIST = 0x1000,
        SERVER_CREDENTIAL = 0x4000,
        EXPECT_CONFIRMATION = 0x20000,
        GENERIC_CREDENTIALS = 0x40000,
        USERNAME_TARGET_CREDENTIALS = 0x80000,
        KEEP_USERNAME = 0x100000,
    }

    public struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszMessageText;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszCaptionText;
        public IntPtr hbmBanner;
    }

    public enum CredUIReturnCodes
    {
        NO_ERROR = 0,
        ERROR_CANCELLED = 1223,
        ERROR_NO_SUCH_LOGON_SESSION = 1312,
        ERROR_NOT_FOUND = 1168,
        ERROR_INVALID_ACCOUNT_NAME = 1315,
        ERROR_INSUFFICIENT_BUFFER = 122,
        ERROR_INVALID_PARAMETER = 87,
        ERROR_INVALID_FLAGS = 1004,
    }

    [DllImport("credui", CharSet = CharSet.Unicode, EntryPoint = "CredUIPromptForCredentialsW", ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
    private static extern CredUIReturnCodes CredUIPromptForCredentials(ref CREDUI_INFO creditUR,
              string targetName,
              IntPtr reserved1,
              int iError,
              StringBuilder userName,
              int maxUserName,
              StringBuilder password,
              int maxPassword,
              [MarshalAs(UnmanagedType.Bool)] ref bool pfSave,
              CREDUI_FLAGS flags);

    private const int MAX_USER_NAME = 50;
    private const int MAX_PASSWORD = 127;

    public static CredUIReturnCodes PromptForCredentials(
              ref CREDUI_INFO creditUI,
              string targetName,
              int netError,
              ref string userName,
              ref string password,
              ref bool save,
              CREDUI_FLAGS flags)
    {

        StringBuilder user = new StringBuilder(MAX_USER_NAME);
        if (!string.IsNullOrEmpty(userName) && userName.Length < MAX_USER_NAME)
            user.Append(userName);
        StringBuilder pwd = new StringBuilder(MAX_PASSWORD);
        creditUI.cbSize = Marshal.SizeOf(creditUI);

        CredUIReturnCodes result = CredUIPromptForCredentials(
                      ref creditUI,
                      targetName,
                      IntPtr.Zero,
                      netError,
                      user,
                      MAX_USER_NAME,
                      pwd,
                      MAX_PASSWORD,
                      ref save,
                      flags);

        userName = user.ToString();
        password = pwd.ToString();

        return result;
    }

    [DllImport("Kernel32.dll", EntryPoint = "Wow64RevertWow64FsRedirection", ExactSpelling = true, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool Wow64RevertWow64FsRedirection(IntPtr oldValue);

    [DllImport("Kernel32.dll", EntryPoint = "Wow64DisableWow64FsRedirection", ExactSpelling = true, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool Wow64DisableWow64FsRedirection(out IntPtr oldValue);

    [DllImport("kernel32", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool pIsWow64);

    [DllImport("kernel32.dll", SetLastError = false, CharSet = CharSet.Unicode)]
    internal static extern IntPtr OpenFileMapping(uint dwDesiredAccess, bool bInheritHandle, string lpName);

    /// <summary>
    /// This function checks if the OS is 64 bits.
    /// </summary>
    public static bool IsWow64()
    {
        bool isWow64 = false;
        System.Diagnostics.Process curProcess = System.Diagnostics.Process.GetCurrentProcess();
        try
        {
            IsWow64Process(curProcess.Handle, out isWow64);
        }
        catch (Exception e)
        {
            isWow64 = false;
            Debug.Fail("Failed in calling IsWow64Process: " + e.Message);
        }
        return isWow64;
    }

    public const ushort IMAGE_FILE_MACHINE_UNKNOWN = unchecked(0);
    public const ushort IMAGE_FILE_MACHINE_ARM64 = unchecked(0xAA64);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);

    public static bool IsArm64OperatingSystem()
    {
        if (GetWowProcessInformation(out ushort _, out ushort nativeMachine))
        {
            return nativeMachine == IMAGE_FILE_MACHINE_ARM64;
        }

        return false;
    }

    public static bool CurrentProcessIsArm64()
    {
        if (GetWowProcessInformation(out ushort processMachine, out ushort nativeMachine))
        {
            // This is a bit tricky. If the process is not running in a WOW, processMachine will be unknown. So, it is
            // ARM64 if the machine architecture is ARM64 and the process is not running in a WOW
            return processMachine == IMAGE_FILE_MACHINE_UNKNOWN && nativeMachine == IMAGE_FILE_MACHINE_ARM64;
        }

        return false;
    }

    public static bool GetWowProcessInformation(out ushort processMachine, out ushort nativeMachine)
    {
        processMachine = 0;
        nativeMachine = 0; 
        // IsWow64Process2 is not available on all supported versions of Windows (namely Server 2016, windows8) so
        // protect it with a try/catch
        try
        {
            IntPtr handle = Process.GetCurrentProcess().Handle;
            return IsWow64Process2(handle, out processMachine, out nativeMachine);
       }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }

    [DllImport("Oleaut32.dll", PreserveSig = false)]
    private static extern void VariantClear(IntPtr variant);

    public static void VariantClearInternal(IntPtr variant)
    {
        VariantClear(variant);
    }

    public static bool Succeeded(int hr)
    {
        return hr >= 0;
    }

    public static bool Failed(int hr)
    {
        return hr < 0;
    }

    public static int ThrowOnFailure(int hr)
    {
        if (Failed(hr))
        {
            Marshal.ThrowExceptionForHR(hr);
        }

        return hr;
    }
}

internal delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

[Flags]
internal enum ThreadAccess : int
{
    TERMINATE = (0x0001),
    SUSPEND_RESUME = (0x0002),
    GET_CONTEXT = (0x0008),
    SET_CONTEXT = (0x0010),
    SET_INFORMATION = (0x0020),
    QUERY_INFORMATION = (0x0040),
    SET_THREAD_TOKEN = (0x0080),
    IMPERSONATE = (0x0100),
    DIRECT_IMPERSONATION = (0x0200)
}

[StructLayout(LayoutKind.Sequential)]
internal struct TITLEBARINFO
{
    public int cbSize;
    public RECT rcTitleBar;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public int[] rgstate;
}

/// <summary>
/// A rect structure to match the Win32 RECT
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct RECT
{
    public int left;
    public int top;
    public int right;
    public int bottom;
}

/// <summary>
/// Win32 MONITORINFO Struct
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MONITORINFO
{
    // When we move to C# language version 10.0 and can use parameterless
    // constructors on structs, move the logic of "SetSize" into
    // that constructor.
    public void SetSize()
    {
        cbSize = Marshal.SizeOf(this);
    }

    public int cbSize;
    public RECT rcMonitor;
    public RECT rcWork;
    public int dwFlags;
};

/// <summary>
/// A point structure to match the Win32 POINT
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct POINT
{
    public int x;
    public int y;
};

[Flags]
internal enum WinEventHookFlags
{
    // The callback function is NOT mapped into the address space of the process that generates the event.
#pragma warning disable CA1008 // Enums should have zero value
    OutOfContext = 0x0000,
#pragma warning restore CA1008 // Enums should have zero value
    // Prevents this instance of the hook from receiving the events that are generated by the thread that
    // is registering this hook.
    SkipOwnThread = 0x0001,
    // Prevents this instance of the hook from receiving the events that are generated by threads
    // in this process. This flag does not prevent threads from generating events.
    SkipOwnProcess = 0x0002,
    // The callback function IS mapped into the address space of the process that generates the event.
    InContext = 0x0004
}

[Flags]
internal enum STARTFLAGS
{
    STARTF_USESHOWWINDOW = 0x00000001,
    STARTF_USESIZE = 0x00000002,
    STARTF_USEPOSITION = 0x00000004,
    STARTF_USECOUNTCHARS = 0x00000008,
    STARTF_USEFILLATTRIBUTE = 0x00000010,
    STARTF_RUNFULLSCREEN = 0x00000020,
    STARTF_FORCEONFEEDBACK = 0x00000040,
    STARTF_FORCEOFFFEEDBACK = 0x00000080,
    STARTF_USESTDHANDLES = 0x00000100,
    STARTF_USEHOTKEY = 0x00000200
};

[StructLayout(LayoutKind.Sequential)]
internal struct SECURITY_ATTRIBUTES
{
    public int nLength;
    public IntPtr lpSecurityDescriptor;
    public int bInheritHandle;
}

[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct STARTUPINFO
{
    internal int cb;
    internal string lpReserved;
    internal string lpDesktop;
    internal string lpTitle;
    internal int dwX;
    internal int dwY;
    internal int dwXSize;
    internal int dwYSize;
    internal int dwXCountChars;
    internal int dwYCountChars;
    internal int dwFillAttribute;
    internal STARTFLAGS dwFlags;
    internal short wShowWindow;
    internal short cbReserved2;
    internal IntPtr lpReserved2;
    internal IntPtr hStdInput;
    internal IntPtr hStdOutput;
    internal IntPtr hStdError;
}

[Flags]
public enum CreationFlags
{
    CREATE_SUSPENDED = 0x00000004,
    CREATE_NEW_CONSOLE = 0x00000010,
    CREATE_NEW_PROCESS_GROUP = 0x00000200,
    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
    CREATE_SEPARATE_WOW_VDM = 0x00000800,
    CREATE_DEFAULT_ERROR_MODE = 0x04000000,
    CREATE_NOWINDOW = 0x08000000,
}

/// <summary>
/// Contains basic and extended limit information for a job object.
/// </summary>
/// <remarks>
/// <para>The system tracks the value of PeakProcessMemoryUsed and PeakJobMemoryUsed constantly. This allows you know the peak memory usage of each job. You can use this information to establish a memory limit using the JOB_OBJECT_LIMIT_PROCESS_MEMORY or JOB_OBJECT_LIMIT_JOB_MEMORY value.</para>
/// <para>Note that the job memory and process memory limits are very similar in operation, but they are independent. You could set a job-wide limit of 100 MB with a per-process limit of 10 MB. In this scenario, no single process could commit more than 10 MB, and the set of processes associated with a job could never exceed 100 MB.</para>
/// <para>To register for notifications that a job has exceeded its peak memory limit while allowing processes to continue to commit memory, use the SetInformationJobObject function with the JobObjectNotificationLimitInformation information class.</para>
/// </remarks>
internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
{
    /// <summary>
    /// A <see cref="JOBOBJECT_BASIC_LIMIT_INFORMATION"/> structure that contains basic limit information.
    /// </summary>
    internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;

    /// <summary>
    /// Reserved.
    /// </summary>
    internal IO_COUNTERS IoInfo;

    /// <summary>
    /// If the <see cref="JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags"/> member of the <see cref="JOBOBJECT_BASIC_LIMIT_INFORMATION"/> structure specifies the
    /// <see cref="JOB_OBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_PROCESS_MEMORY"/> value, this member specifies the limit for the virtual memory that can be committed by a process.
    /// Otherwise, this member is ignored.
    /// </summary>
    internal UIntPtr ProcessMemoryLimit;

    /// <summary>
    /// If the <see cref="JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags"/> member of the <see cref="JOBOBJECT_BASIC_LIMIT_INFORMATION"/> structure specifies the
    /// <see cref="JOB_OBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_JOB_MEMORY"/> value,
    /// this member specifies the limit for the virtual memory that can be committed for the job. Otherwise, this member is ignored.
    /// </summary>
    internal UIntPtr JobMemoryLimit;

    /// <summary>
    /// The peak memory used by any process ever associated with the job.
    /// </summary>
    internal UIntPtr PeakProcessMemoryUsed;

    /// <summary>
    /// The peak memory usage of all processes currently associated with the job.
    /// </summary>
    internal UIntPtr PeakJobMemoryUsed;
}

/// <summary>
/// Contains basic limit information for a job object.
/// </summary>
internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
{
    /// <summary>
    /// If LimitFlags specifies JOB_OBJECT_LIMIT_PROCESS_TIME, this member is the per-process user-mode execution time limit, in 100-nanosecond ticks. Otherwise, this member is ignored.
    /// </summary>
    internal long PerProcessUserTimeLimit;

    /// <summary>
    /// If LimitFlags specifies JOB_OBJECT_LIMIT_JOB_TIME, this member is the per-job user-mode execution time limit, in 100-nanosecond ticks. Otherwise, this member is ignored.
    /// </summary>
    internal long PerJobUserTimeLimit;

    /// <summary>
    /// The limit flags that are in effect. This member is a bitfield that determines whether other structure members are used.
    /// </summary>
    internal JOB_OBJECT_LIMIT_FLAGS LimitFlags;

    /// <summary>
    /// If LimitFlags specifies JOB_OBJECT_LIMIT_WORKINGSET, this member is the minimum working set size in bytes for each process associated with the job. Otherwise, this member is ignored.
    /// </summary>
    internal UIntPtr MinWorkingSetSize;

    /// <summary>
    /// If LimitFlags specifies JOB_OBJECT_LIMIT_WORKINGSET, this member is the maximum working set size in bytes for each process associated with the job. Otherwise, this member is ignored.
    /// </summary>
    internal UIntPtr MaxWorkingSetSize;

    /// <summary>
    /// If LimitFlags specifies JOB_OBJECT_LIMIT_ACTIVE_PROCESS, this member is the active process limit for the job. Otherwise, this member is ignored.
    /// </summary>
    internal uint ActiveProcessLimit;

    /// <summary>
    /// If LimitFlags specifies JOB_OBJECT_LIMIT_AFFINITY, this member is the processor affinity for all processes associated with the job. Otherwise, this member is ignored.
    /// </summary>
    internal UIntPtr Affinity;

    /// <summary>
    /// If LimitFlags specifies JOB_OBJECT_LIMIT_PRIORITY_CLASS, this member is the priority class for all processes associated with the job. Otherwise, this member is ignored.
    /// </summary>
    internal uint PriorityClass;

    /// <summary>
    /// If LimitFlags specifies JOB_OBJECT_LIMIT_SCHEDULING_CLASS, this member is the scheduling class for all processes associated with the job. Otherwise, this member is ignored.
    /// </summary>
    internal uint SchedulingClass;
}

/// <summary>
/// Contains I/O accounting information for a process or a job object.
/// For a job object, the counters include all operations performed by all processes that have ever been associated with the job,
/// in addition to all processes currently associated with the job.
/// </summary>
internal struct IO_COUNTERS
{
    /// <summary>
    /// The number of read operations performed.
    /// </summary>
    internal ulong ReadOperationCount;

    /// <summary>
    /// The number of write operations performed.
    /// </summary>
    internal ulong WriteOperationCount;

    /// <summary>
    /// The number of I/O operations performed, other than read and write operations.
    /// </summary>
    internal ulong OtherOperationCount;

    /// <summary>
    /// The number of bytes read.
    /// </summary>
    internal ulong ReadTransferCount;

    /// <summary>
    /// The number of bytes written.
    /// </summary>
    internal ulong WriteTransferCount;

    /// <summary>
    /// The number of bytes transferred during operations other than read and write operations.
    /// </summary>
    internal ulong OtherTransferCount;
}

/// <summary>
/// The limit flags that are in effect.
/// </summary>
[Flags]
internal enum JOB_OBJECT_LIMIT_FLAGS
{
    /// <summary>
    /// Causes all processes associated with the job to use the same minimum and maximum working set sizes.
    /// </summary>
    JOB_OBJECT_LIMIT_WORKINGSET = 0x1,

    /// <summary>
    /// Causes all processes associated with the job to use the same priority class.
    /// </summary>
    JOB_OBJECT_LIMIT_PROCESS_TIME = 0x2,

    /// <summary>
    /// Establishes a user-mode execution time limit for the job.
    /// </summary>
    JOB_OBJECT_LIMIT_JOB_TIME = 0x4,

    /// <summary>
    /// Establishes a maximum number of simultaneously active processes associated with the job.
    /// </summary>
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8,

    /// <summary>
    /// Causes all processes associated with the job to use the same processor affinity.
    /// </summary>
    JOB_OBJECT_LIMIT_AFFINITY = 0x10,

    /// <summary>
    /// Causes all processes associated with the job to use the same priority class.
    /// </summary>
    JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x20,

    /// <summary>
    /// Preserves any job time limits you previously set. As long as this flag is set, you can establish a per-job time limit once, then alter other limits in subsequent calls.
    /// </summary>
    JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME = 0x40,

    /// <summary>
    /// Causes all processes in the job to use the same scheduling class.
    /// </summary>
    JOB_OBJECT_LIMIT_SCHEDULING_CLASS = 0x80,

    /// <summary>
    /// Causes all processes associated with the job to limit their committed memory.
    /// </summary>
    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100,

    /// <summary>
    /// Causes all processes associated with the job to limit the job-wide sum of their committed memory.
    /// </summary>
    JOB_OBJECT_LIMIT_JOB_MEMORY = 0x200,

    /// <summary>
    /// Forces a call to the SetErrorMode function with the SEM_NOGPFAULTERRORBOX flag for each process associated with the job.
    /// </summary>
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400,

    /// <summary>
    /// If any process associated with the job creates a child process using the CREATE_BREAKAWAY_FROM_JOB flag while this limit is in effect, the child process is not associated with the job.
    /// </summary>
    JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x800,

    /// <summary>
    /// Allows any process associated with the job to create child processes that are not associated with the job.
    /// </summary>
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x1000,

    /// <summary>
    /// Causes all processes associated with the job to terminate when the last handle to the job is closed.
    /// </summary>
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000,

    /// <summary>
    /// Allows processes to use a subset of the processor affinity for all processes associated with the job.
    /// </summary>
    JOB_OBJECT_LIMIT_SUBSET_AFFINITY = 0x4000,
}

/// <summary>
/// The information class for the limits to be set.
/// </summary>
/// <remarks>
/// Taken from https://msdn.microsoft.com/en-us/library/windows/desktop/ms686216(v=vs.85).aspx.
/// </remarks>
[SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "PInvoke API")]
internal enum JOBOBJECTINFOCLASS
{
    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a <see cref="JOBOBJECT_BASIC_LIMIT_INFORMATION" /> structure.
    /// </summary>
    JobObjectBasicLimitInformation = 2,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_BASIC_UI_RESTRICTIONS structure.
    /// </summary>
    JobObjectBasicUIRestrictions = 4,

    /// <summary>
    /// This flag is not supported. Applications must set security limitations individually for each process.
    /// </summary>
    JobObjectSecurityLimitInformation = 5,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_END_OF_JOB_TIME_INFORMATION structure.
    /// </summary>
    JobObjectEndOfJobTimeInformation = 6,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_ASSOCIATE_COMPLETION_PORT structure.
    /// </summary>
    JobObjectAssociateCompletionPortInformation = 7,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a <see cref="JOBOBJECT_EXTENDED_LIMIT_INFORMATION" /> structure.
    /// </summary>
    JobObjectExtendedLimitInformation = 9,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a USHORT value that specifies the list of processor groups to assign the job to.
    /// The cbJobObjectInfoLength parameter is set to the size of the group data. Divide this value by sizeof(USHORT) to determine the number of groups.
    /// </summary>
    JobObjectGroupInformation = 11,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION structure.
    /// </summary>
    JobObjectNotificationLimitInformation = 12,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a buffer that contains an array of GROUP_AFFINITY structures that specify the affinity of the job for the processor groups to which the job is currently assigned.
    /// The cbJobObjectInfoLength parameter is set to the size of the group affinity data. Divide this value by sizeof(GROUP_AFFINITY) to determine the number of groups.
    /// </summary>
    JobObjectGroupInformationEx = 14,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_CPU_RATE_CONTROL_INFORMATION structure.
    /// </summary>
    JobObjectCpuRateControlInformation = 15,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_NET_RATE_CONTROL_INFORMATION structure.
    /// </summary>
    JobObjectNetRateControlInformation = 32,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2 structure.
    /// </summary>
    JobObjectNotificationLimitInformation2 = 34,

    /// <summary>
    /// The lpJobObjectInfo parameter is a pointer to a JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2 structure.
    /// </summary>
    JobObjectLimitViolationInformation2 = 35,
}

#pragma warning restore IDE1006 // Naming Styles

