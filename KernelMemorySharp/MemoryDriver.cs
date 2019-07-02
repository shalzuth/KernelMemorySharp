using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace KernelMemorySharp
{
    public unsafe static class MemoryDriver
    {
        public static Int32 ProcessId = 0;
        public static UInt64 BaseAddress = 0;
        [DllImport("ntdll.dll", EntryPoint = "NtOpenFile", ExactSpelling = true, SetLastError = true)]
        public static extern uint NtOpenFile(IntPtr* handle, uint access, OBJECT_ATTRIBUTES* objectAttributes, IO_STATUS_BLOCK* ioStatus, System.IO.FileShare share, uint openOptions);
        [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
        public static extern bool DeviceIoControl(IntPtr hDevice, int dwIoControlCode, void* InBuffer, int nInBufferSize, void* OutBuffer, int nOutBufferSize, ref UInt64 pBytesReturned, uint lpOverlapped);
        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
            public uint status;
            public IntPtr information;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;
            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }
            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }
            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        static IntPtr DeviceHandle;
        public static void Open()
        {
            IO_STATUS_BLOCK ioStatus;
            IntPtr deviceHandle;
            var objectAttributes = new OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            var deviceName = new UNICODE_STRING(@"\Device\shalz");
            objectAttributes.ObjectName = new IntPtr(&deviceName);
            var status = NtOpenFile(&deviceHandle, (uint)(0xC0100000), &objectAttributes, &ioStatus, System.IO.FileShare.None, 3u);
            DeviceHandle = deviceHandle;
        }
        public static void Close()
        {
            CloseHandle(DeviceHandle);
        }
        public static Int32 IOCTL(Int32 Function) { return DriverLoaderSharp.Natives.CTL_CODE(DriverLoaderSharp.Natives.FILE_DEVICE_UNKNOWN, (Function), DriverLoaderSharp.Natives.CtlMethod.Buffered, 0); }
        private static Int32 IOCTL_COOKIE = IOCTL(0x301);
        private static Int32 IOCTL_GET_PROC = IOCTL(0x302);
        private static Int32 IOCTL_GET_MODULE = IOCTL(0x303);
        private static Int32 IOCTL_CALLBACK = IOCTL(0x304);
        private static Int32 IOCTL_RPM = IOCTL(0x305);
        private static Int32 IOCTL_WPM = IOCTL(0x306);
        private static Int32 IOCTL_UNLOAD = DriverLoaderSharp.Natives.CTL_CODE(DriverLoaderSharp.Natives.FILE_DEVICE_UNKNOWN, 0x307, DriverLoaderSharp.Natives.CtlMethod.Neither, 0);
        struct Nop { }

        public static Boolean LoadDriver(String location)
        {
            Open();
            if (GetCookie() == 0x80085)
                return true;
            DriverLoaderSharp.VirtualBox.MapDriver(location);
            Open();
            if (GetCookie() == 0x80085)
                return true;
            return false;
        }
        public static void SetAppToHook(String procName, Boolean launch = false)
        {
            SetCallback(true, procName);
            if (launch) System.Diagnostics.Process.Start(procName);
            while (GetProcId() == 0) System.Threading.Thread.Sleep(500);
            ProcessId = GetProcId();
            BaseAddress = GetModuleAddr();
            SetCallback(false);
        }
        public static Int32 GetCookie()
        {
            return (Int32)DriverLoaderSharp.Natives.DeviceIoControl<UInt64>(DeviceHandle, IOCTL_COOKIE, new UInt64());
        }
        public static Int32 GetProcId()
        {
            return (Int32)DriverLoaderSharp.Natives.DeviceIoControl<UInt64>(DeviceHandle, IOCTL_GET_PROC, new UInt64());
        }
        public static UInt64 GetModuleAddr()
        {
            return DriverLoaderSharp.Natives.DeviceIoControl<UInt64>(DeviceHandle, IOCTL_GET_MODULE, new UInt64());
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IoctlProcessStruct
        {
            public Boolean Load;
            public UNICODE_STRING ProcessName;
            public IoctlProcessStruct(Boolean load, String procName)
            {
                Load = load;
                ProcessName = new UNICODE_STRING(procName);
            }
        };
        public static Boolean SetCallback(Boolean enable, String procName = "")
        {
            var processStruct = new MemoryDriver.IoctlProcessStruct(enable, procName);
            return DriverLoaderSharp.Natives.DeviceIoControl<Boolean>(DeviceHandle, IOCTL_CALLBACK, processStruct);
        }
        public static Boolean UnloadDriver()
        {
            return DriverLoaderSharp.Natives.DeviceIoControl<Boolean>(DeviceHandle, IOCTL_UNLOAD, new Nop());
        }
        [StructLayout(LayoutKind.Sequential)]
        struct IoctlMemoryStruct
        {
            public Int32 ProcessId;
            public UInt64 Address;
            public IntPtr Buffer;
            public Int32 Size;
        };
        public static T ReadProcessMemory<T>(UInt64 addr)
        {
            if (typeof(T) == typeof(String))
            {
                List<Byte> bytes = new List<Byte>();
                for (UInt64 i = 0; i < 16; i++)
                {
                    var letters8 = ReadProcessMemory<UInt64>(addr + i * 8);
                    var tempBytes = BitConverter.GetBytes(letters8);
                    for (int j = 0; j < 8; j++)
                    {
                        if (tempBytes[j] == 0)
                            return (T)(Object)Encoding.UTF8.GetString(bytes.ToArray());
                        bytes.Add(tempBytes[j]);
                    }
                }
                return (T)(Object)Encoding.UTF8.GetString(bytes.ToArray());
            }
            var size = Marshal.SizeOf<T>();
            IntPtr intPtr = Marshal.AllocHGlobal(size);
            var input = new IoctlMemoryStruct();
            input.ProcessId = ProcessId;
            input.Address = addr;
            input.Size = size;
            input.Buffer = intPtr;

            var output = new IoctlMemoryStruct();
            ulong io = 0;
            //var status = DriverLoaderSharp.Natives.DeviceIoControl(new SafeFileHandle(DeviceHandle, true), IOCTL_RPM, (object)&input, Marshal.SizeOf<IoctlMemoryStruct>(), &output, (UInt32)Marshal.SizeOf(typeof(IoctlMemoryStruct)), ref io, 0);
            var status = DeviceIoControl(DeviceHandle, IOCTL_RPM, &input, Marshal.SizeOf<IoctlMemoryStruct>(), &output, Marshal.SizeOf(typeof(IoctlMemoryStruct)), ref io, 0);
            var obj = Marshal.PtrToStructure<T>(intPtr);
            Marshal.FreeHGlobal(intPtr);
            return obj;
        }
        public static void WriteProcessMemory<T>(UInt64 addr, T value)
        {
            var objPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            Marshal.StructureToPtr(value, objPtr, false);
            var size = Marshal.SizeOf(typeof(T));
            var input = new IoctlMemoryStruct();
            input.ProcessId = ProcessId;
            input.Address = addr;
            input.Size = size;
            input.Buffer = objPtr;
            var output = new IoctlMemoryStruct();
            ulong io = 0;
            var status = DeviceIoControl(DeviceHandle, IOCTL_WPM, &input, Marshal.SizeOf<IoctlMemoryStruct>(), &output, Marshal.SizeOf<IoctlMemoryStruct>(), ref io, 0);
            Marshal.FreeHGlobal(objPtr);
        }
    }
}
