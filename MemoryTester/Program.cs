using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using KernelMemorySharp;

namespace MemoryTester
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(Int32 dwDesiredAccess, Boolean bInheritHandle, Int32 dwProcessId);
        [DllImport("kernel32.dll")]
        static extern Boolean ReadProcessMemory(Int32 hProcess, Int64 lpBaseAddress, Byte[] lpBuffer, Int32 dwSize, ref Int32 lpNumberOfBytesRead);

        static void Main(string[] args)
        {
            if (!MemoryDriver.LoadDriver(@"MemoryDriver.sys"))
                throw new Exception("couldn't load driver");
            MemoryDriver.SetAppToHook("notepad.exe", true);
            var val = MemoryDriver.ReadProcessMemory<UInt64>(MemoryDriver.BaseAddress + 0x200);

            var process =  Process.GetProcessesByName("notepad")[0];
            var processHandle = OpenProcess(0x0010, false, process.Id);
            Int32 bytesRead = 0;
            var buffer = new Byte[8];
            ReadProcessMemory(processHandle.ToInt32(), process.MainModule.BaseAddress.ToInt64() + 0x200, buffer, buffer.Length, ref bytesRead);
            var val2 = BitConverter.ToUInt64(buffer, 0);
            Console.WriteLine("kernel driver status : " + (val == val2));
            Console.WriteLine("press any key to exit");
            Console.ReadLine();
        }
    }
}
