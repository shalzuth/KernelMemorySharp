using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KernelMemorySharp;

namespace MemoryTester
{
    class Program
    {
        [DllImport("kernel32")] static extern IntPtr OpenProcess(Int32 dwDesiredAccess, Boolean bInheritHandle, Int32 dwProcessId);
        [DllImport("kernel32")] static extern Boolean ReadProcessMemory(IntPtr hProcess, Int64 lpBaseAddress, Byte[] lpBuffer, Int32 dwSize, ref Int32 lpNumberOfBytesRead);
        [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
        [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        static unsafe void Main(string[] args)
        {
            var app = "MemoryTester";
            Console.WriteLine("loading driver");
            if (!MemoryDriver.LoadDriver(@"MemoryDriver.sys"))
                throw new Exception("couldn't load driver");
            //MemoryDriver.SetAppToHook(app + ".exe", false);

            /*var baseAddr = UInt64.Parse(Console.ReadLine());
            var size = UInt64.Parse(Console.ReadLine());
            var gm = new List<Byte>();
            for(var i = 0u; i < size; i += 8)
            {
                var v = MemoryDriver.ReadProcessMemory<UInt64>(baseAddr + i);
                gm.AddRange(BitConverter.GetBytes(v));
            }
            System.IO.File.WriteAllBytes("test.bin", gm.ToArray());*/

            //var val = MemoryDriver.ReadProcessMemory<UInt64>(MemoryDriver.BaseAddress + 0x2000);
            var process = Process.GetProcessesByName(app)[0];
            MemoryDriver._ProcessId = process.Id;
            var file = @"C:\Users\WDAGUtilityAccount\Desktop\Debug\dlltest.dll";
            MemoryDriver.ShowConsole();
           // Console.WriteLine(MemoryDriver.GetModule("ucrtbase.dll").ToString("X"));
           // Console.Read();
            MemoryDriver.InjectDll(process.Id, file);
            Console.WriteLine("fin");
            Console.ReadLine();
        }
    }
}
