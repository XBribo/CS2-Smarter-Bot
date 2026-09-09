using CounterStrikeSharp.API.Core;
using CounterStrikeSharp.API.Modules.Memory;
using System;
using System.Runtime.InteropServices;

namespace BotState;

public partial class BotState
{

    // 360 FOV patch constants for fake defuse search phase
    private const uint PageExecuteReadWrite = 0x40;

    // 360 FOV patch tracking for fake defuse search
    private sealed record FovPatchDefinition(
        string Name,
        string Signature,
        int Offset,
        byte[] Expected,
        byte[] Replacement);

    private sealed record AppliedFovPatch(
        string Name,
        nint Address,
        byte[] Original);

    private static readonly FovPatchDefinition[] FovPatches =
    [
        new(
            "IsVisiblePos_IgnoreFOV",
            "48 8D 05 ? ? ? ? 48 C7 45 98 1F 01 00 00 48 89 45 90 45 0F B6 E8 0F 10 45 90",
            19,
            [0x45, 0x0F, 0xB6, 0xE8],       // movzx r13d, r8b
            [0x45, 0x33, 0xED, 0x90]),      // xor r13d, r13d; nop

        new(
            "IsVisiblePlayer_IgnoreFOV",
            "48 8D 05 ? ? ? ? 48 C7 45 CF 4D 01 00 00 48 89 45 C7 41 0F B6 D8 0F 10 45 C7",
            19,
            [0x41, 0x0F, 0xB6, 0xD8],       // movzx ebx, r8b
            [0x33, 0xDB, 0x90, 0x90]),      // xor ebx, ebx; nop; nop
    ];

    private static readonly FovPatchDefinition[] LinuxFovPatches =
    [
        new(
            "IsVisiblePos_IgnoreFOV",
            "80 BD ? ? ? ? 00 74 ? 48 8B 7B 18 48 8B B5 ? ? ? ? 48 8B 07 FF 90 A0 09 00 00 84 C0 74 ?",
            7,
            [0x74],                         // je no-FOV path
            [0xEB]),                        // jmp no-FOV path

        new(
            "IsVisiblePlayer_IgnoreFOV",
            "45 84 F6 74 ? 49 8B 54 24 18 48 89 DF 48 8B 0A 48 89 55 98 48 8B 89 A0 09 00 00 48 89 4D A0 FF 90 B8 02 00 00",
            3,
            [0x74],                         // je no-FOV path
            [0xEB]),                        // jmp no-FOV path
    ];

    private const int LinuxPageRead = 0x1;
    private const int LinuxPageWrite = 0x2;
    private const int LinuxPageExecute = 0x4;
    private const int LinuxPageExecuteReadWrite =
        LinuxPageRead | LinuxPageWrite | LinuxPageExecute;
    private const int LinuxPageExecuteRead = LinuxPageRead | LinuxPageExecute;

    private readonly List<AppliedFovPatch> _appliedFovPatches = [];
    private bool _fovPatchesAvailable = false;

    //---------------------------------------------------------------------------------------
    // 360 FOV patch system for fake defuse search phase
    //---------------------------------------------------------------------------------------

    // Enables FOV patching on supported platforms
    private void InitializeFovPatches()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            _fovPatchesAvailable = false;
            return;
        }

        _fovPatchesAvailable = true;
    }

    // Applies the platform-specific FOV branch patches
    private void ApplyFovPatches()
    {
        if (!_fovPatchesAvailable || _appliedFovPatches.Count > 0)
            return;

        FovPatchDefinition[] patches = RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
            ? LinuxFovPatches
            : FovPatches;

        foreach (FovPatchDefinition patch in patches)
        {
            if (!TryApplyFovPatch(patch))
            {
                RestoreAllFovPatches();
                _fovPatchesAvailable = false;
                return;
            }
        }
    }

    // Applies one FOV patch after validating its original bytes
    private bool TryApplyFovPatch(FovPatchDefinition patch)
    {
        try
        {
            nint signatureAddress = NativeAPI.FindSignature(
                Addresses.ServerPath,
                patch.Signature);

            if (signatureAddress == nint.Zero)
                return false;

            nint address = signatureAddress + patch.Offset;
            byte[] original = new byte[patch.Replacement.Length];
            Marshal.Copy(address, original, 0, original.Length);

            if (!original.SequenceEqual(patch.Expected))
                return false;

            if (!WriteExecutableMemory(address, patch.Replacement))
            {
                WriteExecutableMemory(address, original);
                return false;
            }

            _appliedFovPatches.Add(new AppliedFovPatch(patch.Name, address, original));
            return true;
        }
        catch
        {
            return false;
        }
    }

    // Restores all FOV patches applied during the current search phase
    private void RestoreAllFovPatches()
    {
        for (int i = _appliedFovPatches.Count - 1; i >= 0; i--)
        {
            AppliedFovPatch patch = _appliedFovPatches[i];
            WriteExecutableMemory(patch.Address, patch.Original);
        }

        _appliedFovPatches.Clear();
    }

    // Writes bytes into executable text memory on Linux and restores RX permissions
    private static bool WriteLinuxExecutableMemory(nint address, byte[] bytes)
    {
        if (bytes.Length == 0)
            return true;

        long pageSize = Environment.SystemPageSize;
        if (pageSize <= 0 || (pageSize & (pageSize - 1)) != 0)
            return false;

        long addressValue = address.ToInt64();
        long endAddress;
        long pageEnd;
        try
        {
            endAddress = checked(addressValue + bytes.Length);
            pageEnd = checked((endAddress + pageSize - 1) & ~(pageSize - 1));
        }
        catch (OverflowException)
        {
            return false;
        }

        long pageStart = addressValue & ~(pageSize - 1);
        if (pageEnd <= pageStart)
            return false;

        nint pageAddress = (nint)pageStart;
        nuint pageLength = (nuint)(pageEnd - pageStart);
        if (MProtect(pageAddress, pageLength, LinuxPageExecuteReadWrite) != 0)
            return false;

        bool success = false;
        try
        {
            Marshal.Copy(bytes, 0, address, bytes.Length);
            success = true;
        }
        finally
        {
            if (MProtect(pageAddress, pageLength, LinuxPageExecuteRead) != 0)
                success = false;
        }

        return success;
    }

    // Writes bytes into executable memory and restores platform page permissions
    private static bool WriteExecutableMemory(nint address, byte[] bytes)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return WriteLinuxExecutableMemory(address, bytes);

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return false;

        if (!VirtualProtect(address, (nuint)bytes.Length, PageExecuteReadWrite, out uint oldProtect))
            return false;

        bool success = false;
        try
        {
            Marshal.Copy(bytes, 0, address, bytes.Length);
            success = FlushInstructionCache(GetCurrentProcess(), address, (nuint)bytes.Length);
        }
        finally
        {
            if (!VirtualProtect(address, (nuint)bytes.Length, oldProtect, out _))
                success = false;
        }

        return success;
    }

    // Changes page protection on Windows
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualProtect(
        nint address,
        nuint size,
        uint newProtect,
        out uint oldProtect);

    // Changes page permissions on Linux
    [DllImport("libc.so.6", EntryPoint = "mprotect", SetLastError = true)]
    private static extern int MProtect(
        nint address,
        nuint size,
        int protection);

    // Returns the current process handle on Windows
    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    // Flushes modified instruction bytes from the Windows instruction cache
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushInstructionCache(
        nint process,
        nint baseAddress,
        nuint size);
}
