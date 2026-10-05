[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $SeedDirectory,
    [Parameter(Mandatory = $true)] [string] $IsoPath,
    [long] $MaximumBytes = 1073741824
)
# IMAPI2FS writes a real ISO9660+Joliet image labelled cidata; no host references.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath $IsoPath) { throw 'ISO already exists.' }
$source = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class SignalBridgeSeedIso
{
    public static void Save(string path, object image, long limit)
    {
        IStream stream = (IStream)image;
        using (FileStream file = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
        {
            byte[] buffer = new byte[1048576];
            IntPtr read = Marshal.AllocHGlobal(4);
            try
            {
                while (true)
                {
                    stream.Read(buffer, buffer.Length, read);
                    int count = Marshal.ReadInt32(read);
                    if (count <= 0) break;
                    if (file.Position + count > limit) throw new InvalidDataException("ISO exceeds bound.");
                    file.Write(buffer, 0, count);
                }
                file.Flush(true);
            }
            finally { Marshal.FreeHGlobal(read); }
        }
    }
}
'@
Add-Type -TypeDefinition $source -Language CSharp
$fsi = $null; $result = $null
try {
    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $fsi.FileSystemsToCreate = 3
    $fsi.ISO9660InterchangeLevel = 2
    $fsi.FreeMediaBlocks = 0
    $fsi.VolumeName = 'cidata'
    $fsi.Root.AddTree($SeedDirectory, $false)
    $result = $fsi.CreateResultImage()
    $length = [long]$result.BlockSize * [long]$result.TotalBlocks
    if ($length -le 0 -or $length -gt $MaximumBytes) { throw 'ISO size outside bound.' }
    [SignalBridgeSeedIso]::Save($IsoPath, $result.ImageStream, $MaximumBytes)
    "{""iso_bytes"": $length}"
}
finally {
    foreach ($com in @($result, $fsi)) {
        if ($null -ne $com -and [Runtime.InteropServices.Marshal]::IsComObject($com)) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($com)
        }
    }
}
