[CmdletBinding()]
param(
	[Parameter()]
	[ValidateScript( { Test-Path -LiteralPath $_ -PathType Leaf })]
	[string]
	$ProjectPath,

	[Parameter()]
	[ValidateScript( { Test-Path -LiteralPath $_ -PathType Container })]
	[string]
	$SourceDirectory,

	[Parameter()]
	[ValidateSet('Release', 'Debug')]
	[string]
	$Configuration = 'Release',

	[Parameter()]
	[ValidateSet('x64', 'x86')]
	[string]
	$Platform = 'x64',

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]
	$DestinationPath = $env:TEMP,

	[Parameter()]
	[version]
	$Version,

	[Parameter()]
	[switch]
	$SkipClean
)

Write-Verbose -Message "Start building MSI package for OpenSSH for Windows; CI = [$env:CI]"
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Linq;
/// <summary>
/// Helper methods for working with <see cref="Guid"/>.
/// </summary>
public static class OpenSSH.Portable.GuidUtility
{

	/// <summary>
	/// Creates a name-based UUID using the algorithm from RFC 4122 §4.3.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="name">The name (within that namespace).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
	public static Guid Create(Guid namespaceId, string name)
	{
		return Create(namespaceId, name, 5);
	}

	/// <summary>
	/// Creates a name-based UUID using the algorithm from RFC 4122 §4.3.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="name">The name (within that namespace).</param>
	/// <param name="version">The version number of the UUID to create; this value must be either
	/// 3 (for MD5 hashing) or 5 (for SHA-1 hashing).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
	public static Guid Create(Guid namespaceId, string name, int version)
	{
		if (name == null)
			throw new ArgumentNullException("name");

		// convert the name to a sequence of octets (as defined by the standard or conventions of its namespace) (step 3)
		// ASSUME: UTF-8 encoding is always appropriate
		return Create(namespaceId, System.Text.Encoding.UTF8.GetBytes(name), version);
	}

	/// <summary>
	/// Creates a name-based UUID using the algorithm from RFC 4122 §4.3.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="nameBytes">The name (within that namespace).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
    public static Guid Create(Guid namespaceId, byte[] nameBytes)
    {
        return Create(namespaceId, nameBytes, 5);
    }

	/// <summary>
	/// Creates a name-based UUID using the algorithm from RFC 4122 §4.3.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="nameBytes">The name (within that namespace).</param>
	/// <param name="version">The version number of the UUID to create; this value must be either
	/// 3 (for MD5 hashing) or 5 (for SHA-1 hashing).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
	public static Guid Create(Guid namespaceId, byte[] nameBytes, int version)
	{
		if (version != 3 && version != 5)
			throw new ArgumentOutOfRangeException("version", "version must be either 3 or 5.");

		// convert the namespace UUID to network order (step 3)
		var namespaceBytes = namespaceId.ToByteArray();
		SwapByteOrder(namespaceBytes);

		// compute the hash of the namespace ID concatenated with the name (step 4)
		var data = namespaceBytes.Concat(nameBytes).ToArray();
		byte[] hash;
		using (var algorithm = version == 3 ? (System.Security.Cryptography.HashAlgorithm)System.Security.Cryptography.MD5.Create() : System.Security.Cryptography.SHA1.Create())
			hash = algorithm.ComputeHash(data);

		// most bytes from the hash are copied straight to the bytes of the new GUID (steps 5-7, 9, 11-12)
		var newGuid = new byte[16];
		Array.Copy(hash, 0, newGuid, 0, 16);

		// set the four most significant bits (bits 12 through 15) of the time_hi_and_version field to the appropriate 4-bit version number from Section 4.1.3 (step 8)
		newGuid[6] = (byte)((newGuid[6] & 0x0F) | (version << 4));

		// set the two most significant bits (bits 6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively (step 10)
		newGuid[8] = (byte)((newGuid[8] & 0x3F) | 0x80);

		// convert the resulting UUID to local byte order (step 13)
		SwapByteOrder(newGuid);
		return new Guid(newGuid);
	}

	private static void SwapByteOrder(byte[] guid)
	{
		SwapBytes(guid, 0, 3);
		SwapBytes(guid, 1, 2);
		SwapBytes(guid, 4, 5);
		SwapBytes(guid, 6, 7);
	}

	private static void SwapBytes(byte[] guid, int left, int right)
	{
		var temp = guid[left];
		guid[left] = guid[right];
		guid[right] = temp;
	}
}
"@


$SourceDirectory = Resolve-Path -LiteralPath $SourceDirectory

$msBuildDir = &"${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
if (0 -ne $LASTEXITCODE -or [string]::IsNullOrWhiteSpace($msBuildDir)) {
	if ($env:CI) {
		Write-Host "##vso[task.logissue type=error]MsBuild installation path not found. ErrorCode: $LASTEXITCODE; Error: $msBuildPath"
	}
	throw "MsBuild installation path not found. ErrorCode: $LASTEXITCODE; Error: $msBuildPath"
} else {
	$msBuildPath = Join-Path -Path $msBuildDir -ChildPath 'MSBuild\Current\Bin\MSBuild.exe'
	if (-not (Test-Path -Path $msBuildPath)) {
		$msBuildPath = Join-Path -Path $msBuildDir -ChildPath 'MSBuild\15.0\Bin\MSBuild.exe'
		if (-not (Test-Path -Path $msBuildPath)) {
			if ($env:CI) {
				Write-Host '##vso[task.logissue type=error]MsBuild installation path not found'
			}
			throw 'MsBuild installation path not found.'
		}
	}
}
Write-Verbose -Message "Getting external application msbuild.exe from [$msBuildPath]"

if ([string]::IsNullOrWhiteSpace($Version)) {
	Write-Verbose -Message "Getting version from compiled binaries ..."
	$Version = (Get-ChildItem (Join-Path -Path $SourceDirectory -ChildPath '*.exe')).VersionInfo.FileVersion `
	| Sort-Object -Unique -Descending `
	| Select-Object -First 1

	if (-not $Version) {
		if ($env:CI) {
			Write-Host "##vso[task.logissue type=error]Unable to determine version from files in [$SourceDirectory]"
		}
		throw "Unable to determine version from files in [$SourceDirectory]"
	}
}

$namespace = [guid]'0a9fe0e0-6295-42cc-825e-87661998f45f'
$productID = [OpenSSH.Portable.GuidUtility]::Create($namespace, [string]$Version)

Write-Verbose -Message "ProductId: $productID"
Write-Verbose -Message "Version: $Version"
Write-Verbose -Message "Configuration: $Configuration"
Write-Verbose -Message "Platform: $Platform"
Write-Verbose -Message "SourceDirectory: $SourceDirectory"

$argv = @(
	$ProjectPath,
	"/p:Version=$Version",
	"/p:Configuration=$Configuration",
	"/p:Platform=$Platform",
	"/p:SourceDir=$SourceDirectory"
	"/p:ProductId=$productID"
)

if ($env:CI) {
	$argv += @('-v:detailed')
}
if ($DestinationPath) {
	Write-Verbose -Message "DestinationPath: $DestinationPath"
	$argv += @( "/p:OutputPath=$DestinationPath" )
}

'Clean', 'Build' `
| Where-Object -FilterScript { 'Clean' -ne $_ -or (-not $SkipClean) } `
| ForEach-Object -Process {
	$target = $_

	Write-Verbose -Message "Executing msbuild on target $target"

	& $msBuildPath @argv "/t:$target" 2>&1 | Write-Host
	if (0 -ne $LASTEXITCODE) {
		if ($env:CI) {
			Write-Host "##vso[task.logissue type=error]Failed to build MSI package. ErrorCode: $LASTEXITCODE."
		}
		throw "Failed to build MSI package. ErrorCode: $LASTEXITCODE."
	}
}
