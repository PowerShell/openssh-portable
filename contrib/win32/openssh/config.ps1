Param($Config_h_vs, $Config_h, $VCIncludePath, $OutCRTHeader)

Copy-Item $Config_h_vs $Config_h -Force
if (Test-Path $OutCRTHeader) {exit}
$headers = ("stdio.h", "string.h", "sys\types.h", "ctype.h", "stdlib.h")
$paths = $VCIncludePath.Split(";")
Set-Content -Path $OutCRTHeader -Value "/*`r`n * DO NOT EDIT - AutoGenerated by config.ps1`r`n */`r`n" -Force
foreach ($header in $headers) {
    foreach ($path in $paths)
    {
        if ($path -and (Test-Path (Join-Path $path $header)))
        {
            $entry = "#define  " + $header.ToUpper().Replace(".","_").Replace("\","_") + "  `"" + (Join-Path $path $header) + "`""
            Add-Content -Path $OutCRTHeader -Value $entry
            break
        }

    }
}