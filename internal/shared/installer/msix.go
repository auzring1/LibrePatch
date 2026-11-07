package installer

import (
	"path"
	"regexp"
	"strings"
)

// MSIX / AppX packages (D151). They are not installed by running a program the package carries: the agent runs a fixed
// PowerShell script of its own (below) that provisions the package for every user of the computer and, for people who are
// signed in right now, registers it at once. Nothing executable comes from the server; the script receives the package's
// path, its identity name and its version as parameters only.

var (
	appxNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-]{0,49}$`)
	// Name_Version_Architecture_ResourceId_PublisherId, the full name of an installed package; the resource id is usually empty.
	appxFullRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9.\-]{0,49})_(\d+(?:\.\d+){1,3})_([A-Za-z0-9]+)_([A-Za-z0-9\-]*)_([a-z0-9]{13})$`)
	// Name_PublisherId, the family name winget manifests carry.
	appxFamilyRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9.\-]{0,49})_([a-z0-9]{13})$`)
)

// MSIXExtensions are the file extensions of a package or bundle.
var MSIXExtensions = []string{".msix", ".msixbundle", ".appx", ".appxbundle"}

// IsMSIXFileName reports whether name has the extension of an AppX/MSIX package or bundle.
func IsMSIXFileName(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	for _, e := range MSIXExtensions {
		if ext == e {
			return true
		}
	}
	return false
}

// ValidAppxName reports whether s is a package identity name (letters, digits, dots and dashes, at most 50 characters).
func ValidAppxName(s string) bool { return appxNameRe.MatchString(s) }

// AppxNameFromFamily returns the identity name of a package family name ("Microsoft.WindowsTerminal_8wekyb3d8bbwe").
func AppxNameFromFamily(family string) (string, bool) {
	m := appxFamilyRe.FindStringSubmatch(strings.TrimSpace(family))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// AppxNameFromFullName returns the identity name of an installed package's full name.
func AppxNameFromFullName(full string) (string, bool) {
	m := appxFullRe.FindStringSubmatch(full)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// AppxDetectionKey is the key of a detection rule that looks for a package by identity name: the agent compares it as a
// prefix of the full name, so the underscore keeps "Microsoft.WindowsTerminal" from also matching its preview.
func AppxDetectionKey(name string) string { return name + "_" }

// AppxNameFromDetectionKey is the reverse of AppxDetectionKey.
func AppxNameFromDetectionKey(key string) (string, bool) {
	n := strings.TrimSuffix(key, "_")
	if n == key || !ValidAppxName(n) {
		return "", false
	}
	return n, true
}

// MSIXInstallScript provisions an MSIX/AppX package (or bundle) for all users of the computer and registers it for the
// people who are signed in now. Parameters: -Package (path of the verified file), -Name (identity name), -Version.
// Exit code 0 means the package is provisioned at the wanted version (or newer); anything else is a failure whose reason is
// printed. It is written for Windows PowerShell 5.1.
const MSIXInstallScript = `param(
    [Parameter(Mandatory = $true)][string]$Package,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Version
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function ConvertTo-Ver([string]$text) {
    $v = $null
    if ([System.Version]::TryParse($text, [ref]$v)) { return $v }
    return $null
}

# The newest version of this package that is provisioned for new users or installed for anyone.
function Get-Newest {
    $found = @()
    foreach ($p in @(Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $Name })) {
        $v = ConvertTo-Ver ([string]$p.Version)
        if ($v) { $found += $v }
    }
    foreach ($p in @(Get-AppxPackage -AllUsers -Name $Name)) {
        $v = ConvertTo-Ver ([string]$p.Version)
        if ($v) { $found += $v }
    }
    if ($found.Count -eq 0) { return $null }
    return ($found | Sort-Object -Descending | Select-Object -First 1)
}

$target = ConvertTo-Ver $Version
$have = Get-Newest
if ($have -and $target -and ($have -ge $target)) {
    Write-Output "$Name $have is already provisioned or installed; nothing to do."
    exit 0
}

try {
    Write-Output "Provisioning $Name $Version for all users."
    Add-AppxProvisionedPackage -Online -PackagePath $Package -SkipLicense | Out-Null
} catch {
    $m = $_.Exception.Message
    Write-Output "Windows could not install the package: $m"
    if ($m -match 'dependenc|0x80073CF3|0x80073D19|0x80073CF9') {
        Write-Output "A package that this app needs (for example Microsoft.VCLibs or Microsoft.UI.Xaml) is probably missing on this computer."
    }
    exit 1
}

# People who are signed in now get the app at once; everyone else gets it when they next sign in.
$share = $null
try {
    $users = @(Get-Process -Name explorer -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserName -Unique)
    if ($users.Count -gt 0) {
        $share = Join-Path $env:ProgramData ('LibrePatch\msix-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $share -Force | Out-Null
        & icacls.exe $share /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
        $copy = Join-Path $share ('package' + [System.IO.Path]::GetExtension($Package))
        Copy-Item -LiteralPath $Package -Destination $copy
        $quoted = $copy.Replace("'", "''")
        $register = Join-Path $share 'register.ps1'
        Set-Content -LiteralPath $register -Encoding UTF8 -Value ("Add-AppxPackage -LiteralPath '" + $quoted + "' -ForceUpdateFromAnyVersion")
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        foreach ($user in $users) {
            $task = 'LibrePatch-msix-' + [guid]::NewGuid().ToString('N')
            try {
                $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $register + '"')
                $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
                Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null
                Start-ScheduledTask -TaskName $task
                $deadline = (Get-Date).AddMinutes(5)
                do {
                    Start-Sleep -Seconds 2
                    $state = [string](Get-ScheduledTask -TaskName $task).State
                } while ((($state -eq 'Running') -or ($state -eq 'Queued')) -and ((Get-Date) -lt $deadline))
                $code = (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
                if ($code -eq 0) { Write-Output "Registered for $user." }
                else { Write-Output "Could not register for $user now (result $code); they may need to sign out and in." }
            } catch {
                Write-Output "Could not register for $user now: $($_.Exception.Message)"
            } finally {
                Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }
} catch {
    Write-Output "Signed-in users were not registered now: $($_.Exception.Message)"
} finally {
    if ($share) { Remove-Item -LiteralPath $share -Recurse -Force -ErrorAction SilentlyContinue }
}

$now = Get-Newest
if (-not $now) {
    Write-Output "The package was added, but $Name is not listed afterwards."
    exit 1
}
if ($target -and ($now -lt $target)) {
    Write-Output "Expected $Name $Version, but the newest version here is $now."
    exit 1
}
Write-Output "$Name $now is provisioned for all users."
exit 0
`

// MSIXRemoveScript removes every version of an MSIX/AppX package for all users and from the provisioning list. Parameter:
// -Name (identity name). Exit code 0 means the package is gone.
const MSIXRemoveScript = `param(
    [Parameter(Mandatory = $true)][string]$Name
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    $installed = @(Get-AppxPackage -AllUsers -Name $Name)
    $provisioned = @(Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $Name })
    if (($installed.Count -eq 0) -and ($provisioned.Count -eq 0)) {
        Write-Output "$Name is not installed; nothing to do."
        exit 0
    }
    foreach ($p in $installed) {
        Write-Output "Removing $($p.PackageFullName) for all users."
        Remove-AppxPackage -Package $p.PackageFullName -AllUsers
    }
    foreach ($p in $provisioned) {
        Write-Output "Removing the provisioned $($p.PackageName)."
        Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName | Out-Null
    }
} catch {
    Write-Output "Windows could not remove the package: $($_.Exception.Message)"
    exit 1
}
$left = @(Get-AppxPackage -AllUsers -Name $Name).Count + @(Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $Name }).Count
if ($left -gt 0) {
    Write-Output "$Name is still listed afterwards."
    exit 1
}
Write-Output "$Name was removed."
exit 0
`
