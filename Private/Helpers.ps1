#Requires -Version 5.1
Set-StrictMode -Version Latest

# Severity ordering used for filtering and threshold comparisons.
$script:WinAuditSeverityRank = @{
    Info     = 0
    Low      = 1
    Medium   = 2
    High     = 3
    Critical = 4
}

function New-WinAuditFinding {
    <#
        .SYNOPSIS
            Builds a single, consistently-shaped finding object.

        .DESCRIPTION
            Pure helper with no side effects. Every analyser calls this so
            every finding in the report has the same shape regardless of
            which check produced it.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'New-WinAuditFinding only constructs and returns an in-memory pscustomobject; it never changes system state, so ShouldProcess does not apply.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Object,

        [Parameter(Mandatory)]
        [string]$Risk,

        [Parameter(Mandatory)]
        [string]$Remediation,

        [string]$Details = ''
    )

    [pscustomobject]@{
        PSTypeName  = 'WinAudit.Finding'
        Id          = $Id
        Severity    = $Severity
        Category    = $Category
        Object      = $Object
        Risk        = $Risk
        Remediation = $Remediation
        Details     = $Details
    }
}

function Test-WinAuditUserWritablePath {
    <#
        .SYNOPSIS
            Heuristically determines whether a filesystem path lies in a
            location a standard (non-admin) user can typically write to.

        .DESCRIPTION
            Pure, pattern-based check so it can be unit tested without
            touching a real filesystem or ACL. Deliberately conservative:
            it flags well-known user-writable roots (profile folders,
            temp directories, the root of a drive) and leaves protected
            system locations (System32, Program Files, the Windows
            directory itself) alone.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $normalized = $Path.Trim().Trim('"')

    $protectedRoots = @(
        '^[A-Za-z]:\\Windows\\System32\\',
        '^[A-Za-z]:\\Windows\\SysWOW64\\',
        '^[A-Za-z]:\\Program Files\\',
        '^[A-Za-z]:\\Program Files \(x86\)\\',
        '^[A-Za-z]:\\Windows\\$'
    )
    foreach ($pattern in $protectedRoots) {
        if ($normalized -match $pattern) {
            return $false
        }
    }

    # Note: %ProgramData% is deliberately NOT treated as user-writable here.
    # Its default ACL grants standard users Read & Execute only - many
    # legitimate, Microsoft-signed components (e.g. Windows Defender) stage
    # binaries there, and flagging the whole tree would be a false positive.
    $writableRoots = @(
        '^[A-Za-z]:\\Users\\',
        '^[A-Za-z]:\\Windows\\Temp\\',
        '^[A-Za-z]:\\Temp\\',
        '^[A-Za-z]:\\Perflogs\\',
        '\\AppData\\',
        '^[A-Za-z]:\\[^\\]+$'
    )
    foreach ($pattern in $writableRoots) {
        if ($normalized -match $pattern) {
            return $true
        }
    }

    return $false
}

function Get-WinAuditBinaryPathFromServicePath {
    <#
        .SYNOPSIS
            Extracts the executable path portion of a Win32_Service
            PathName value, stripping any quoting and trailing arguments.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$PathName
    )

    if ([string]::IsNullOrWhiteSpace($PathName)) {
        return ''
    }

    $trimmed = $PathName.Trim()

    if ($trimmed.StartsWith('"')) {
        $endQuote = $trimmed.IndexOf('"', 1)
        if ($endQuote -gt 0) {
            return $trimmed.Substring(1, $endQuote - 1)
        }
    }

    $match = [regex]::Match($trimmed, '^(.*?\.exe)', 'IgnoreCase')
    if ($match.Success) {
        return $match.Groups[1].Value
    }

    # No .exe token found (e.g. a bare path with no extension) - fall back
    # to the first whitespace-delimited token.
    return ($trimmed -split '\s+')[0]
}

function Test-WinAuditUnquotedServicePath {
    <#
        .SYNOPSIS
            Determines whether a service PathName is vulnerable to the
            classic unquoted-service-path privilege escalation.

        .DESCRIPTION
            A path is vulnerable only when it is NOT wrapped in quotes AND
            the executable portion of the path contains at least one space
            (Windows will otherwise try each space-delimited prefix as a
            candidate executable, in directory order, before the real one).
            A path with no spaces at all is never vulnerable, quoted or not.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$PathName
    )

    if ([string]::IsNullOrWhiteSpace($PathName)) {
        return $false
    }

    $trimmed = $PathName.Trim()

    if ($trimmed.StartsWith('"')) {
        return $false
    }

    $exePath = Get-WinAuditBinaryPathFromServicePath -PathName $trimmed
    return $exePath.Contains(' ')
}

function Test-WinAuditSeverityAtLeast {
    <#
        .SYNOPSIS
            Compares a severity string against a threshold severity.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
        [string]$Threshold
    )

    return $script:WinAuditSeverityRank[$Severity] -ge $script:WinAuditSeverityRank[$Threshold]
}
