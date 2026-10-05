# Invoked only by the separately reviewed Windows source launcher. No globals.
param(
    [Parameter(Mandatory = $true)][string]$Workspace,
    [Parameter(Mandatory = $true)][string]$Run,
    [Parameter(Mandatory = $true)][ValidateSet('SecureEmpty', 'Verify')][string]$Mode
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Fixed branch codes only: no exception message, type, target path or principal.
$phase = 1
$checked = 0
$diagnosticMode = if ($Mode -ieq 'SecureEmpty') { 'SecureEmpty' } else { 'Verify' }
try {
    if ($Run -cnotmatch '^[a-f0-9]{32}$' -or -not [IO.Path]::IsPathRooted($Workspace)) {
        throw 'Invalid private run identity.'
    }
    $phase = 2 # Resolve the fixed run beneath the workspace.
    $workspacePath = [IO.Path]::GetFullPath($Workspace).TrimEnd('\')
    $runPath = [IO.Path]::GetFullPath((Join-Path $workspacePath "var\enterprise\runs\$Run"))
    if (-not $runPath.StartsWith($workspacePath + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Private run escaped its workspace.'
    }
    $phase = 3 # Reject redirected or missing directory ancestors.
    $ancestor = Get-Item -LiteralPath $runPath -Force
    while ($null -ne $ancestor) {
        # DirectoryInfo.Parent is a raw .NET object, without PowerShell's
        # provider-added PSIsContainer property. Test the actual object type.
        if ($ancestor -isnot [IO.DirectoryInfo] -or ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Redirected private run parent.'
        }
        if ($ancestor.FullName.TrimEnd('\') -ieq $workspacePath) { break }
        $ancestor = $ancestor.Parent
    }
    if ($null -eq $ancestor) { throw 'Private run workspace not found.' }
    $phase = 4 # Resolve only the two approved principals.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemIdentity = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $allowed = @($identity.Value, $systemIdentity.Value)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagate = [Security.AccessControl.PropagationFlags]::None
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $allow = [Security.AccessControl.AccessControlType]::Allow
    if ($Mode -eq 'SecureEmpty') {
        $phase = 5 # Refuse ownership mismatch before any permission write.
        $existingAcl = Get-Acl -LiteralPath $runPath
        if ($existingAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $identity.Value) {
            throw 'Private run owner did not match the current identity.'
        }
        $phase = 6 # Do not reinitialize existing run contents.
        if (@(Get-ChildItem -LiteralPath $runPath -Force).Count -ne 0) {
            throw 'Only a fresh empty private run can be secured.'
        }
        $phase = 7 # Construct a protected DACL with exactly the approved grants.
        $newAcl = [Security.AccessControl.DirectorySecurity]::new()
        $newAcl.SetAccessRuleProtection($true, $false)
        foreach ($principal in @($identity, $systemIdentity)) {
            $newAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $principal, $full, $inherit, $propagate, $allow
            ))
        }
        # Copy only Access into a fresh descriptor. Owner/group/audit sections
        # are neither copied nor modified; no WRITE_OWNER request is needed.
        $accessSection = [Security.AccessControl.AccessControlSections]::Access
        $descriptor = $newAcl.GetSecurityDescriptorSddlForm($accessSection)
        $accessOnlyAcl = [Security.AccessControl.DirectorySecurity]::new()
        $accessOnlyAcl.SetSecurityDescriptorSddlForm($descriptor, $accessSection)
        $phase = 8 # Persist the DACL only; ownership must remain unchanged.
        [IO.Directory]::SetAccessControl($runPath, $accessOnlyAcl)
    }
    # Enumerate manually so a junction is rejected before recursion follows it.
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($runPath)
    while ($pending.Count -gt 0) {
        $phase = 9 # Read one item without following a reparse point.
        $path = $pending.Dequeue()
        $item = Get-Item -LiteralPath $path -Force
        $phase = 10 # Enforce redirection and traversal-count bounds.
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ++$checked -gt 2500) {
            throw 'Redirected or oversized private run.'
        }
        $phase = 11 # Read back actual permissions after any write.
        $acl = Get-Acl -LiteralPath $path
        $phase = 12 # All retained items must still belong to the current user.
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $identity.Value) {
            throw 'Private run ownership changed.'
        }
        $phase = 13 # The root must not inherit public access.
        if ($path -eq $runPath -and -not $acl.AreAccessRulesProtected) {
            throw 'Private run inheritance changed.'
        }
        $phase = 14 # Exactly two effective access rules are permitted.
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if ($rules.Count -ne 2) { throw 'Unexpected private run permissions.' }
        $seen = @()
        foreach ($rule in $rules) {
            $phase = 15 # No additional principal, right or propagation mode.
            $sid = $rule.IdentityReference.Value
            if ($sid -notin $allowed -or $sid -in $seen -or $rule.AccessControlType -ne $allow -or
                $rule.FileSystemRights -ne $full -or $rule.PropagationFlags -ne $propagate -or
                ($item.PSIsContainer -and $rule.InheritanceFlags -ne $inherit) -or
                (-not $item.PSIsContainer -and $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None)) {
                throw 'Unexpected private run access rule.'
            }
            $seen += $sid
        }
        if ($item.PSIsContainer) {
            $phase = 16 # Enumerate children only after this item passed checks.
            foreach ($child in Get-ChildItem -LiteralPath $path -Force) {
                $pending.Enqueue($child.FullName)
            }
        }
    }
    $phase = 17 # Preserve the existing two-key success protocol.
    @{ private_acl_verified = $true; inherited_public_access_removed = $true } | ConvertTo-Json -Compress
} catch {
    # No user identity, target path, ACL details or credentials in diagnostics.
    $failure = [ordered]@{
        kind = 'signalbridge-private-acl-failure'
        mode = $diagnosticMode
        phase = $phase
        checked_count = [Math]::Min($checked, 2501)
    }
    if ($phase -eq 8) {
        $apiHResult = $null
        try {
            $diagnosticException = $_.Exception
            $innerLinks = 0
            while ($null -ne $diagnosticException -and $null -ne $diagnosticException.InnerException -and
                $innerLinks -lt 4) {
                $diagnosticException = $diagnosticException.InnerException
                ++$innerLinks
            }
            # Report only a completed chain's Int32 status; never error text.
            if ($null -ne $diagnosticException -and $null -eq $diagnosticException.InnerException -and
                $diagnosticException.HResult -is [int]) {
                $apiHResult = $diagnosticException.HResult
            }
        } catch { }
        $failure['api_hresult'] = $apiHResult
    }
    [Console]::Error.WriteLine(($failure | ConvertTo-Json -Compress))
    exit 1
}
