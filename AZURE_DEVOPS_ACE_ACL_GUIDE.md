# Azure DevOps ACE/ACL Structure Guide

## Overview

Azure DevOps uses **Access Control Entries (ACE)** and **Access Control Lists (ACL)** to manage permissions across the organization and its various resources (projects, repositories, branches, pipelines, etc.). Understanding how to read, interpret, and manipulate these structures is crucial for managing permissions programmatically across any namespace.

## Table of Contents

1. [ACL/ACE Structure](#aclace-structure)
2. [Security Namespaces](#security-namespaces)
3. [Querying ACLs](#querying-acls)
4. [Permission Encoding](#permission-encoding)
5. [Finding Deny Permissions](#finding-deny-permissions)
6. [Decoding Actual Permissions](#decoding-actual-permissions)
7. [Modifying Deny Permissions](#modifying-deny-permissions)
8. [Examples](#examples)

---

## ACL/ACE Structure

### Access Control List (ACL)

An **ACL** is a collection of **ACE**s for a specific object (project, repository, branch, etc.). The structure returned from the Azure DevOps REST API looks like:

```json
{
  "acesDictionary": {
    "descriptor1": {
      "descriptor": "user descriptor string",
      "allow": 15,
      "deny": 8,
      "extendedInfo": {
        "effectiveAllow": 7,
        "effectiveDeny": 8
      }
    }
  },
  "includeExtendedInfo": true,
  "iluCount": 0,
  "token": "repoV2/project-id/repo-id",
  "inheritPermissions": true
}
```

### Access Control Entry (ACE)

An **ACE** is a single entry within an ACL that specifies:
- **descriptor**: Who the entry applies to (user, group, or service identity)
- **allow**: Bitfield of permissions explicitly allowed
- **deny**: Bitfield of permissions explicitly denied
- **extendedInfo**: Calculated effective permissions

### Key Points

- Each permission is represented as a **bit** in a 32-bit integer
- Multiple permissions are represented as **bitwise OR** combinations
- **Allow** and **Deny** are separate fields (deny takes precedence)
- **effectiveAllow** = allow AND NOT deny (actual permissions granted)

---

## Security Namespaces

Azure DevOps organizes permissions into distinct **security namespaces**, each managing a specific area of the system. Different namespaces have different permission sets and token formats.

### Common Namespaces

| Namespace | ID | Token Format | Purpose |
|-----------|----|----|---------|
| Git Repositories | `2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87` | `repoV2/[projectId]/[repoId]` | Repository-level permissions |
| Git Repository Refs | `2ea2a0a7-a7f6-4add-8bba-e517a6456619` | `refs/heads/[branchName]` | Branch and ref permissions |
| Team Project | `52d39943-cb85-4d7f-8fa8-c6baac873d33` | `[projectId]` | Project-level permissions |
| Analytics | `58450c49-b02d-465a-ab12-59d9ccc18e15` | `[projectId]/[viewId]` | Analytics view permissions |
| Build | `33344d82-413d-495d-b498-1a4279c2e20b` | `[buildId]` or `[projectId]/[buildId]` | Build pipeline permissions |
| Release | `c788c23e-1b46-4162-8f5e-rfc.release` | `[releaseId]` or `[projectId]/[releaseId]` | Release pipeline permissions |
| Tagging | `6e4b3447-2a25-4247-b5dd-a6f073fbf231` | `[projectId]/[tagId]` | Tagging permissions |

### Finding Your Namespaces

Retrieve all available namespaces for your organization:

**REST API:**
```powershell
$orgUrl = "https://dev.azure.com/myorg"
$token = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($pat)"))
$authHeader = @{Authorization = "Basic $token"}

$namespacesUrl = "$orgUrl/_apis/securitynamespaces?api-version=7.2-preview.1"
$namespaces = Invoke-RestMethod -Uri $namespacesUrl -Headers $authHeader
$namespaces.value | Select-Object name, namespaceId | Format-Table
```

**Azure DevOps CLI:**
```bash
az devops security namespace list --org https://dev.azure.com/myorg
```

The response includes the namespace ID (used in API calls) and permission definitions for each namespace.

---

## Querying ACLs

Before modifying permissions, you must retrieve the current ACL for a specific object. ACLs are namespace-specific, so you need the correct namespace ID and token.

### Prerequisites

You'll need:
- **Organization URL**: `https://dev.azure.com/{org}`
- **Personal Access Token (PAT)**: With appropriate permissions
- **Namespace ID**: The security namespace you're querying
- **Token(s)**: The object identifier(s) within that namespace

### REST API - Query ACL

**Basic Query:**
```powershell
param(
    [string]$OrgUrl = "https://dev.azure.com/myorg",
    [string]$Pat = "your-pat-here",
    [string]$NamespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87",  # Git Repositories
    [string]$Token = "repoV2/project-guid/repo-guid"
)

# Create auth header
$base64Pat = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
$authHeader = @{Authorization = "Basic $base64Pat"}

# Query ACL
$aclUrl = "$OrgUrl/_apis/accesscontrollists/$NamespaceId" +
          "?tokens=$([Uri]::EscapeDataString($Token))&api-version=7.1"

$acl = Invoke-RestMethod -Uri $aclUrl -Headers $authHeader -Method GET

# Display ACL structure
$acl | ConvertTo-Json -Depth 10 | Out-Host
```

**Querying Multiple Tokens:**
```powershell
# Query multiple objects in one call (separated by comma)
$tokens = @("repoV2/project-id/repo1-id", "repoV2/project-id/repo2-id")
$tokenString = ($tokens | ForEach-Object { [Uri]::EscapeDataString($_) }) -join ","

$aclUrl = "$OrgUrl/_apis/accesscontrollists/$NamespaceId" +
          "?tokens=$tokenString&api-version=7.1"

$acls = Invoke-RestMethod -Uri $aclUrl -Headers $authHeader -Method GET
```

### Azure DevOps CLI - Query ACL

**Query by Token:**
```bash
# Set authentication
export AZURE_DEVOPS_EXT_PAT="your-pat-here"

# Query ACL
az devops security permission list \
  --namespace-id "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87" \
  --token "repoV2/project-guid/repo-guid" \
  --org https://dev.azure.com/myorg \
  --output table
```

**Query with Filtering:**
```bash
# Show only entries with explicit denies
az devops security permission list \
  --namespace-id "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87" \
  --token "repoV2/project-guid/repo-guid" \
  --org https://dev.azure.com/myorg \
  --output json | jq '.[] | select(.deny > 0)'
```

### Understanding Token Formats

Tokens vary by namespace. Common patterns:

**Git Repository Namespace:**
```
repoV2/{projectId}/{repositoryId}                    # Entire repository
repoV2/{projectId}/{repositoryId}/refs/heads/branch  # Specific branch
```

**Team Project Namespace:**
```
{projectId}                                          # Entire project
```

**Build/Release Pipelines:**
```
{buildDefinitionId}                                  # Build definition
{releaseDefinitionId}                               # Release definition
```

Consult the namespace documentation or test in the Azure DevOps UI to determine the correct token format for your target resource.

---

## Permission Encoding

### Bit-Based Permission System

Permissions in Azure DevOps are encoded as individual bits in a 32-bit integer. Each bit position represents a specific permission. The bit layout varies by namespace.

### Retrieving Permission Definitions

To see all permissions for a namespace:

**REST API:**
```powershell
$namespacesUrl = "$OrgUrl/_apis/securitynamespaces?api-version=7.2-preview.1"
$namespaces = Invoke-RestMethod -Uri $namespacesUrl -Headers $authHeader

$gitRepoNamespace = $namespaces.value | Where-Object { $_.namespaceId -eq "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87" }
$gitRepoNamespace.actions | Select-Object name, bit | Format-Table
```

**Example Output:**
```
name                              bit
----                              ---
Administer                        0
Create Repository                 1
Delete Repository                 2
Rename Repository                 3
Edit Policies                      4
Create Branch                      5
Create Tag                         6
Manage Notes                       7
Force Push (Rewrite History)       8
Manage Permissions                 9
Contribute to Pull Requests        10
Contribute                         11
Manage Repositories                12
```

### Understanding Permission Values

Permissions are represented as decimal numbers that are the sum of their bit positions (powers of 2):

**Examples:**
- Bit 0 = 1 (Administer)
- Bit 1 = 2 (Create Repository)
- Bit 11 = 2048 (Contribute)
- Bits 0-11 = 4095 (All standard permissions)
- Bits 4, 11, 12 = 16 + 2048 + 4096 = 6160 (Contribute + Edit Policies + Manage Repositories)

### Determining Bit Positions

To find which bits are set in a permission value:

```powershell
function Get-SetBits {
    param([int]$Value)
    
    $bits = @()
    for ($i = 0; $i -lt 32; $i++) {
        if (($Value -band [Math]::Pow(2, $i)) -ne 0) {
            $bits += $i
        }
    }
    return $bits
}

# Example
$permissionValue = 2064
$setBits = Get-SetBits -Value $permissionValue
Write-Host "Bits set in $permissionValue : $setBits"  # Output: 4 11 12
```

---

## Finding Deny Permissions

### Identifying Deny ACEs in ACL Response

```powershell
# Parse permissions JSON and find entries with denies
$permissions = Get-Content ".\data\Permissions.json" | ConvertFrom-Json

foreach ($ace in $permissions.acesDictionary) {
    if ($ace.deny -ne 0) {
        Write-Host "Deny found for descriptor: $($ace.descriptor)"
        Write-Host "Deny bits: $($ace.deny)"
        Write-Host "Binary: $([System.Convert]::ToString($ace.deny, 2))"
    }
}
```

### Query ACL for Specific Token (Object)

To find denies on a specific repository or project:

```powershell
$token = "repoV2/project-id/repo-id"  # Example for a repository
$namespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"  # Git Repositories

$aclUrl = "https://dev.azure.com/{org}/_apis/accesscontrollists/$namespaceId" +
          "?tokens=$token&api-version=7.1"

$acl = Invoke-RestMethod -Uri $aclUrl -Headers @{Authorization = $authHeader}

# Find entries with non-zero deny field
$denies = $acl.value.acesDictionary | Where-Object { $_.deny -ne 0 }
```

### Understanding Deny Precedence

- **Deny always wins** - If a permission bit is set in both `allow` and `deny`, the user does NOT have that permission
- `effectiveAllow` = `allow` AND NOT `deny` (this is the actual permission granted)
- A user might have high `allow` value but low `effectiveAllow` if denies are present

---

## Decoding Actual Permissions

### Calculate Effective Permissions

```powershell
function Get-EffectivePermission {
    param(
        [int]$Allow,
        [int]$Deny
    )
    # Effective = Allow AND NOT Deny
    return $Allow -band -bnot $Deny
}

# Example
$allow = 4095  # Bits 0-11
$deny = 256    # Bit 8 (Force Push)
$effective = Get-EffectivePermission -Allow $allow -Deny $deny
Write-Host "Effective: $effective (removed Force Push from Allow)"
```

### Convert Binary to Permission Names

```powershell
function Decode-Permissions {
    param(
        [int]$PermissionValue,
        [hashtable]$PermissionMap
    )
    
    $permissions = @()
    foreach ($permission in $PermissionMap.GetEnumerator()) {
        $bitValue = [Math]::Pow(2, $permission.Name)
        if (($PermissionValue -band $bitValue) -ne 0) {
            $permissions += $permission.Value
        }
    }
    return $permissions
}

# Git Repository Permissions
$gitRepoPermissions = @{
    0 = "Administer"
    1 = "Create Repository"
    2 = "Delete Repository"
    3 = "Rename Repository"
    4 = "Edit Policies"
    5 = "Create Branch"
    6 = "Create Tag"
    7 = "Manage Notes"
    8 = "Force Push (Rewrite History)"
    9 = "Manage Permissions"
    10 = "Contribute to Pull Requests"
    11 = "Contribute"
    12 = "Manage Repositories"
}

$allow = 2064
$deniedPerms = Decode-Permissions -PermissionValue $deny -PermissionMap $gitRepoPermissions
Write-Host "User can: $(Decode-Permissions -PermissionValue $allow -PermissionMap $gitRepoPermissions)"
Write-Host "User denied: $deniedPerms"
```

### Reading from Parsed ACL

```powershell
# From the PermissionHelper script pattern
foreach ($descriptor in $acl.acesDictionary.Keys) {
    $ace = $acl.acesDictionary[$descriptor]
    $effective = $ace.allow -band -bnot $ace.deny
    
    Write-Host "Descriptor: $descriptor"
    Write-Host "  Allow: $($ace.allow) (binary: $([System.Convert]::ToString($ace.allow, 2)))"
    Write-Host "  Deny:  $($ace.deny) (binary: $([System.Convert]::ToString($ace.deny, 2)))"
    Write-Host "  Effective: $effective"
}
```

---

## Modifying Deny Permissions

Modifying individual permissions is safer than bulk operations. This section covers how to make targeted changes to specific ACE entries.

### Overview of the Process

1. **Query** the current ACL for the target token
2. **Identify** the specific descriptor and current deny value
3. **Calculate** the new deny value (removing specific bits)
4. **Apply** the change via REST API or CLI
5. **Verify** the change was successful

### REST API - Modify Individual ACE

**Step-by-Step Example:**

```powershell
param(
    [string]$OrgUrl = "https://dev.azure.com/myorg",
    [string]$Pat = "your-pat-here",
    [string]$NamespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87",
    [string]$Token = "repoV2/project-id/repo-id",
    [string]$Descriptor = "Microsoft.IdentityManagement.Identity;user-descriptor",
    [int]$DenyBitToRemove = 256  # Force Push (bit 8)
)

# Setup
$base64Pat = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
$authHeader = @{Authorization = "Basic $base64Pat"}

# Step 1: Query current ACL
$aclUrl = "$OrgUrl/_apis/accesscontrollists/$NamespaceId" +
          "?tokens=$([Uri]::EscapeDataString($Token))&api-version=7.1"

Write-Host "Querying ACL for token: $Token"
$acl = Invoke-RestMethod -Uri $aclUrl -Headers $authHeader -Method GET

# Step 2: Find the specific ACE
if (-not $acl.value.acesDictionary.ContainsKey($Descriptor)) {
    Write-Host "ERROR: Descriptor not found in ACL"
    return
}

$currentACE = $acl.value.acesDictionary[$Descriptor]
Write-Host "Found ACE for $Descriptor"
Write-Host "  Current Allow: $($currentACE.allow)"
Write-Host "  Current Deny:  $($currentACE.deny)"

# Step 3: Calculate new deny value
$newDeny = $currentACE.deny -band -bnot $DenyBitToRemove

Write-Host "  Removing bit $([Math]::Log2($DenyBitToRemove)) (value: $DenyBitToRemove)"
Write-Host "  New Deny:  $newDeny"

# Verify calculation
if ($newDeny -eq $currentACE.deny) {
    Write-Host "INFO: Deny value unchanged - bit was not set"
    return
}

# Step 4: Apply change via PATCH
$patchUrl = "$OrgUrl/_apis/accesscontrollists/$NamespaceId" +
            "?api-version=7.1"

$body = @{
    token = $Token
    merge = $false
    accessControlEntries = @(
        @{
            descriptor = $Descriptor
            allow = $currentACE.allow
            deny = $newDeny
        }
    )
} | ConvertTo-Json

Write-Host "Applying change..."
$patchResponse = Invoke-RestMethod -Uri $patchUrl `
                                   -Headers $authHeader `
                                   -Method PATCH `
                                   -ContentType "application/json" `
                                   -Body $body

Write-Host "Change applied successfully"

# Step 5: Verify
Write-Host "Verifying change..."
$verifyAcl = Invoke-RestMethod -Uri $aclUrl -Headers $authHeader -Method GET
$verifiedACE = $verifyAcl.value.acesDictionary[$Descriptor]

if ($verifiedACE.deny -eq $newDeny) {
    Write-Host "SUCCESS: Deny value updated correctly"
    Write-Host "  Verified Deny: $($verifiedACE.deny)"
} else {
    Write-Host "WARNING: Deny value mismatch after update"
    Write-Host "  Expected: $newDeny"
    Write-Host "  Actual: $($verifiedACE.deny)"
}
```

### Azure DevOps CLI - Modify Individual ACE

**Query and Modify:**
```bash
# Step 1: Query ACL
az devops security permission show \
  --namespace-id "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87" \
  --token "repoV2/project-id/repo-id" \
  --descriptor "Microsoft.IdentityManagement.Identity;descriptor" \
  --org https://dev.azure.com/myorg \
  --output json

# Step 2: Update permission
az devops security permission update \
  --namespace-id "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87" \
  --token "repoV2/project-id/repo-id" \
  --descriptor "Microsoft.IdentityManagement.Identity;descriptor" \
  --allow-bit 0 \
  --deny-bit 0 \
  --org https://dev.azure.com/myorg
```

### Common Scenarios

**Clear All Denies for a User:**

```powershell
# Set deny to 0 (keep existing allow)
$newDeny = 0  # Clear all denies

$body = @{
    token = $Token
    merge = $false
    accessControlEntries = @(
        @{
            descriptor = $Descriptor
            allow = $currentACE.allow
            deny = $newDeny
        }
    )
} | ConvertTo-Json

Invoke-RestMethod -Uri $patchUrl -Headers $authHeader -Method PATCH `
                  -ContentType "application/json" -Body $body
```

**Remove Specific Deny Bit:**

```powershell
# Example: Remove Force Push deny (bit 8 = 256) from existing denies
$currentDeny = 264    # Binary: 100001000 (bits 3 and 8)
$bitToRemove = 256    # Force Push

$newDeny = $currentDeny -band -bnot $bitToRemove
# Result: 8 (only bit 3 remains)
```

**Add Allow Permission (without changing denies):**

```powershell
# Keep deny the same, update allow
$currentACE = $acl.value.acesDictionary[$Descriptor]
$newAllow = $currentACE.allow -bor 32  # Add "Create Branch" (bit 5)

$body = @{
    token = $Token
    merge = $false
    accessControlEntries = @(
        @{
            descriptor = $Descriptor
            allow = $newAllow
            deny = $currentACE.deny
        }
    )
} | ConvertTo-Json
```

### Critical Considerations

1. **Merge Parameter**: 
   - `merge: false` = Replace entire ACE (recommended for clarity)
   - `merge: true` = Merge with existing ACL (can cause unexpected changes)

2. **Descriptor Format**: Ensure full identity descriptor is used:
   ```
   Microsoft.IdentityManagement.Identity;{guid}           # Individual user
   Microsoft.TeamFoundation.Group;{project}\{group-name}  # Group
   ```

3. **Always Verify**: Re-query after modification to confirm the change applied correctly

4. **Understand Permissions**: Know what bits you're modifying before making changes

---

## Examples

### Example 1: Query and Display ACL for Any Namespace

```powershell
param(
    [string]$OrgUrl = "https://dev.azure.com/myorg",
    [string]$Pat = "your-pat-here",
    [string]$NamespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87",  # Change as needed
    [string]$Token = "repoV2/project-guid/repo-guid"                 # Change as needed
)

$base64Pat = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
$authHeader = @{Authorization = "Basic $base64Pat"}

$aclUrl = "$OrgUrl/_apis/accesscontrollists/$NamespaceId" +
          "?tokens=$([Uri]::EscapeDataString($Token))&api-version=7.1"

$acl = Invoke-RestMethod -Uri $aclUrl -Headers $authHeader -Method GET

# Display all ACE entries
foreach ($descriptor in $acl.value.acesDictionary.Keys) {
    $ace = $acl.value.acesDictionary[$descriptor]
    $effective = $ace.allow -band -bnot $ace.deny
    
    Write-Host "Descriptor: $descriptor"
    Write-Host "  Allow:     $($ace.allow)"
    Write-Host "  Deny:      $($ace.deny)"
    Write-Host "  Effective: $effective"
    Write-Host ""
}
```

### Example 2: Find All Entries with Denies

```powershell
# From existing $acl variable (see Example 1)

$deniedEntries = @()
foreach ($descriptor in $acl.value.acesDictionary.Keys) {
    $ace = $acl.value.acesDictionary[$descriptor]
    if ($ace.deny -ne 0) {
        $deniedEntries += @{
            Descriptor = $descriptor
            Deny = $ace.deny
            AllowValue = $ace.allow
            Effective = $ace.allow -band -bnot $ace.deny
        }
    }
}

if ($deniedEntries.Count -eq 0) {
    Write-Host "No denies found in ACL"
} else {
    Write-Host "Found $($deniedEntries.Count) entries with denies:"
    $deniedEntries | Format-Table -AutoSize
}
```

### Example 3: Decode Permissions to Human-Readable Names

```powershell
# First, retrieve the namespace to get permission definitions
$namespacesUrl = "$OrgUrl/_apis/securitynamespaces?api-version=7.2-preview.1"
$namespaces = Invoke-RestMethod -Uri $namespacesUrl -Headers $authHeader

$namespace = $namespaces.value | Where-Object { $_.namespaceId -eq $NamespaceId }

function Get-PermissionNames {
    param(
        [int]$Value,
        [psobject]$Namespace
    )
    
    $permissionNames = @()
    foreach ($action in $namespace.actions) {
        $bitValue = [Math]::Pow(2, $action.bit)
        if (($Value -band $bitValue) -ne 0) {
            $permissionNames += $action.name
        }
    }
    return $permissionNames
}

# Example: Decode allow and deny permissions
$ace = $acl.value.acesDictionary[$descriptor]
$allowedPermissions = Get-PermissionNames -Value $ace.allow -Namespace $namespace
$deniedPermissions = Get-PermissionNames -Value $ace.deny -Namespace $namespace

Write-Host "Allowed: $(($allowedPermissions -join ', ') -or 'None')"
Write-Host "Denied:  $(($deniedPermissions -join ', ') -or 'None')"
```

### Example 4: Remove a Specific Deny Bit from a User

```powershell
param(
    [string]$OrgUrl = "https://dev.azure.com/myorg",
    [string]$Pat = "your-pat-here",
    [string]$NamespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87",
    [string]$Token = "repoV2/project-id/repo-id",
    [string]$Descriptor = "Microsoft.IdentityManagement.Identity;user-guid",
    [int]$DenyBitToRemove = 256  # Example: Force Push (bit 8)
)

$base64Pat = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
$authHeader = @{Authorization = "Basic $base64Pat"}

# Query current ACL
$aclUrl = "$OrgUrl/_apis/accesscontrollists/$NamespaceId" +
          "?tokens=$([Uri]::EscapeDataString($Token))&api-version=7.1"

$acl = Invoke-RestMethod -Uri $aclUrl -Headers $authHeader -Method GET

# Find the ACE
if (-not $acl.value.acesDictionary.ContainsKey($Descriptor)) {
    Write-Host "ERROR: Descriptor not found"
    return
}

$currentACE = $acl.value.acesDictionary[$Descriptor]
$bitPosition = [Math]::Log2($DenyBitToRemove)

Write-Host "Current State:"
Write-Host "  Allow: $($currentACE.allow)"
Write-Host "  Deny:  $($currentACE.deny) (binary: $([System.Convert]::ToString($currentACE.deny, 2)))"

# Calculate new deny value
$newDeny = $currentACE.deny -band -bnot $DenyBitToRemove

if ($newDeny -eq $currentACE.deny) {
    Write-Host "INFO: Bit $bitPosition is not set in deny - no change needed"
    return
}

Write-Host "After removing bit $bitPosition :"
Write-Host "  New Deny: $newDeny (binary: $([System.Convert]::ToString($newDeny, 2)))"

# Apply the change
$patchUrl = "$OrgUrl/_apis/accesscontrollists/$NamespaceId?api-version=7.1"

$body = @{
    token = $Token
    merge = $false
    accessControlEntries = @(
        @{
            descriptor = $Descriptor
            allow = $currentACE.allow
            deny = $newDeny
        }
    )
} | ConvertTo-Json

Write-Host "Applying change..."
Invoke-RestMethod -Uri $patchUrl -Headers $authHeader -Method PATCH `
                  -ContentType "application/json" -Body $body | Out-Null

# Verify
Start-Sleep -Seconds 1  # Brief delay to ensure propagation
$verify = Invoke-RestMethod -Uri $aclUrl -Headers $authHeader -Method GET
$verifiedACE = $verify.value.acesDictionary[$Descriptor]

if ($verifiedACE.deny -eq $newDeny) {
    Write-Host "SUCCESS: Change verified"
    Write-Host "  Verified Deny: $($verifiedACE.deny)"
} else {
    Write-Host "WARNING: Verification failed"
    Write-Host "  Expected: $newDeny"
    Write-Host "  Actual: $($verifiedACE.deny)"
}
```

### Example 5: Clear All Denies for a Single User

```powershell
# Continue from Example 4 setup...
# This removes ALL deny permissions while keeping allow unchanged

$newDeny = 0  # Clear all denies

$body = @{
    token = $Token
    merge = $false
    accessControlEntries = @(
        @{
            descriptor = $Descriptor
            allow = $currentACE.allow
            deny = $newDeny
        }
    )
} | ConvertTo-Json

Write-Host "Clearing all denies..."
Invoke-RestMethod -Uri $patchUrl -Headers $authHeader -Method PATCH `
                  -ContentType "application/json" -Body $body | Out-Null

# Verify
$verify = Invoke-RestMethod -Uri $aclUrl -Headers $authHeader -Method GET
$verifiedACE = $verify.value.acesDictionary[$Descriptor]

Write-Host "Result:"
Write-Host "  Old Deny: $($currentACE.deny)"
Write-Host "  New Deny: $($verifiedACE.deny)"
```

---

## References

- [Azure DevOps REST API - Access Control Lists Query](https://learn.microsoft.com/en-us/rest/api/azure/devops/security/access-control-lists/query?view=azure-devops-rest-7.1&tabs=HTTP)
- [Azure DevOps REST API - Security Namespaces](https://learn.microsoft.com/en-us/rest/api/azure/devops/security/security-namespaces)
- [Security Namespace Reference](https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference?view=azure-devops)
- [Azure DevOps Permissions Reference](https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions?view=azure-devops)
- [Azure DevOps CLI Security Commands](https://learn.microsoft.com/en-us/cli/azure/devops/security)
- [Azure DevOps CLI Permission Commands](https://learn.microsoft.com/en-us/cli/azure/devops/security/permission)
- [Git Repository Tokens for Security Service](https://devblogs.microsoft.com/devops/git-repo-tokens-for-the-security-service/)
- [DevOps API Examples - GitHub](https://github.com/artgarciams/DevOpsApi)
- [Azure DevOps REST API Core - Projects](https://learn.microsoft.com/en-us/rest/api/azure/devops/core/projects/get?view=azure-devops-rest-7.1)
- [Azure DevOps REST API Git - Repositories](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/repositories/get-repository?view=azure-devops-rest-7.1)

---

## Summary

| Task | Method | Key Points |
|------|--------|-----------|
| **Query ACL** | REST API / CLI | Use correct namespace ID and token format |
| **Find Denies** | Query & inspect | Check `deny` field for non-zero values |
| **Decode Permissions** | Bitwise operations | Check individual bit positions against namespace actions |
| **Calculate Effective** | Bitwise math | `effective = allow AND NOT deny` |
| **Modify Permission** | REST PATCH / CLI | Update individual ACE with new deny value |
| **Verify Changes** | Re-query ACL | Confirm changes applied correctly |

---

## Important Notes

- **Namespaces vary**: Permission bit positions differ by namespace - always retrieve current namespace definitions
- **Token formats differ**: Each namespace uses a different token format (e.g., `repoV2/...` for Git repos, `{projectId}` for projects)
- **Individual modifications**: Make targeted changes to specific ACEs rather than bulk operations for better control
- **Always verify**: Re-query after modifications to confirm changes propagated correctly
- **Delay propagation**: Allow 1-2 seconds for Azure DevOps to propagate permission changes

---

__Note__

>_This guide was generated with GitHub Copilot assistance using PermissionHelper script patterns and Azure DevOps documentation. It provides generic guidance applicable to all Azure DevOps namespaces and security permissions. Content was curated for accuracy but should be validated against current Azure DevOps API documentation before making permission changes in production environments._