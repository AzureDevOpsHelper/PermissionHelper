
function Get-EntraToken {
    if (Get-Module -Name Az -ListAvailable)
    {
        try
        {
            Write-Host "Found Az module, attempting to use it to get an access token."
            $result = Get-AzAccessToken -ResourceUrl '499b84ac-1321-427f-aa17-267ca6975798'
            Clear-Host
        }
        catch
        {
            Write-Host "AZ login will open a modal identity picker in the top left of the screen, please choose the account you want to use."
            Write-Host "It may take a few seconds to load, please be patient."  
            Write-Host "It will then ask you to pick a subscription, please choose a subscription that is associated with the tenant that backs your org."
            Connect-AzAccount 
            $result = Get-AzAccessToken -ResourceUrl '499b84ac-1321-427f-aa17-267ca6975798'
            Clear-Host
        } 
    }
    else
    {
        Clear-Host
        Write-Host "It seems that the Az module is not installed or not working properly."
        Write-Host "Please wait while we attempt to install the Az module."
        Install-Module -Name Az -Repository PSGallery -Force -AllowClobber -Verbose -Scope CurrentUser -ErrorAction Stop
        Clear-Host
        Write-Host "The Az module has been installed successfully."
        Write-Host "AZ login will open a modal identity picker in the top left of the screen, please choose the account you want to use."
        Write-Host "It may take a few seconds to load, please be patient."  
        Write-Host "It will then ask you to pick a subscription, please choose a subscription that is associated with the tenant that backs your org."
        Connect-AzAccount -WarningAction 'SilentlyContinue' -ErrorAction 'Stop' -InformationAction 'SilentlyContinue' -ProgressAction 'SilentlyContinue'
        $result = Get-AzAccessToken -ResourceUrl '499b84ac-1321-427f-aa17-267ca6975798'        
        Clear-Host
    }
    $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($result.Token))
    $AuthHeader = "Bearer $plainToken"
    $result | Add-Member -NotePropertyName 'AuthHeader' -NotePropertyValue $AuthHeader -Force
    return $result
}
function Get-GraphToken {
    $result = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/" #| Out-Null
    $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($result.Token))
    $AuthHeader = "Bearer $plaintoken"
    $result | Add-Member -NotePropertyName 'AuthHeader' -NotePropertyValue $AuthHeader -Force
    return $result
}
function Update-ConsoleLine {
    param (
        [int]$Line = 0,
        [string]$Message = ""
    )
    [Console]::SetCursorPosition(0, $Line)
    [Console]::Write(" " * ([Console]::BufferWidth))
    [Console]::SetCursorPosition(0, $Line)
    if ($Message -ne "") {
            Write-Host $Message -NoNewline
    }
}
function GET-AzureDevOpsRestAPI {
    param (
        [string]$Authheader,
        [string]$RestAPIUrl
    )

    $Headers = @{
        Authorization           = $Authheader
        "X-TFS-FedAuthRedirect" = "Suppress"
    }
    $params = @{
        Uri                     = $RestAPIUrl
        Headers                 = $headers
        Method                  = 'GET'
        ContentType             = 'application/json'
        StatusCodeVariable      = 'statusCode' 
        ResponseHeadersVariable = 'responseHeaders'
    }
    try
    {   $WP = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        $PP = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        $result = Invoke-RestMethod @params 
        $results = New-Object "System.Collections.Generic.Dictionary[[String],[PSCustomObject]]"
        $results.Add("results", $result)
        $results.Add("responseHeaders", $responseHeaders)
        $results.Add("statusCode", $statusCode)
        if (($statusCode -eq 429) -or (($null -ne $responseHeaders."Retry-After") -and ($responseHeaders."Retry-After" -gt 0))){
            $RetryAfter = 30.0
            [double]::TryParse($responseHeaders."Retry-After", [ref]$RetryAfter)
            Update-ConsoleLine -Line 16 -Message "$RestAPIURL"
            Update-ConsoleLine -Line 17 -Message "Sleeping for $RetryAfter seconds to avoid throttling."
            "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "Function  : GET-AzureDevOpsRestAPI" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "*Throttling (non Error):*" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "URL       : $RestAPIURL" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "statusCode: $statusCode" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "Sleeping for $RetryAfter seconds before resuming thread" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            Start-Sleep -Seconds $RetryAfter            
        }
        $WarningPreference = $WP
        $ProgressPreference = $PP
        Update-ConsoleLine -Line 15
        Update-ConsoleLine -Line 16
        Update-ConsoleLine -Line 17
        return $results
    }
    Catch {
        "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Function  : GET-AzureDevOpsRestAPI" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "URL       : $RestAPIURL" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "statusCode: $statusCode" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        $responseHeaders | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Errors.log" -Append -Force
        $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        throw $_
    }
}
function Get-AzureDevOpsPermissions {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {    
    $namespaceUrl = "$($orgUrl)/_apis/securitynamespaces?api-version=7.2-preview.1"
    $namespaces = GET-AzureDevOpsRestAPI -RestAPIUrl $namespaceUrl -Authheader $Authheader
    "[" | Out-File -FilePath ".\data\Permissions.json" -Force
    $processedItems = [hashtable]::Synchronized(@{
        Lock    = [System.Threading.Mutex]::new()
        File    = ".\data\Permissions.json"
    })
    $namespaces.results.value | Foreach-Object -ThrottleLimit 5 -Parallel {
        $namespace        = $_
        $Authheader       = $using:Authheader
        $_orgUrl          = $using:orgUrl
        $ref              = $using:processedItems
        $scriptPath = $MyInvocation.MyCommand.Path
        $queue = @()
        if (-not $scriptPath) {
        $scriptPath = Get-ChildItem -Path "$((Get-Location).Path)\PermissionHelper.ps1" -ErrorAction Stop | Select-Object -ExpandProperty FullName -First 1
        }
        $env:IS_CHILD_JOB = $true 
        . "$scriptPath"
        $permissionUrl = $_orgUrl + "/_apis/accesscontrollists/" + $namespace.namespaceId + "?includeExtendedInfo=true&recurse=true&api-version=7.2-preview.1"
        $permissionResult = GET-AzureDevOpsRestAPI -RestAPIUrl $permissionUrl -Authheader $Authheader
        Update-ConsoleLine -Line 13 -Message "Working on NamespaceId: $($namespace.name)/$($namespace.displayName) ($($namespace.namespaceId))"
        foreach ($permission in $permissionResult.results.value)
        {   
            foreach ($descriptor in ((($permission.acesDictionary).psobject.Properties).Value))
            {  
                $_descriptor = $descriptor.descriptor
                $allowNullSafe                = ($null -eq $permission.acesDictionary."$_descriptor".allow) ? 0 : $permission.acesDictionary."$_descriptor".allow
                $denyNullSafe                 = ($null -eq $permission.acesDictionary."$_descriptor".deny) ? 0 : $permission.acesDictionary."$_descriptor".deny
                $effectiveAllowNullSafe       = ($null -eq $permission.acesDictionary."$_descriptor".extendedInfo.effectiveAllow) ? 0 : $permission.acesDictionary."$_descriptor".extendedInfo.effectiveAllow
                $effectiveDenyNullSafe        = ($null -eq $permission.acesDictionary."$_descriptor".extendedInfo.effectiveDeny) ? 0 : $permission.acesDictionary."$_descriptor".extendedInfo.effectiveDeny
                if ($effectiveAllowNullSafe -gt 0 -or $effectiveDenyNullSafe -gt 0 -or $allowNullSafe -gt 0 -or $denyNullSafe -gt 0)
                {
                    $tokenNullSafe   = ($null -eq $permission.token) ? "" : $permission.token
                    $enumactions  = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                    foreach ( $action in $namespace.actions )
                    {
                        if (( $allowNullSafe -band $action.bit ) -eq $action.bit ) 
                        {
                            $enumactions.Add($action.displayName, "Allow")
                        }
                        elseif (( $effectiveAllowNullSafe -band $action.bit ) -eq $action.bit )
                        {
                            $enumactions.Add($action.displayName, "Inherited Allow")
                        }
                        elseif (( $effectiveDenyNullSafe -band $action.bit ) -eq $action.bit )
                        {
                            $enumactions.Add($action.displayName, "Inherited Deny")
                        }
                        elseif (( $denyNullSafe -band $action.bit ) -eq $action.bit )
                        {
                            $enumactions.Add($action.displayName, "Deny")
                        }
                        else
                        {
                            $enumactions.Add($action.displayName, "Not Set")
                        }
                    }  
                    $friendlyToken = $tokenNullSafe
                    $permissionitem = [pscustomobject]@{
                        namespaceId          = $namespace.namespaceId
                        namespaceName        = $namespace.name
                        namespacedisplayName = $namespace.displayName
                        inheritPermissions   = ($null -eq $permission.inheritPermissions) ? $false : $permission.inheritPermissions
                        token                = $tokenNullSafe
                        friendlyToken        = $friendlyToken
                        descriptor           = ($null -eq $permission.acesDictionary."$_descriptor".descriptor) ? "" : $permission.acesDictionary."$_descriptor".descriptor
                        friendlydescriptor   = ($null -eq $permission.acesDictionary."$_descriptor".descriptor) ? "" : $permission.acesDictionary."$_descriptor".descriptor
                        allow                = $allowNullSafe
                        deny                 = $denyNullSafe
                        effectiveAllow       = $effectiveAllowNullSafe
                        effectiveDeny        = $effectiveDenyNullSafe
                        enumactions          = $enumactions | ConvertTo-Json | ConvertFrom-Json
                    }
                    $queue += $permissionitem
                }
            }
            if ($ref['Lock'].WaitOne()) 
            {
                ($queue | ConvertTo-Json -Depth 100).TrimStart("[").TrimEnd("]`n") + "," | Out-File -FilePath $ref['File'] -append -force
                $ref['Lock'].ReleaseMutex()
            }                   
            $queue = @()
        }
    }
    $fs = [System.IO.File]::Open(".\data\Permissions.json", 'Open', 'ReadWrite')
    $fs.SetLength($fs.Length - 3)
    $fs.Close()
    "`n]" | Out-File -FilePath ".\data\Permissions.json" -append -Force
    }
    catch 
    {
        "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Function  : Get-AzureDevOpsPermissions" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        throw $_ 
    }
    finally 
    {
        Update-ConsoleLine -Line 13
        #$threadSafeallPermissions = $null
    }
}
function Convert-Permissions {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    #todo: Lookup:
    # AnalyticsViews, 
    # ServiceEndpoints, 
    # Plan, 
    # Process, 
    # CSS, 
    # TeamLabSecurity, 
    # Iteration, 
    # Workspaces (seems like this is associated with VS Profile), 
    # DashboardsPrivileges
    try
    {
        $count = 0
        $groupfile = Get-Item -Path ".\data\Groups.json"
        $groups = Get-Content -Path $groupfile.FullName -Raw
        $groups = $groups | ConvertFrom-Json | Select-Object -Property SID, principalName, originId #, domain
#        $accountID = ($groups | Where-Object { ($_.domain).Contains("vstfs:///Framework/IdentityDomain/") } | Select-Object -First 1 -Property domain).domain
#        $accountID = $accountID.TrimStart('vstfs:///Framework/IdentityDomain/')
        $projfile = Get-Item -Path ".\data\Projects.json"
        $projects = Get-Content -Path $projfile.FullName -Raw
        $projects = ($projects | ConvertFrom-Json) | Select-Object -Property id, name
        $identfile = Get-Item -Path ".\data\Identities.json"
        $identities = Get-Content -Path $identfile.FullName -Raw
        $identities = $identities | ConvertFrom-Json <#| Where-Object {($_.descriptor).Contains("ServiceIdentity")  }#> | Select-Object -Property descriptor, customDisplayName, providerDisplayName
        $repositoryfile = Get-Item -Path ".\data\Repositories.json"
        $repos = Get-Content -Path $repositoryfile.FullName -Raw
        $repos = ($repos | ConvertFrom-Json).value | Select-Object -Property id, name
        $queryfile = Get-Item -Path ".\data\Queries.json"
        $queries = Get-Content -Path $queryfile.FullName -Raw
        $queries = ($queries | ConvertFrom-Json) | Select-Object -Property id, name
        $reader = [System.IO.File]::OpenText(".\data\Permissions.json")
        Remove-Item -Path ".\data\Permissions_Readable.json" -Force -ErrorAction SilentlyContinue
        $writer = New-Object System.IO.StreamWriter(".\data\Permissions_Readable.json", $false, [System.Text.Encoding]::UTF8)
        while($null -ne ($line = $reader.ReadLine())) {
            if ($line.Contains("`"friendlydescriptor`":"))
            {
                if ($line.Contains("S-")) 
                {
                    $newline = $line
                    $newline = $newline.Split(";") 
                    $groupSID = $newline[1].TrimEnd("`",")
                    $groupName = ($groups | Where-Object { $_.SID -eq $groupSID } | Select-Object -First 1 -Property principalName).principalName
                    if ($null -ne  $groupName)
                    {
                        $line = ("    `"friendlydescriptor`": `"$groupName`",").Replace("\","\\")
                    }
                    else {
                        #it seems like sometimes the SID a group has is not the same as the one in permissions (mostly for PCA group)
                        $grpUrl = "$($orgUrl)/_apis/identities?descriptors=Microsoft.TeamFoundation.Identity;$groupSID&api-version=7.2-preview.1"
                        $grpUrl = $grpUrl.Replace("dev.azure.com", "vssps.dev.azure.com")
                        $Result =  GET-AzureDevOpsRestAPI -RestAPIUrl $grpUrl -Authheader $Authheader
                        if ($null -ne $Result.results.value.descriptor)
                        {
                            $Result = $Result.results.value
                            $grp = @{
                                SID           = $groupSID
                                principalName = $Result.providerDisplayName
                            }
                            $line = ("    `"friendlydescriptor`": `"$($grp.principalName)`",").Replace("\","\\")
                            $groups += $grp
                        }
                    }
                }
                elseif (($line.Contains("ServiceIdentity")))
                {
                    $newline1 = $line
                    $svcAcc = $newline1.TrimStart("    `"friendlydescriptor`": `"").TrimEnd("`",")
                    $id = $identities | Where-Object { $_.descriptor -eq $svcAcc } | Select-Object -First 1
                    if ($null -ne  $id)
                    {
                        $identityName = ($null -eq $id.customDisplayName) ? $id.principalName : $id.customDisplayName
                        $line = "    `"friendlydescriptor`": `"$identityName`","
                    }
                } 
                elseif (($line.Contains("ServicePrincipal")))
                {
                    #I suspect that the service principal lookup needs to go here but there might be ACES for removed SP
                    $line = "    `"friendlydescriptor`": `"Service Principal lookup not yet implemented`","
                }
                elseif (($line.Contains("@")))
                {
                    $newline = $line
                    $newline = $newline.Split("\\") 
                    $UPN = $newline[1].TrimEnd("`",")
                    $line = "    `"friendlydescriptor`": `"$UPN`","
                }
            }
            elseif ($line.Contains("`"friendlyToken`":"))
            {
                $regex = [regex]'\b[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}\b'
                $regexMatches = $regex.Matches($line)
                foreach ($match in $regexMatches)
                {
                    $projectname = ($projects | Where-Object { $_.id -eq $match } | Select-Object -Property name).name 
                    if ($null -ne  $projectname)
                    {
                        $line = $line.Replace($match.Value,$projectname)
                    }
                    $groupName = ($groups | Where-Object { $_.originId -eq $match } | Select-Object -First 1 -Property principalName).principalName
                    if ($null -ne  $groupName)
                    {
                        $line = $line.Replace($match.Value,$groupName.Replace("\","\\"))
                    }
                    $repositoryName = ($repos | Where-Object { $_.id -eq $match } | Select-Object -First 1 -Property name).name
                    if ($null -ne  $repositoryName)
                    {
                        $line = $line.Replace($match.Value,$repositoryName)
                        if ($line.Contains("/refs/heads/"))
                        {   
                            $tokenNullSafe = $line.TrimStart("    `"friendlyToken`": `"").TrimEnd("`",")
                            for ($i = 5 ; $i -lt ($tokenNullSafe -split '/').Count ; $i = $i + 1) 
                            {
                                $asciiChars = (($tokenNullSafe -split '/')[$i]) -split "00" 
                                $charstring = ''
                                ForEach ($char in  $asciiChars)
                                {
                                    if ($char -ne '')
                                    {
                                        $charstring = $charstring + [char][byte]"0x$char" 
                                    }
                                }
                                $line = $line.Replace((($tokenNullSafe -split '/')[$i]), $charstring)
                            }
                        }
                    }
                    $queryName = ($queries | Where-Object { $_.id -eq $match } | Select-Object -First 1 -Property name).name
                    if ($null -ne  $queryName)
                    {
                        $line = $line.Replace($match.Value,$queryName)
                    }
                }
            }
            $writer.WriteLine($line)
            $count++
            if ($count % 5000 -eq 0)
            {
                Update-ConsoleLine -Line 2 -Message "Processed $count lines so far..."
            }
        }
    }
    catch
    {
        Update-ConsoleLine -Line 18 "ERROR:" +
        Update-ConsoleLine -Line 21 "ErrorDescription: $($_)"
        Update-ConsoleLine -Line 22 "at line $($_.InvocationInfo.ScriptLineNumber)"
    }
    finally
    {
        $reader.Close()
        $writer.Close()
        $groups = $null
        $projects = $null
        $identities = $null
        $queries = $null
    }
}
function Get-AzureDevOpsProjects {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try
    {
        $projectsurl = $orgUrl + "/_apis/projects?stateFilter=All&api-version=2.2"
        $projectResult =  GET-AzureDevOpsRestAPI -RestAPIUrl $projectsurl -Authheader $Authheader
        $projects = $projectResult.results.value
        try
        {
            #had some issues calling Graphapi, so I made this skip if it fails
            $graphToken =  Get-GraphToken #| Out-Null
            $Graphapiurl = "https://graph.microsoft.com/v1.0/organization/$($graphToken.TenantId)?`$select=Id,displayName"
            $domainResult =  GET-AzureDevOpsRestAPI -RestAPIUrl $Graphapiurl -Authheader $graphToken.AuthHeader
            $domainasproj = @{
                id             = $domainResult.results.id
                name           = $domainResult.results.displayName
                url            = $Graphapiurl
                state          = "Domain"
                revision       = 1
                visibility     = "Tenant"
                lastUpdateTime = [datetime]::MinValue
            }          
            $projects += $domainasproj
        }
        catch
        {
            "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "Function  : Get-AzureDevOpsProjects" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "*Graph API call failed, skipping tenant information*" | Out-File -FilePath ".\data\Errors.log" -Append -Force
            $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
            "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        }
        finally 
        {
            $projects | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Projects.json" -Append -Force
        }
    }
    Catch {
        "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Function  : Get-AzureDevOpsProjects" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        throw $_
    }
    finally 
    {
        $projects = $null
        $projectResult = $null
        $domainResult = $null
    }
}
function Get-AzureDevOpsGroups {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try
    {
        $allGroups = @()
        $orgUrl = $orgUrl.Replace("dev.azure.com", "vssps.dev.azure.com")
        $Result = $null
        Do
        {
            if  ($null -eq $Result.responseHeaders."x-ms-continuationtoken")
            {
                $groupInfourl = "$($orgUrl)/_apis/graph/groups?api-version=7.1-preview.1"
            }
            else 
            {
                $groupInfourl = "$($orgUrl)/_apis/graph/groups?continuationToken=$($Result.responseHeaders."x-ms-continuationtoken")&api-version=7.1-preview.1"
            }
            $Result =  GET-AzureDevOpsRestAPI -RestAPIUrl $groupInfourl -Authheader $Authheader
            $allGroups += $Result.results.value
        }
        While  ($null -ne $Result.responseHeaders."x-ms-continuationtoken")
        foreach ($group in $allGroups)
        {
            $descriptor = ($group.descriptor).Split(".")
            $crumb = $descriptor[1]
            switch ($crumb.Length % 4) {
                2 { $crumb += '==' }
                3 { $crumb += '=' }
            }
            $decode = $([Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($crumb)))
            $group | Add-Member -NotePropertyName 'SID' -NotePropertyValue $decode.ToString()
        }
        $allGroups | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Groups.json" -Force
    }
    Catch{
        "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Function  : Get-AzureDevOpsGroups" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        throw $_
    }
    finally
    {
        $allGroups = $null
    }
}
function Get-AzureDevOpsRepositories {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {    
        $reposUrl = "$($orgUrl)/_apis/git/repositories?api-version=7.2-preview.1"
        $reposResult = GET-AzureDevOpsRestAPI -RestAPIUrl $reposUrl -Authheader $Authheader
        $reposResult.results | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Repositories.json" -Force
    }
    Catch 
    {
        "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Function  : Get-AzureDevOpsRepositories" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        throw $_
    }
    finally 
    {
        $reposResult = $null
    }
}
function Get-AzureDevOpsQueries {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try
    {
        $projfile = Get-Item -Path ".\data\Projects.json"
        $projects = Get-Content -Path $projfile.FullName -Raw
        $projects = $projects | ConvertFrom-Json | Where-Object { $_.state -ne "Domain" } | Select-Object -Property id, name
        $queries = @()
        foreach ($project in $projects)
        {
            $queriesUrl = "$($orgUrl)/$($project.name)/_apis/wit/queries?depth=100&api-version=7.2-preview.2"
            $queryResult = GET-AzureDevOpsRestAPI -RestAPIUrl $queriesUrl -Authheader $Authheader
            if ($null -ne $queryResult.results.value) 
            {
                $queries += $queryResult.results.value
            }
        }
        $queries | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Queries.json" -Force
    }
    Catch {
        "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Function  : Get-AzureDevOpsQueries" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        throw $_
    }
    finally 
    {
        $queryResult = $null
        $queries = $null
        $projects = $null
    }
}
function Get-AzureDevOpsUsers {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {
        $allUsers = @()
        $orgUrl = $orgUrl.Replace("dev.azure.com", "vssps.dev.azure.com")
        $Result = $null
        Do
        {
            if ($null -eq $Result.responseHeaders."x-ms-continuationtoken") {
                $usersUrl = "$($orgUrl)/_apis/graph/users?api-version=7.2-preview.1"
            }
            else {
                $usersUrl = "$($orgUrl)/_apis/graph/users?continuationToken=$($Result.responseHeaders."x-ms-continuationtoken")&api-version=7.2-preview.1"
            }
            $Result = GET-AzureDevOpsRestAPI -RestAPIUrl $usersUrl -Authheader $Authheader
            Update-ConsoleLine -Line 12 -Message "Users Total: $($allUsers.Count)"
            $allUsers += $Result.results.value
            
        }
        While ($null -ne $Result.responseHeaders."x-ms-continuationtoken")

        Update-ConsoleLine -Line 12 -Message "Saving Users to file"
        $allUsers | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Users.json" -Force
        $descriptors = $allUsers | Select-Object -ExpandProperty descriptor
        $allUsers = $null
        $identityUrls = @()
        Update-ConsoleLine -Line 12 -Message "Batching descriptors in groups of 50 for API calls"
        for ($i = 0; $i -lt $descriptors.Count; $i += 50) {
            $batch = $descriptors[$i..([math]::Min($i+49, $descriptors.Count-1))]
            $descriptorString = $batch -join ','
            $identityUrl = "$($orgUrl)/_apis/identities?subjectDescriptors=$descriptorString&queryMembership=Direct&api-version=7.2-preview.1"
            $identityUrls += $identityUrl
        }
        $total = $descriptors.Count
        $processedItems = [hashtable]::Synchronized(@{
            Lock    = [System.Threading.Mutex]::new()
            Counter = 0
        })
        $queue = [System.Collections.Concurrent.ConcurrentQueue[pscustomobject]]::new()
        $identityUrls | Foreach-Object -ThrottleLimit 5 -Parallel {
            $identityUrl = $_
            $_Authheader = $using:Authheader
            $_queue = $using:queue
            $_total = $using:total
            $ref = $using:processedItems
            $scriptPath = $MyInvocation.MyCommand.Path
            if (-not $scriptPath) {
            $scriptPath = Get-ChildItem -Path "$((Get-Location).Path)\PermissionHelper.ps1" -ErrorAction Stop | Select-Object -ExpandProperty FullName -First 1
            }
            $env:IS_CHILD_JOB = $true 
            . "$scriptPath"
            $Result = GET-AzureDevOpsRestAPI -RestAPIUrl $identityUrl -Authheader $_Authheader
            if ($ref['Lock'].WaitOne()) 
            {
                $ref['Counter'] += $Result.results.Count
                $ref['Lock'].ReleaseMutex()
            }
            if ($ref['Counter'] % 5000 -eq 0)
            {
                Update-ConsoleLine -Line 12 -Message "Users Total: $($ref['Counter']) of $_total" 
            }
            $_queue.Enqueue($Result.results.value)
        }
        $queue | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Identities.json" -Force
    }
    Catch {
        "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Function  : Get-AzureDevOpsUsers" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        throw $_
    }
    finally 
    {
        Update-ConsoleLine -Line 12
        $descriptors = $null
        $Result = $null
        $queue = $null
    }
}
function Main {
    try
    {
        Remove-Item -Path ".\data\Permissions.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Permissions_Readable.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Groups.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Projects.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Repositories.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Queries.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Users.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Identities.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Errors.log" -Force -ErrorAction SilentlyContinue
        "Errorlog       :" | Out-File -FilePath ".\data\Errors.log" -Force
        Write-Host "Please enter your Org Name"
        $orgName = Read-Host
        $orgUrl = "https://dev.azure.com/$orgname"
        $token = Get-EntraToken
        $Authheader = $token.AuthHeader
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $scriptPath = $MyInvocation.MyCommand.Path
        if (-not $scriptPath) {
            $scriptPath = Get-ChildItem -Path "$((Get-Location).Path)\PermissionHelper.ps1" -ErrorAction Stop | Select-Object -ExpandProperty FullName -First 1
        }
        $jobSpecs = @(
            @{ Name = "GetPermissionsJob"; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsPermissions  -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; Streaming = $Host },
            @{ Name = "GetProjectsJob";    Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsProjects     -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; Streaming = $Host },
            @{ Name = "GetGroupsJob";      Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsGroups       -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; Streaming = $Host },
            @{ Name = "GetUsersJob";       Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsUsers        -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; Streaming = $Host },
            @{ Name = "GetReposJob";       Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsRepositories -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; Streaming = $Host },
            @{ Name = "GetQueriesJob";     Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsQueries      -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 1; Streaming = $Host }
        )
        $jobs = @()
        foreach ($spec in $jobSpecs) {
            if ($spec.Order -eq 0)
            {
                if ($spec.Streaming) {
                    $jobs += Start-ThreadJob -ScriptBlock $spec.Script -ArgumentList $spec.Args -Name $spec.Name -StreamingHost $spec.Streaming
                } else {
                    $jobs += Start-ThreadJob -ScriptBlock $spec.Script -ArgumentList $spec.Args -Name $spec.Name
                }
            }
        }
        clear-host
        [Console]::CursorVisible = $false
        $complete = @()
        while ($jobs.Count -gt 0) 
        {
            $timerpos = $jobs.Count + $complete.Count + 1
            foreach ($job in $jobs) {
                $state = $job.State
                $Name = $job.Name
                $Id = $job.Id
                if ($state -eq "Completed") {
                    Receive-Job -Job $job *>$null
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue *>$null
                    $done = [pscustomobject]@{
                        id = $Id
                        Name = $Name
                        State = $state
                    }
                    Update-ConsoleLine -Line $job.Id -Message "$($job.Name): $($job.State)"
                    if (($Name -eq "GetProjectsJob") -and ($null -eq ($jobs | Where-Object { $_.Name -eq "GetQueriesJob" } )) )
                    {
                        $next = $jobSpecs | Where-Object { $_.name -eq "GetQueriesJob" }
                        $jobs += Start-ThreadJob -ScriptBlock $next.Script -ArgumentList $next.Args -Name $next.Name -StreamingHost $spec.Streaming
                        $newid = $jobs | Where-Object { $_.Name -eq "GetQueriesJob" }
                        Update-ConsoleLine -Line $newid.Id -Message "$($newid.Name): $($newid.State)"
                    }
                    $complete += $done
                    $jobs = $jobs | Where-Object { $_.Id -ne $job.Id }
                }
                elseif ($state -eq "Failed"){
                    Update-ConsoleLine -Line $job.Id "$($job.Name): $state"
                    Update-ConsoleLine -Line 18 
                    Receive-Job -Job $jobs *>$null
                    Remove-Job -Job $jobs -Force *>$null
                    exit
                }
                else {
                    Update-ConsoleLine -Line $job.Id -Message "$($job.Name): $state"
                }
            }
            foreach ($done in $complete) {
                Update-ConsoleLine -Line $done.Id -Message "$($done.Name): $($done.State)"
            }
            Update-ConsoleLine -Line $timerpos -Message ("Execution time: {0:mm\:ss}" -f $stopwatch.Elapsed)
            for($inc = 1; $inc -le 4; $inc++) {
                Update-ConsoleLine -Line ($timerpos + $inc)
            }
            Start-Sleep -Seconds 2
        }
        Update-ConsoleLine -line 1 -Message "Performing Post Processing to give friendly tokens and descriptors..."
        for($inc = 2; $inc -le 15; $inc++) {
            Update-ConsoleLine -Line ($inc)
        }
        Convert-Permissions -Authheader $Authheader -orgUrl $orgUrl
        $stopwatch.Stop()
        [Console]::CursorVisible = $true
        Update-ConsoleLine -Line 13    
        Update-ConsoleLine -Line 3 -Message ("Total Execution time: {0:mm\:ss}" -f $stopwatch.Elapsed)
        Update-ConsoleLine -Line 4 -Message "All jobs completed successfully."
        Update-ConsoleLine -Line 5
    }
    Catch
    {
        "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Date/Time : $(Get-Date)" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "Function  : Get-AzureDevOpsProjects" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
        "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
        exit
    }
    finally 
    {
        $stopwatch = $null
        $Authheader = $null
        $orgUrl = $null
        $env:IS_CHILD_JOB = $false
    }
}

if (-not $env:IS_CHILD_JOB) {
    Main
}