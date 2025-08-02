
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
        [int]$Line,
        [string]$Message = ""
    )
    if ($Global:Console['Lock'].WaitOne()) 
    {
<#        if ($line -gt 10 )
        {
            $gotime = [int](Get-Date -Format "fff")  
            $diff = ($line * 10)  - $gotime
            if ($diff -lt 0) 
            {
                $diff += 1000  
            }
            Start-Sleep -Milliseconds $diff
        } #>
        $Global:Console['Line'] = $Line
        [Console]::SetCursorPosition(0, $Line)
        [Console]::Write(" " * ([Console]::BufferWidth))
        [Console]::SetCursorPosition(0, $Line)
        if ($Message -ne "") {
                Write-Host $Message -NoNewline
        } 
        $Global:Console['Lock'].ReleaseMutex()
    }
}
function Update-Log {
    param (
        [string]$Function       = "",
        [string]$Message        = "",
        [string]$URL            = "",
        [PSCustomObject]$ErrorM = $null
    )
    "---------------------------------------------------------------------------------------------------------------" | Out-File -FilePath ".\data\Errors.log" -Append -Force
    "Date/Time : $(Get-Date -Format "yyyy/MM/dd HH:mm:ss.fff")" | Out-File -FilePath ".\data\Errors.log" -Append -Force
    "Function  : $Function" | Out-File -FilePath ".\data\Errors.log" -Append -Force
    if ($null -ne $Message -and $Message -ne "") 
    {
        "Message   : $Message" | Out-File -FilePath ".\data\Errors.log" -Append -Force
    }
    if ($null -ne $URL -and $URL -ne "") 
    {
        "URL       : $URL" | Out-File -FilePath ".\data\Errors.log" -Append -Force
    }
    if ($null -ne $ErrorM)
    {    
        $_ | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
    }
    "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
    
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
            Update-Log -Function "GET-AzureDevOpsRestAPI" -Message "Throttling (non Error) sleeping for $RetryAfter seconds before resuming thread" -URL $RestAPIURL 
            Start-Sleep -Seconds $RetryAfter            
        }
        $WarningPreference = $WP
        $ProgressPreference = $PP
        return $results
    }
    Catch {
        Update-Log -Function "GET-AzureDevOpsRestAPI" -Message "Api call failed `nStatusCode: $($_.Exception.Response.StatusCode.value__) - $($_.Exception.Response.StatusDescription)" -URL $RestAPIURL -ErrorM $_
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
        Update-Log -Function "Get-AzureDevOpsPermissions" -Message "Starting to get atomic permissions for $($orgUrl)"
        $namespaceUrl = "$($orgUrl)/_apis/securitynamespaces?api-version=7.2-preview.1"
        $namespaces = GET-AzureDevOpsRestAPI -RestAPIUrl $namespaceUrl -Authheader $Authheader
        $processedItems = [hashtable]::Synchronized(@{
            Lock    = [System.Threading.Mutex]::new()
            File    = ".\data\Permissions.json"
        })
        #remove Deprecated and read-only namespaces https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference?view=azure-devops#deprecated-and-read-only-namespaces
        $activeNS = $namespaces.results.value | Where-Object {$_.Name -ne "CrossProjectWidgetView" -and `
                                                            $_.Name -ne "DataProvider" -and `
                                                            $_.Name -ne "Favorites" -and `
                                                            $_.Name -ne "Graph" -and `
                                                            $_.Name -ne "Identity2" -and `
                                                            $_.Name -ne "IdentityPicker"-and `
                                                            $_.Name -ne "Job" -and `
                                                            $_.Name -ne "Location" -and `
                                                            $_.Name -ne "ProjectAnalysisLanguageMetrics" -and `
                                                            $_.Name -ne "Proxy" -and `
                                                            $_.Name -ne "Publish" -and `
                                                            $_.Name -ne "Registry" -and `
                                                            $_.Name -ne "Security" -and `
                                                            $_.Name -ne "ServicingOrchestration" -and `
                                                            $_.Name -ne "SettingEntries" -and `
                                                            $_.Name -ne "Social" -and `
                                                            $_.Name -ne "StrongBox"-and `
                                                            $_.Name -ne "TeamLabSecurity" -and `
                                                            $_.Name -ne "TestManagement" -and `
                                                            $_.Name -ne "VersionControlItems2" -and `
                                                            $_.Name -ne "ViewActivityPaneSecurity" -and `
                                                            $_.Name -ne "WebPlatform"-and `
                                                            $_.Name -ne "WorkItemsHub" -and `
                                                            $_.Name -ne "WorkItemTracking" -and `
                                                            $_.Name -ne "WorkItemTrackingConfiguration"}
        $activeNS = $activeNS | Sort-Object -Property name
        $activeNS | Foreach-Object -ThrottleLimit 12 -Parallel {
            $namespace        = $_
            $Authheader       = $using:Authheader
            $_orgUrl          = $using:orgUrl
            $ref              = $using:processedItems
            $scriptPath = $MyInvocation.MyCommand.Path
            $threadSafeallPermissions = [System.Collections.Concurrent.ConcurrentQueue[pscustomobject]]::new()
            if (-not $scriptPath) {
                $scriptPath = Get-ChildItem -Path "$((Get-Location).Path)\PermissionHelper.ps1" -ErrorAction Stop | Select-Object -ExpandProperty FullName -First 1
            }
            $env:IS_CHILD_JOB = $true 
            . "$scriptPath"
            $permissionUrl = $_orgUrl + "/_apis/accesscontrollists/" + $namespace.namespaceId + "?includeExtendedInfo=true&recurse=true&api-version=7.2-preview.1"
            $permissionResult = GET-AzureDevOpsRestAPI -RestAPIUrl $permissionUrl -Authheader $Authheader
            #Update-ConsoleLine -Line 13 -Message "Getting Namespace: $($namespace.name) - ($($namespace.namespaceId))" 
            #foreach ($permission in $permissionResult.results.value)
            #{
            $permissionResult.results.value | ForEach-Object -ThrottleLimit 15 -Parallel {   
                $permission = $_
                $namespace  = $using:namespace
                #$Authheader = $using:Authheader
                #$orgUrl     = $using:orgUrl
                $queue      = $using:threadSafeallPermissions
                $scriptPath = $MyInvocation.MyCommand.Path
                if (-not $scriptPath) {
                    $scriptPath = Get-ChildItem -Path "$((Get-Location).Path)\PermissionHelper.ps1" -ErrorAction Stop | Select-Object -ExpandProperty FullName -First 1
                }
                $env:IS_CHILD_JOB = $true 
                . "$scriptPath"
                #$sp = ($permission.token).Split("/")
                #Update-ConsoleLine -Line 14 -Message "Token: $(sp[1])/.../$($sp[-1])"
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
                        $queue.Enqueue($permissionitem)
                    }
                }
            }
            #$allPermissions = @()
            #$allPermissions = [array]$threadSafeallPermissions
            #Remove-Variable -Name threadSafeallPermissions -ErrorAction SilentlyContinue
            if ($threadSafeallPermissions.Count -ne 0) 
            { 
                if ($ref['Lock'].WaitOne()) 
                {
                    #Update-ConsoleLine -Line 13 -Message "Completed Namespace: $($namespace.name) - ($($namespace.namespaceId))" 
                    #Update-ConsoleLine -Line 14 -Message "Writing to File: $($namespace.name) - ($($namespace.namespaceId))"
                    if ( Test-Path $ref['File'] )
                    {
                        "," | Out-File -FilePath $ref['File'] -append -force -NoNewline
                        ((($threadSafeallPermissions | ConvertTo-Json -Depth 100).TrimStart("[")).TrimEnd("]")) | Out-File -FilePath $ref['File'] -append -force -NoNewline
                    }
                    else 
                    {
                        "[" | Out-File -FilePath $ref['File'] -Force -NoNewline
                        ((($threadSafeallPermissions | ConvertTo-Json -Depth 100).TrimStart("[")).TrimEnd("]")) | Out-File -FilePath $ref['File'] -append -force -NoNewline
                    }
                    $ref['Lock'].ReleaseMutex()
                }
            }                   
            #$queue = @()
        }
        "]" | Out-File -FilePath ".\data\Permissions.json" -append -Force
        #Update-ConsoleLine -Line 14 -Message "Written to File: $($namespace.name) - ($($namespace.namespaceId))"
    }
    catch 
    {
        Update-Log -Function "Get-AzureDevOpsPermissions" -Message "Error while getting atomic permissions for $($namespace.name) - ($($namespace.namespaceId))" -URL $permissionUrl -ErrorM $_
        throw $_ 
    }
    finally 
    {
    #    Update-ConsoleLine -Line 13
    #    Update-ConsoleLine -Line 14
        Remove-Variable -Name $namespaces -ErrorAction SilentlyContinue
        Remove-Variable -Name $processedItems -ErrorAction SilentlyContinue
        Remove-Variable -Name $permissionResult -ErrorAction SilentlyContinue
        Remove-Variable -Name $threadSafeallPermissions -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsPermissions" -Message "Done getting atomic permissions for $($orgUrl)"
    }
}
function Convert-Permissions {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    # todo: Resolve Service Accounts and Service Principals
    # todo: Lookup:
    # AnalyticsViews, 
    # ServiceEndpoints, 
    # Plan, 
    # Process, 
    # CSS, 
    # Iteration, 
    # Workspaces (seems like this is associated with VS Profile), 
    # DashboardsPrivileges
    try
    {
        Update-Log -Function "Convert-Permissions" -Message "Starting to convert permissions file for $($orgUrl)"
        $count = 0
        Update-Log -Function "Convert-Permissions" -Message "Reading Groups file"
        $groupfile = Get-Item -Path ".\data\Groups.json"
        $groups = Get-Content -Path $groupfile.FullName -Raw
        $groups = ($groups | ConvertFrom-Json) | Select-Object -Property SID, principalName 
        $groups = $groups | Group-Object -AsHashTable -Property SID 
        Update-Log -Function "Convert-Permissions" -Message "Loaded Groups file to Hashtable"
        Remove-Variable -Name $groupfile -ErrorAction SilentlyContinue
        
        Update-Log -Function "Convert-Permissions" -Message "Reading Projects file"
        $projfile = Get-Item -Path ".\data\Projects.json"
        $projects = Get-Content -Path $projfile.FullName -Raw
        $projects = ($projects | ConvertFrom-Json) | Select-Object -Property id, name
        $projects = $projects | Group-Object -AsHashtable -Property id
        Update-Log -Function "Convert-Permissions" -Message "Loaded Projects file to Hashtable"
        Remove-Variable -Name $projfile -ErrorAction SilentlyContinue
        
        Update-Log -Function "Convert-Permissions" -Message "Reading Identities file"
        $identfile = Get-Item -Path ".\data\Identities.json"
        $identities = Get-Content -Path $identfile.FullName -Raw
        $identities = ($identities | ConvertFrom-Json) | Select-Object -Property descriptor, customDisplayName, providerDisplayName
        $identities = $identities | Group-Object -AsHashtable -Property descriptor
        Update-Log -Function "Convert-Permissions" -Message "Loaded Identities file to Hashtable"
        Remove-Variable -Name $identfile -ErrorAction SilentlyContinue
        
        Update-Log -Function "Convert-Permissions" -Message "Reading repos file"
        $repositoryfile = Get-Item -Path ".\data\Repositories.json"
        $repos = Get-Content -Path $repositoryfile.FullName -Raw
        $repos = ($repos | ConvertFrom-Json).value | Select-Object -Property id, name
        $repos = $repos | Group-Object -AsHashtable -Property id
        Update-Log -Function "Convert-Permissions" -Message "Loaded repos file to Hashtable"
        Remove-Variable -Name $repositoryfile -ErrorAction SilentlyContinue
        
        Update-Log -Function "Convert-Permissions" -Message "Reading Queries file"
        $queryfile = Get-Item -Path ".\data\Queries.json"
        $queries = Get-Content -Path $queryfile.FullName -Raw
        $queries = ($queries | ConvertFrom-Json) | Select-Object -Property id, name
        $queries = $queries | Group-Object -AsHashtable -Property id
        Update-Log -Function "Convert-Permissions" -Message "Loaded Queries file to Hashtable"
        Remove-Variable -Name $queryfile -ErrorAction SilentlyContinue
        
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
                    #$groupName = ($groups | Where-Object { $_.SID -eq $groupSID } | Select-Object -First 1 -Property principalName).principalName
                    #Update-Log -Function "Convert-Permissions" -Message "Processing group with SID $groupSID"
                    $groupName = $groups[$groupSID].principalName
                    #Update-Log -Function "Convert-Permissions" -Message "Found group with SID $groupSID - $groupName"
                    if ($null -ne  $groupName)
                    {
                        $line = ("    `"friendlydescriptor`": `"$groupName`",").Replace("\","\\")
                    }
                    else 
                    {
                        #it seems like sometimes the SID a group has is not the same as the one in permissions (mostly for PCA group)
                        try
                        {
                            #Update-Log -Function "Convert-Permissions" -Message "Group with SID $groupSID not found in Groups file, trying to get it from Graph API"
                            $grpUrl = "$($orgUrl)/_apis/identities?descriptors=Microsoft.TeamFoundation.Identity;$groupSID&api-version=7.2-preview.1"
                            $grpUrl = $grpUrl.Replace("dev.azure.com", "vssps.dev.azure.com")
                            $Result =  GET-AzureDevOpsRestAPI -RestAPIUrl $grpUrl -Authheader $Authheader
                        }
                        catch 
                        {
                            Update-Log -Function "Convert-Permissions" -Message "Error while processing group with SID $groupSID `nContinue without this info (added token to groups to avoid future calls)" -URL $grpUrl -ErrorM $_
                        }
                        if ($null -ne $Result.results.value.descriptor)
                        {
                            $Result = $Result.results.value
                            #Update-Log -Function "Convert-Permissions" -Message "Found group with SID $groupSID in Graph API - $($Result.providerDisplayName)"
                            $line = ("    `"friendlydescriptor`": `"$($Result.providerDisplayName)`",").Replace("\","\\")
                            $grp = @{     
                                SID = $groupSID 
                                principalName = $Result.providerDisplayName
                            }
                            $groups[$groupSID] = $grp
                        }
                        else 
                        {
                            #Update-Log -Function "Convert-Permissions" -Message "Group with SID $groupSID not found in Groups file or Graph API, adding it to groups hashtable as $groupSID"
                            $grp = @{ 
                                SID = $groupSID 
                                principalName = $groupSID
                        }
                            $groups[$groupSID] = $grp
                        }
                    }
                }
                elseif (($line.Contains("ServiceIdentity")))
                {
                    $newline1 = $line
                    $svcAcc = $newline1.TrimStart("    `"friendlydescriptor`": `"").TrimEnd("`",")
                    #Update-Log -Function "Convert-Permissions" -Message "Processing service account with descriptor $svcAcc"
                    #$svcAcc = "Microsoft.IdentityModel.Claims.ClaimsIdentity;72f988bf-86f1-41af-91ab-2d7cd011db47\v-malasaini@microsoft.com"  
                    #Measure-Command{
                    #$id = $identities | Where-Object { $_.descriptor -eq $svcAcc } | Select-Object -First 1
                    $id = $identities[$svcAcc]
                    #Update-Log -Function "Convert-Permissions" -Message "Found service account with descriptor $svcAcc - $($id.customDisplayName)"`
                    #$id
                    #}

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
                    #$projectname = ($projects | Where-Object { $_.id -eq $match } | Select-Object -Property name).name
                    $projectname = $projects[$match.Value].name 
                    if ($null -ne  $projectname)
                    {
                        $line = $line.Replace($match.Value,$projectname)
                    }
                    else 
                    {
                        #$groupName = ($groups | Where-Object { $_.originId -eq $match } | Select-Object -First 1 -Property principalName).principalName
                        $groupName = $groups[$match.Value].principalName
                        if ($null -ne  $groupName)
                        {
                            $line = $line.Replace($match.Value,$groupName.Replace("\","\\"))
                        }
                        else 
                        {
                            #$repositoryName = ($repos | Where-Object { $_.id -eq $match } | Select-Object -First 1 -Property name).name
                            $repositoryName = $repos[$match.Value].name
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
                            else
                            {
                                #$queryName = ($queries | Where-Object { $_.id -eq $match } | Select-Object -First 1 -Property name).name
                                $queryName = $queries[$match.Value].name
                                if ($null -ne  $queryName)
                                {
                                    $line = $line.Replace($match.Value,$queryName)
                                }
                            }
                        }
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
        Update-Log -Function "Convert-Permissions" -Message "Error while processing permissions file" -URL ".\data\Permissions.json" -ErrorM $_ath ".\data\Errors.log" -Append -Force
        throw $_ 
    }
    finally
    {
        $reader.Close()
        $writer.Close()
        Remove-Variable -Name $groups -ErrorAction SilentlyContinue
        Remove-Variable -Name $projects -ErrorAction SilentlyContinue
        Remove-Variable -Name $identities -ErrorAction SilentlyContinue
        Remove-Variable -Name $queries -ErrorAction SilentlyContinue
        Remove-Variable -Name $repos -ErrorAction SilentlyContinue
        Update-Log -Function "Convert-Permissions" -Message "Done converting permissions file for $($orgUrl)"
    }
}
function Get-AzureDevOpsProjects {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try
    {
        Update-Log -Function "Get-AzureDevOpsProjects" -Message "Starting to get projects for $($orgUrl)"
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
            Update-Log -Function "Get-AzureDevOpsProjects" -Message "Graph API call failed, skipping tenant information" -URL $Graphapiurl -ErrorM $_h ".\data\Errors.log" -Append -Force
        }
        finally 
        {
            $projects | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Projects.json" -Append -Force
        }
    }
    Catch {
        Update-Log -Function "Get-AzureDevOpsProjects" -Message "Error while getting projects for $($orgUrl)" -URL $projectsurl -ErrorM $_ePath ".\data\Errors.log" -Append -Force
        throw $_
    }
    finally 
    {
        Remove-Variable -Name $projects -ErrorAction SilentlyContinue
        Remove-Variable -Name $projectResult -ErrorAction SilentlyContinue
        Remove-Variable -Name $domainResult -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsProjects" -Message "Done getting projects for $($orgUrl)"
    }
}
function Get-AzureDevOpsGroups {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try
    {
        Update-Log -Function "Get-AzureDevOpsGroups" -Message "Starting to get groups for $($orgUrl)"
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
        Update-Log -Function "Get-AzureDevOpsGroups" -Message "Error while getting groups for $($orgUrl)" -URL $groupInfourl -ErrorM $_
        throw $_
    }
    finally
    {
        Remove-Variable -Name $allGroups -ErrorAction SilentlyContinue
        Remove-Variable -Name $Result -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsGroups" -Message "Done getting groups for $($orgUrl)"
    }
}
function Get-AzureDevOpsRepositories {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {   
        Update-Log -Function "Get-AzureDevOpsRepositories" -Message "Starting to get repositories for $($orgUrl)"
        $reposUrl = "$($orgUrl)/_apis/git/repositories?api-version=7.2-preview.1"
        $reposResult = GET-AzureDevOpsRestAPI -RestAPIUrl $reposUrl -Authheader $Authheader
        $reposResult.results | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Repositories.json" -Force
    }
    Catch 
    {
        Update-Log -Function "Get-AzureDevOpsRepositories" -Message "Error while getting repositories for $($orgUrl)" -URL $reposUrl -ErrorM $_
        throw $_
    }
    finally 
    {
        Remove-Variable -Name $reposResult -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsRepositories" -Message "Done getting repositories for $($orgUrl)"
    }
}
function Get-AzureDevOpsQueries {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try
    {
        Update-Log -Function "Get-AzureDevOpsQueries" -Message "Starting to get queries for $($orgUrl)"
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
        Update-Log -Function "Get-AzureDevOpsQueries" -Message "Error while getting queries for $($orgUrl)/$($project.name)" -URL $queriesUrl -ErrorM $_
        throw $_
    }
    finally 
    {
        Remove-Variable -Name $queryResult -ErrorAction SilentlyContinue
        Remove-Variable -Name $queries -ErrorAction SilentlyContinue
        Remove-Variable -Name $projects -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsQueries" -Message "Done getting queries for $($orgUrl)"
    }
}
function Get-AzureDevOpsUsers {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {
        Update-Log -Function "Get-AzureDevOpsUsers" -Message "Starting to get users for $($orgUrl)"
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
            #Update-ConsoleLine -Line 12 -Message "Users Total: $($allUsers.Count)"
            $allUsers += $Result.results.value
            
        }
        While ($null -ne $Result.responseHeaders."x-ms-continuationtoken")

        #Update-ConsoleLine -Line 12 -Message "Saving Users to file"
        $allUsers | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Users.json" -Force
        $descriptors = $allUsers | Select-Object -ExpandProperty descriptor
        Remove-Variable -Name $allUsers -ErrorAction SilentlyContinue
        $identityUrls = @()
        #Update-ConsoleLine -Line 12 -Message "Batching descriptors in groups of 50 for API calls"
        for ($i = 0; $i -lt $descriptors.Count; $i += 50) {
            $batch = $descriptors[$i..([math]::Min($i+49, $descriptors.Count-1))]
            $descriptorString = $batch -join ','
            #$identityUrl = "$($orgUrl)/_apis/identities?subjectDescriptors=$descriptorString&queryMembership=Direct&api-version=7.2-preview.1"
            $identityUrl = "$($orgUrl)/_apis/identities?subjectDescriptors=$descriptorString&api-version=7.2-preview.1"
            $identityUrls += $identityUrl
        }
        Remove-Variable -Name $descriptors -ErrorAction SilentlyContinue
        $processed = [hashtable]::Synchronized(@{
            Lock   = [System.Threading.Mutex]::new()
            File   = ".\data\Identities.json"
            Count  = 0
        })
        $Total = $identityUrls.Count
        #Update-ConsoleLine -Line 12 -Message "Getting Identities in parallel"
        $identityUrls | Foreach-Object -ThrottleLimit 6 -Parallel {
            $identityUrl = $_
            $Total = $using:Total
            $_Authheader = $using:Authheader
            $ref = $using:processed
            $scriptPath = $MyInvocation.MyCommand.Path
            if (-not $scriptPath) {
            $scriptPath = Get-ChildItem -Path "$((Get-Location).Path)\PermissionHelper.ps1" -ErrorAction Stop | Select-Object -ExpandProperty FullName -First 1
            }
            $env:IS_CHILD_JOB = $true 
            . "$scriptPath"
            $Result = GET-AzureDevOpsRestAPI -RestAPIUrl $identityUrl -Authheader $_Authheader
            $queue = $Result.results.value
            if ($ref['Lock'].WaitOne()) 
            {
                if ( Test-Path $ref['File'] )
                {
                    "," | Out-File -FilePath $ref['File'] -append -force -NoNewline
                    $queue = $queue | ConvertTo-Json -Depth 100
                    $queue = $queue.Trim("[", "`n", "]")
                    $queue  | Out-File -FilePath $ref['File'] -append -force -NoNewline
                }
                else 
                {
                    "[" | Out-File -FilePath $ref['File'] -Force -NoNewline
                    $queue = $queue | ConvertTo-Json -Depth 100
                    $queue = $queue.TrimStart("[")
                    $queue = $queue.Trim("[", "`n", "]")
                    $queue  | Out-File -FilePath $ref['File'] -append -force -NoNewline
                }
                $ref['Count']++
                #Update-ConsoleLine -Line 12 -Message "Processed $($ref['Count']) groups out of $Total groups"
                $ref['Lock'].ReleaseMutex()
            }                   
        }
        "]" | Out-File -FilePath ".\data\Identities.json" -append -Force
    }
    Catch {
        Update-Log -Function "Get-AzureDevOpsUsers" -Message "Error while getting users for $($orgUrl)" -URL $identityUrl -ErrorM $_
        throw $_
    }
    finally 
    {
        Update-ConsoleLine -Line 12
        Remove-Variable -Name $Result -ErrorAction SilentlyContinue
        Remove-Variable -Name $queue -ErrorAction SilentlyContinue
        Remove-Variable -Name $identityUrls -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsUsers" -Message "Done getting users for $($orgUrl)"
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
        Update-Log -Function "Main" -Message "Starting execution of PermissionHelper.ps1"
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
            @{ Name = "GetProjectsJob";    Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsProjects     -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; },
            @{ Name = "GetGroupsJob";      Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsGroups       -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; },
            @{ Name = "GetUsersJob";       Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsUsers        -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; Streaming = $Host },
            @{ Name = "GetReposJob";       Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsRepositories -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; },
            @{ Name = "GetQueriesJob";     Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsQueries      -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 1; }
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
        Clear-Host
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
            Update-ConsoleLine -Line $timerpos -Message ("Execution time: {0:hh\:mm\:ss}" -f $stopwatch.Elapsed)
#            for($inc = 1; $inc -le 4; $inc++) {
#                Update-ConsoleLine -Line ($timerpos + $inc)
#            }
            Start-Sleep -Seconds 1
        }
        Clear-Host
        Update-ConsoleLine -line 1 -Message "Performing Post Processing to give friendly tokens and descriptors..."
        #for($inc = 2; $inc -le 10; $inc++) {
        #    Update-ConsoleLine -Line ($inc)
        #}        
        Convert-Permissions -Authheader $Authheader -orgUrl $orgUrl
        $stopwatch.Stop()
        [Console]::CursorVisible = $true
        
        #Update-ConsoleLine -Line 13    
        Update-ConsoleLine -Line 3 -Message ("Total Execution time: {0:hh\:mm\:ss}" -f $stopwatch.Elapsed)
        Update-ConsoleLine -Line 4 -Message "All jobs completed successfully."
        Update-ConsoleLine -Line 5
    }
    Catch
    {
        Update-Log -Function "Main" -Message "Error while executing PermissionHelper.ps1" -ErrorM $_
        exit
    }
    finally 
    {
        $env:IS_CHILD_JOB = $false
        Remove-Variable -Name * -ErrorAction SilentlyContinue
        Update-Log -Function "Main" -Message "Done executing PermissionHelper.ps1"
    }
}

$Global:Console = [hashtable]::Synchronized(@{
    Lock   = [System.Threading.Mutex]::new()
    Line   = [int] 0
})

if (-not $env:IS_CHILD_JOB) {
    Main
}