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
        $spaces = (" " * ([Console]::BufferWidth - $Message.Length))
        [Console]::SetCursorPosition(0, $Line)
        if ($Message -ne "") {
            Write-Host "$($Message)$($spaces)"  -NoNewline
        } 
        else {
            Write-Host "$($spaces)"  -NoNewline
            [Console]::SetCursorPosition(0, $Line)
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
        try
        {
            $ErrorM | ConvertFrom-Json | ConvertTo-Json -Depth 10 | Out-File -FilePath ".\data\Errors.log" -Append -Force
        }
        catch
        {
            $ErrorM | Format-List | Out-File -FilePath ".\data\Errors.log" -Append -Force
        }
    }
    "---------------------------------------------------------------------------------------------------------------`r`n" | Out-File -FilePath ".\data\Errors.log" -Append -Force
    
}
function GET-AzureDevOpsRestAPI {
    param (
        [string]$Authheader,
        [string]$RestAPIUrl,
        [string]$Method = 'GET'
    )

    $Headers = @{
        Authorization           = $Authheader
        "X-TFS-FedAuthRedirect" = "Suppress"
    }
    $params = @{
        Uri                     = $RestAPIUrl
        Headers                 = $headers
        Method                  = $Method
        ContentType             = 'application/json'
        StatusCodeVariable      = 'statusCode' 
        ResponseHeadersVariable = 'responseHeaders'
    }
    try
    {   $WP = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        $PP = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        $results = New-Object "System.Collections.Generic.Dictionary[[String],[PSCustomObject]]"
        try
        {
            $result = Invoke-RestMethod @params 
        }
        catch 
        {
            if ($_.Exception.Response.StatusCode.value__ -eq 429)
            {
                $RetryAfter = 30.0
                [double]::TryParse($responseHeaders."Retry-After", [ref]$RetryAfter)
                Update-Log -Function "GET-AzureDevOpsRestAPI" -Message "Throttling (with Error: $($_.Exception.Response.StatusCode.value__)) sleeping for $RetryAfter seconds before resuming thread" -URL $RestAPIURL -ErrorM $_
                $RetryAfter += 2
                Start-Sleep -Seconds $RetryAfter
                if ($null -eq $result)
                {
                    $result = GET-AzureDevOpsRestAPI $Authheader $RestAPIUrl
                }
            }
            else 
            {
                throw $_
            }
        }
        $results.Add("results", $result)
        $results.Add("responseHeaders", $responseHeaders)
        $results.Add("statusCode", $statusCode)
        if ((($null -ne $responseHeaders."Retry-After") -and ($responseHeaders."Retry-After" -gt 0))){
            $RetryAfter = 30.0
            [double]::TryParse($responseHeaders."Retry-After", [ref]$RetryAfter)
            Update-Log -Function "GET-AzureDevOpsRestAPI" -Message "Throttling (non Error) sleeping for $RetryAfter seconds before resuming thread" -URL $RestAPIURL 
            $RetryAfter += 2
            Start-Sleep -Seconds $RetryAfter
            #$result = GET-AzureDevOpsRestAPI $Authheader $RestAPIUrl
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
        $activeNS | Foreach-Object -ThrottleLimit 7 -Parallel {
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

            #Update-Log -Function "Get-AzureDevOpsPermissions" -Message "`n`tNameSpace Name:       : $($namespace.name)`n`tNameSpace DisplayName : $($namespace.displayName)`n`tNameSpace ID          : $($namespace.namespaceId)`n`tCount                 : $($permissionResult.results.value.Count)"

            $permissionResult.results.value | ForEach-Object -ThrottleLimit 15 -Parallel {   
                $permission = $_
                $namespace  = $using:namespace
                $queue      = $using:threadSafeallPermissions
                $scriptPath = $MyInvocation.MyCommand.Path
                if (-not $scriptPath) {
                    $scriptPath = Get-ChildItem -Path "$((Get-Location).Path)\PermissionHelper.ps1" -ErrorAction Stop | Select-Object -ExpandProperty FullName -First 1
                }
                $env:IS_CHILD_JOB = $true 
                . "$scriptPath"
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
            if ($threadSafeallPermissions.Count -ne 0) 
            { 
                if ($ref['Lock'].WaitOne()) 
                {
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
        }
        "]" | Out-File -FilePath ".\data\Permissions.json" -append -Force
    }
    catch 
    {
        Update-Log -Function "Get-AzureDevOpsPermissions" -Message "Error while getting atomic permissions for $($namespace.name) - ($($namespace.namespaceId))" -URL $permissionUrl -ErrorM $_.InnerException
        throw $_ 
    }
    finally 
    {
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
    try
    {
        Update-Log -Function "Convert-Permissions" -Message "Starting to convert permissions file for $($orgUrl)"
        $count = 0
        Update-Log -Function "Convert-Permissions" -Message "Reading Groups file"
        $groupfile = Get-Item -Path ".\data\Groups.json"
        $groups = Get-Content -Path $groupfile.FullName -Raw
        $groups = ($groups | ConvertFrom-Json)  
        
        $TFID = ($groups | Where-Object { ($_.domain).Contains("vstfs:///Framework/IdentityDomain/") -and (($_.principalName).Contains("[TEAM FOUNDATION]") )} | Select-Object -First 1 -Property domain).domain
        $TFID = $TFID.TrimStart('vstfs:///Framework/IdentityDomain/')
        $TFID = @{ 
            id   = $TFID
            name = "[TEAM FOUNDATION]"
        }
        $orgname = ($orgUrl.Split("/"))[-1]
        $OrgID = ($groups | Where-Object { ($_.domain).Contains("vstfs:///Framework/IdentityDomain/") -and ($_.principalName).Contains("[$orgname]")} | Select-Object -First 1 -Property domain).domain
        if ($null -eq $OrgID)
        {
            $OrgID = @{
                id   = ""
                name = ""
            }
        }
        else
        {
            $OrgID = @{
                id   = $OrgID.Replace("vstfs:///Framework/IdentityDomain/","")
                name = "[$orgname]"
            }
        }

        $groups1 = $groups | Select-Object -Property SID, principalName
        $groups2 = $groups | Select-Object -Property originId, displayName
        $groups2 = $groups2 | Group-Object -AsHashTable -Property originId
        $groups = $groups1 | Group-Object -AsHashTable -Property SID 

        Update-Log -Function "Convert-Permissions" -Message "Loaded Groups file to Hashtables"
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

        Update-Log -Function "Convert-Permissions" -Message "Reading AnalyticsViews file"
        $Viewsfile = Get-Item -Path ".\data\AnalyticsViews.json"
        $Views = Get-Content -Path $Viewsfile.FullName -Raw
        $Views = ($Views | ConvertFrom-Json) | Select-Object -Property id, name
        $Views = $Views | Group-Object -AsHashtable -Property id
        Update-Log -Function "Convert-Permissions" -Message "Loaded AnalyticsViews file to Hashtable"
        Remove-Variable -Name $Viewsfile -ErrorAction SilentlyContinue
        
        Update-Log -Function "Convert-Permissions" -Message "Reading Processes file"
        $Processesfile = Get-Item -Path ".\data\Processes.json"
        $Processes = Get-Content -Path $Processesfile.FullName -Raw
        $Processes = ($Processes | ConvertFrom-Json) | Select-Object -Property typeId, name
        $Processes = $Processes | Group-Object -AsHashtable -Property typeId
        Update-Log -Function "Convert-Permissions" -Message "Loaded Processes file to Hashtable"
        Remove-Variable -Name $Processesfile -ErrorAction SilentlyContinue

        Update-Log -Function "Convert-Permissions" -Message "Reading Service Endpoints file"
        $serviceEndpointsfile = Get-Item -Path ".\data\serviceendpoint.json"
        $serviceEndpoints = Get-Content -Path $serviceEndpointsfile.FullName -Raw
        $serviceEndpoints = ($serviceEndpoints | ConvertFrom-Json) | Select-Object -Property id, name
        $serviceEndpoints = $serviceEndpoints | Group-Object -AsHashtable -Property id
        Update-Log -Function "Convert-Permissions" -Message "Loaded Service Endpoints file to Hashtable"
        Remove-Variable -Name $serviceEndpointsfile -ErrorAction SilentlyContinue

        Update-Log -Function "Convert-Permissions" -Message "Reading Dashboards file"
        $dashboardsfile = Get-Item -Path ".\data\Dashboards.json"
        $dashboards = Get-Content -Path $dashboardsfile.FullName -Raw
        $dashboards = ($dashboards | ConvertFrom-Json) | Select-Object -Property id, name
        $dashboards = $dashboards | Group-Object -AsHashtable -Property id
        Update-Log -Function "Convert-Permissions" -Message "Loaded Dashboards file to Hashtable"
        Remove-Variable -Name $dashboardsfile -ErrorAction SilentlyContinue

        Update-Log -Function "Convert-Permissions" -Message "Reading Plans file"
        $plansfile = Get-Item -Path ".\data\Plans.json"
        $plans = Get-Content -Path $plansfile.FullName -Raw
        $plans = ($plans | ConvertFrom-Json) | Select-Object -Property id, name
        $plans = $plans | Group-Object -AsHashtable -Property id
        Update-Log -Function "Convert-Permissions" -Message "Loaded Plans file to Hashtable"
        Remove-Variable -Name $plansfile -ErrorAction SilentlyContinue

        Update-Log -Function "Convert-Permissions" -Message "Reading Iterations file"
        $iterationsfile = Get-Item -Path ".\data\Iterations.json"
        $iterations = Get-Content -Path $iterationsfile.FullName -Raw
        $iterations = ($iterations | ConvertFrom-Json) | Select-Object -Property identifier, name
        $iterations = $iterations | Group-Object -AsHashtable -Property identifier
        Update-Log -Function "Convert-Permissions" -Message "Loaded Iterations file to Hashtable"
        Remove-Variable -Name $iterationsfile -ErrorAction SilentlyContinue

        Update-Log -Function "Convert-Permissions" -Message "Reading Areas file"
        $areasfile = Get-Item -Path ".\data\Areas.json"
        $areas = Get-Content -Path $areasfile.FullName -Raw
        $areas = ($areas | ConvertFrom-Json) | Select-Object -Property identifier, name
        $areas = $areas | Group-Object -AsHashtable -Property identifier
        Update-Log -Function "Convert-Permissions" -Message "Loaded Areas file to Hashtable"
        Remove-Variable -Name $areasfile -ErrorAction SilentlyContinue

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
                    $groupName = $groups[$groupSID].principalName
                    if ($null -ne  $groupName)
                    {
                        $line = ("    `"friendlydescriptor`": `"$groupName`",").Replace("\","\\")
                    }
                    else 
                    {
                        #it seems like sometimes the SID a group has is not the same as the one in permissions (mostly for PCA group)
                        try
                        {
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
                            $line = ("    `"friendlydescriptor`": `"$($Result.providerDisplayName)`",").Replace("\","\\")
                            $grp = @{     
                                SID = $groupSID 
                                principalName = $Result.providerDisplayName
                            }
                            $groups[$groupSID] = $grp
                        }
                        else 
                        {
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
                    $id = $identities[$svcAcc]
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
                    if ($null -eq $newline[1])
                    {   #covers BindPend users
                        $newline = $newline.Split(":") 
                        if ($null -eq $newline[1])
                        {   #anything else
                            $newline = $line.Replace("    `"friendlydescriptor`": `"","")
                        }
                    }
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
                    $projectname = $projects[$match.Value].name 
                    if ($null -ne  $projectname)
                    {
                        $line = $line.Replace($match.Value,$projectname)
                    }
                    else 
                    {
                        $groupName = $groups[$match.Value].principalName
                        if ($null -ne  $groupName)
                        {
                            $line = $line.Replace($match.Value,$groupName.Replace("\","\\"))
                        }
                        else 
                        {
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
                                $queryName = $queries[$match.Value].name
                                if ($null -ne  $queryName)
                                {
                                    $line = $line.Replace($match.Value,$queryName)
                                }
                                else
                                {
                                    $viewName = $Views[$match.Value].name
                                    if ($null -ne  $viewName)
                                    {
                                        $line = $line.Replace($match.Value,$viewName)
                                    }
                                    else
                                    {
                                        if ($TFID.id -eq  $match.Value)
                                        {
                                            $line = $line.Replace($match.Value,($TFID.name))
                                        }
                                        else
                                        {
                                            if ($OrgID.id -eq  $match.Value)
                                            {
                                                $line = $line.Replace($match.Value,($OrgID.name))
                                            }
                                            else
                                            {
                                                $ProcessName = $Processes[$match.Value].name
                                                if ($null -ne  $ProcessName)
                                                {
                                                    $line = $line.Replace($match.Value,$ProcessName)
                                                }
                                                else
                                                {
                                                    $serviceEndpointName = $serviceEndpoints[$match.Value].name
                                                    if ($null -ne  $serviceEndpointName)
                                                    {
                                                        $line = $line.Replace($match.Value,$serviceEndpointName)
                                                    }
                                                    else
                                                    {
                                                        $groupName2 = $groups2[$match.Value].displayName
                                                        if ($null -ne  $groupName2)
                                                        {
                                                            $line = $line.Replace($match.Value,$groupName2)
                                                        }
                                                        else
                                                        {
                                                            if ($match.Value -eq  "00000000-0000-0000-0000-000000000000")
                                                            {
                                                                $line = $line.Replace($match.Value,"[Default Team]")
                                                            }
                                                            else
                                                            {
                                                                $dashboardName = $dashboards[$match.Value].name
                                                                if ($null -ne  $dashboardName)
                                                                {
                                                                    $line = $line.Replace($match.Value,$dashboardName)
                                                                }
                                                                else
                                                                {
                                                                    $planName = $plans[$match.Value].name
                                                                    if ($null -ne  $planName)
                                                                    {
                                                                        $line = $line.Replace($match.Value,$planName)
                                                                    }
                                                                    else
                                                                    {
                                                                        $iterationName = $iterations[$match.Value].name
                                                                        if ($null -ne  $iterationName)
                                                                        {
                                                                            $line = $line.Replace($match.Value,$iterationName)
                                                                            $line = $line.Replace("vstfs:///Classification/Node/","")
                                                                        }
                                                                        else
                                                                        {
                                                                            $areaName = $areas[$match.Value].name
                                                                            if ($null -ne  $areaName)
                                                                            {
                                                                                $line = $line.Replace($match.Value,$areaName)
                                                                                $line = $line.Replace("vstfs:///Classification/Node/","")
                                                                            }
                                                                            else
                                                                            {
                                                                                if ($line.Contains("endpoints/"))
                                                                                {
                                                                                    try
                                                                                    {
                                                                                        $proj = $line.TrimStart("    `"friendlyToken`": `"endpoints").TrimEnd("`",")
                                                                                        $proj = $proj.Split("/")
                                                                                        $SCUrl = "$($orgUrl)/$($proj[1])/_apis/serviceendpoint/endpoints/$($match.Value)?api-version=7.2-preview.4"
                                                                                        $Result =  GET-AzureDevOpsRestAPI -RestAPIUrl $SCUrl -Authheader $Authheader
                                                                                        $Result = $Result.results
                                                                                        $name = "$($Result.type) - $($Result.owner) - $($Result.name)"
                                                                                    }
                                                                                    catch 
                                                                                    {
                                                                                        Update-Log -Function "Convert-Permissions" -Message "Error while attempting to find endpoint $($match.Value) in $($proj[1]) `nContinue without this info (added token to groups to avoid future calls)" -URL $SCUrl -ErrorM $_
                                                                                    }
                                                                                    if ($name -ne " -  - ")
                                                                                    {
                                                                                        $line = $line.Replace($match.Value,$name)
                                                                                        $serviceEndpoint = @{     
                                                                                            id = $match.Value 
                                                                                            name = $name
                                                                                        }
                                                                                        $serviceEndpoints[$match.Value] = $serviceEndpoint
                                                                                    }
                                                                                }
                                                                                else
                                                                                {
                                                                                    "---------------------------------------------------------------------------------------------------------------" | Out-File ".\data\Permissions_LookupMisses.log" -Append -Force
                                                                                    "Date/Time : $(Get-Date -Format "yyyy/MM/dd HH:mm:ss.fff")" | Out-File -FilePath ".\data\Permissions_LookupMisses.log" -Append -Force
                                                                                    $line | Out-File -FilePath ".\data\Permissions_LookupMisses.log" -Append -Force
                                                                                    "---------------------------------------------------------------------------------------------------------------" | Out-File ".\data\Permissions_LookupMisses.log" -Append -Force
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
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
        Update-Log -Function "Convert-Permissions" -Message "Error while processing permissions file" -URL ".\data\Permissions.json" -ErrorM $_ ".\data\Errors.log" -Append -Force
        throw $_ 
    }
    finally
    {
        $reader.Close()
        $reader.Dispose()
        $writer.Close()
        $Writer.Dispose()
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        Remove-Variable -Name $reader -ErrorAction SilentlyContinue
        Remove-Variable -Name $writer -ErrorAction SilentlyContinue
        Remove-Variable -Name $groups -ErrorAction SilentlyContinue
        Remove-Variable -Name $groups2 -ErrorAction SilentlyContinue
        Remove-Variable -Name $projects -ErrorAction SilentlyContinue
        Remove-Variable -Name $identities -ErrorAction SilentlyContinue
        Remove-Variable -Name $queries -ErrorAction SilentlyContinue
        Remove-Variable -Name $repos -ErrorAction SilentlyContinue
        Remove-Variable -Name $Views -ErrorAction SilentlyContinue
        Remove-Variable -Name $Processes -ErrorAction SilentlyContinue
        Remove-Variable -Name $serviceEndpoints -ErrorAction SilentlyContinue
        Remove-Variable -Name $dashboards -ErrorAction SilentlyContinue
        Remove-Variable -Name $plans -ErrorAction SilentlyContinue
        Remove-Variable -Name $iterations -ErrorAction SilentlyContinue
        Remove-Variable -Name $areas -ErrorAction SilentlyContinue
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
            $allUsers += $Result.results.value
            
        }
        While ($null -ne $Result.responseHeaders."x-ms-continuationtoken")
        $allUsers | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Users.json" -Force
        $descriptors = $allUsers | Select-Object -ExpandProperty descriptor
        Remove-Variable -Name $allUsers -ErrorAction SilentlyContinue
        $identityUrls = @()
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
        $identityUrls | Foreach-Object -ThrottleLimit 5 -Parallel {
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
            try
            {
                $Result = GET-AzureDevOpsRestAPI -RestAPIUrl $identityUrl -Authheader $_Authheader
            }
            catch
            {
                $errorContent = $_.ErrorDetails
                if ($null -ne $errorContent) 
                {
                    $message = $errorContent.Message
                    if ($message.Contains("TF400813")) {
                        Update-Log -Function "Get-AzureDevOpsUsers" -Message "permissions error (continue)" -URL $identityUrl -ErrorM $_.innerException
                        # Execution will continue here
                    } 
                    else 
                    {
                        throw $_.innerException
                    }
                } 
                else 
                {
                    throw $_
                }
            }
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
                $ref['Lock'].ReleaseMutex()
            }
        }
        "]" | Out-File -FilePath ".\data\Identities.json" -append -Force
    }
    Catch {
        Update-Log -Function "Get-AzureDevOpsUsers" -Message "Error while getting users for $($orgUrl)" -ErrorM $_
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
function Get-AzureDevOpsAnalyticsViews {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {   
        $orgUrl = $orgUrl.Replace("dev.azure.com", "analytics.dev.azure.com")
        Update-Log -Function "Get-AzureDevOpsAnalyticsViews" -Message "Starting to get Analytics Views for $($orgUrl)"
        $projfile = Get-Item -Path ".\data\Projects.json"
        $projects = Get-Content -Path $projfile.FullName -Raw
        $projects = $projects | ConvertFrom-Json | Where-Object { $_.state -ne "Domain" } | Select-Object -Property id, name
        $Views = @()
        foreach ($project in $projects)
        {
            $viewUrl = "$($orgUrl)/$($project.Name)/_apis/Analytics/Views?api-version=7.2-preview.1"
            $viewUrl = [System.Uri]::EscapeUriString($viewUrl)
            $ViewsResult = @()
            try
            {
                $ViewsResult = GET-AzureDevOpsRestAPI -RestAPIUrl $viewUrl -Authheader $Authheader
            }
            Catch 
            {
                $errorContent = $_.ErrorDetails
                if ($null -ne $errorContent) 
                {
                    $message = $errorContent.Message
                    if ($message.Contains("VS403490") -or $message.Contains("VS403605")) {
                        Update-Log -Function "Get-AzureDevOpsAnalyticsViews" -Message "permissions error for $($project.name) (continue)" -ErrorM $_.innerException
                        # Execution will continue here
                    } 
                    else 
                    {
                        throw $_.innerException
                    }
                } 
                else 
                {
                    throw $_
                }
            }
            if ($null -ne $ViewsResult.results.value) 
            {
                $Views += $ViewsResult.results.value
            }
        }
        if ($Views.Count -eq 0)
        {
            $dummy = @{
                id   = ''
                name = ''
            }
            $Views += $dummy
        }
        $Views | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\AnalyticsViews.json" -Force
    }
    Catch 
    {
        Update-Log -Function "Get-AzureDevOpsAnalyticsViews" -Message "Error while getting Analytics Views for $($orgUrl)" -URL $orgUrl -ErrorM $_
        throw $_
    }
    finally 
    {
        Remove-Variable -Name $Views -ErrorAction SilentlyContinue
        Remove-Variable -Name $ViewsResult -ErrorAction SilentlyContinue
        Remove-Variable -Name $projects -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsAnalyticsViews" -Message "Done getting Analytics Views for $($orgUrl)"
    }
}
function Get-AzureDevOpsServiceEndpoints {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {   
        Update-Log -Function "Get-AzureDevOpsServiceEndpoints" -Message "Starting to get Service Endpoints for $($orgUrl)"
        $projfile = Get-Item -Path ".\data\Projects.json"
        $projects = Get-Content -Path $projfile.FullName -Raw
        $projects = $projects | ConvertFrom-Json | Where-Object { $_.state -ne "Domain" } | Select-Object -Property id, name
        #$typesUrl = "$($orgUrl)/_apis/serviceendpoint/types?api-version=7.1"
        #$types = GET-AzureDevOpsRestAPI -RestAPIUrl $typesUrl -Authheader $Authheader
        #$types = $types.results.value | Select-Object -Property id, name, url
        $endpoints = @()
        foreach ($project in $projects)
        {
            #foreach ($type in $types) 
            #{
            #    $endpointUrl = "$($orgUrl)/$($project.name)/_apis/serviceendpoint/endpoints?type=$($type.id)&includeFailed=true&api-version=7.1"
            #    $endpointResult = GET-AzureDevOpsRestAPI -RestAPIUrl $endpointUrl -Authheader $Authheader
            #    if ($null -ne $endpointResult.results.value) 
            #    {
            #        $endpoints += $endpointResult.results.value
            #    }
            #}
            $endpointUrl = "$($orgUrl)/$($project.name)/_apis/serviceendpoint/endpoints?includeFailed=true&api-version=7.2-preview.4"
            $endpointResult = GET-AzureDevOpsRestAPI -RestAPIUrl $endpointUrl -Authheader $Authheader
            if ($null -ne $endpointResult.results.value) 
            {
                $endpoints += $endpointResult.results.value
            }
        }
        if ($endpoints.Count -eq 0)
        {
            $dummy = @{
                id   = ''
                name = ''
            }
            $endpoints += $dummy
        }
        $endpoints | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\ServiceEndpoint.json" -Force
    }
    Catch 
    {
        Update-Log -Function "Get-AzureDevOpsServiceEndpoints" -Message "Error while getting Service Endpoints for $($orgUrl)" -URL $reposUrl -ErrorM $_
        throw $_
    }
    finally 
    {
        Remove-Variable -Name $endpoints -ErrorAction SilentlyContinue
        Remove-Variable -Name $endpointsResult -ErrorAction SilentlyContinue
        Remove-Variable -Name $projects -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsServiceEndpoints" -Message "Done getting Service Endpoints for $($orgUrl)"
    }
}
function Get-AzureDevOpsProcesses {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {   
        Update-Log -Function "Get-AzureDevOpsProcesses" -Message "Starting to get Processes for $($orgUrl)"
        $processUrl = "$($orgUrl)/_apis/work/processes?api-version=7.2-preview.2"
        $processResult = GET-AzureDevOpsRestAPI -RestAPIUrl $processUrl -Authheader $Authheader
        $processResult.results.value | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Processes.json" -Force
    }
    Catch 
    {
        Update-Log -Function "Get-AzureDevOpsProcesses" -Message "Error while getting Processes for $($processUrl)" -URL $reposUrl -ErrorM $_
        throw $_
    }
    finally 
    {
        Remove-Variable -Name $processResult -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsProcesses" -Message "Done getting Processes for $($processUrl)"
    }
}
function Get-AzureDevOpsDashboards {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {   
        Update-Log -Function "Get-AzureDevOpsDashboards" -Message "Starting to get Dashboards for $($orgUrl)"
        $projfile = Get-Item -Path ".\data\Projects.json"
        $projects = Get-Content -Path $projfile.FullName -Raw
        $projects = $projects | ConvertFrom-Json | Where-Object { $_.state -ne "Domain" } | Select-Object -Property id, name
        $Dashboards = @()
        foreach ($project in $projects)
        {
            $DashboardsUrl = "$($orgUrl)/$($project.name)/_apis/dashboard/dashboards?api-version=7.2-preview.3"
            $DashboardsResult = GET-AzureDevOpsRestAPI -RestAPIUrl $DashboardsUrl -Authheader $Authheader
            $Dashboards += $DashboardsResult.results.value
        }
        $Dashboards | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Dashboards.json" -Force
    }
    Catch 
    {
        Update-Log -Function "Get-AzureDevOpsDashboards" -Message "Error while getting Dashboards for $($DashboardsUrl)" -URL $reposUrl -ErrorM $_
        throw $_
    }
    finally 
    {
        Remove-Variable -Name $DashboardsResult -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsDashboards" -Message "Done getting Dashboards for $($orgUrl)"
    }
}
function Get-AzureDevOpsPlans {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {   
        Update-Log -Function "Get-AzureDevOpsPlans" -Message "Starting to get Plans for $($orgUrl)"
        $projfile = Get-Item -Path ".\data\Projects.json"
        $projects = Get-Content -Path $projfile.FullName -Raw
        $projects = $projects | ConvertFrom-Json | Where-Object { $_.state -ne "Domain" } | Select-Object -Property id, name
        $Plans = @()
        foreach ($project in $projects)
        {
            $PlansUrl = "$($orgUrl)/$($project.name)/_apis/work/plans?api-version=7.2-preview.1"
            try
            {
                $PlansResult = GET-AzureDevOpsRestAPI -RestAPIUrl $PlansUrl -Authheader $Authheader
            }
            Catch {
                $errorContent = $_.ErrorDetails
                if ($null -ne $errorContent) 
                {
                    $message = $errorContent.Message
                    if (($message).Contains("TF50309")) {
                        Update-Log -Function "Get-AzureDevOpsPlans" -Message "permissions error for $($project.name) (continue)" -ErrorM $_.innerException
                        # Execution will continue here
                    } 
                    else 
                    {
                        throw $_.innerException
                    }
                } 
                else 
                {
                    throw $_
                }
            }
            if ($null -ne $PlansResult.results.value) 
            {
                $Plans += $PlansResult.results.value
            }
        }
        if ($Plans.Count -eq 0)
        {
            $dummy = @{
                id   = ''
                name = ''
            }
            $Plans += $dummy
        }
        $Plans | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Plans.json" -Force
    }
    Catch 
    {
        Update-Log -Function "Get-AzureDevOpsPlans" -Message "Error while getting Plans for $($orgUrl)" -URL $orgUrl -ErrorM $_
        throw $_
    }
    finally 
    {
        Remove-Variable -Name $DashboardsResult -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsPlans" -Message "Done getting Plans for $($orgUrl)"
    }
}
function Convert-ClassificationNodes {
    param ( 
        [PSCustomObject]$Node
    )
    try
    {
        $flatlist = @()
        $flatlist += $Node
        if ($null -ne $Node.hasChildren -and $Node.hasChildren -eq $true) 
        {
            foreach ($child in $Node.children) 
            {
                $child | Add-Member -NotePropertyName 'projectName' -NotePropertyValue $Node.projectName
                $flatlist += Convert-ClassificationNodes -Node $child
                
            }
        }
        $flatlist = $flatlist | Select-Object -Property id, identifier, name, structureType, projectName, path, url
        return $flatlist
    }
    catch 
    {
        Update-Log -Function "Convert-ClassificationNodes" -Message "Error while converting Classification Nodes" -ErrorM $_
        throw $_
    }
}
function Get-AzureDevOpsClassificationNodes {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    try 
    {
        write-host "Starting to get ClassificationNodes for $($orgUrl)"
        $projfile = Get-Item -Path ".\data\Projects.json"
        $projects = Get-Content -Path $projfile.FullName -Raw
        $projects = $projects | ConvertFrom-Json | Where-Object { $_.state -ne "Domain" } | Select-Object -Property id, name
        $nodes = @()
        foreach ($project in $projects)
        {
            $classificationNodesUrl = "$($orgUrl)/$($project.name)/_apis/wit/classificationnodes?`$depth=10&api-version=7.2-preview.2"
            $classificationNodesResult = GET-AzureDevOpsRestAPI -RestAPIUrl $classificationNodesUrl -Authheader $Authheader
            foreach ($node in $classificationNodesResult.results.value) 
            {
                $node | Add-Member -NotePropertyName 'projectName' -NotePropertyValue $project.name
                $newnodes = Convert-ClassificationNodes -Node $node
                $nodes += $newnodes
            }
        }
        $nodes | Where-Object { $_.structureType -eq "area"     } | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Areas.json"      -Force
        $nodes | Where-Object { $_.structureType -eq "iteration"} | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Iterations.json" -Force
    }
    Catch 
    {
        Update-Log -Function "Get-AzureDevOpsClassificationNodes" -Message "Error while getting ClassificationNodes for $($orgUrl)" -URL $reposUrl -ErrorM $_
        throw $_
    }
    finally 
    {
        Remove-Variable -Name $IterationsResult -ErrorAction SilentlyContinue
        Remove-Variable -Name $nodes -ErrorAction SilentlyContinue
        Remove-Variable -Name $projects -ErrorAction SilentlyContinue
        Remove-Variable -Name $classificationNodesUrl -ErrorAction SilentlyContinue
        Remove-Variable -Name $classificationNodesResult -ErrorAction SilentlyContinue
        Update-Log -Function "Get-AzureDevOpsIterations" -Message "Done getting Iterations for $($orgUrl)"
    }
}
function Main {
    try
    {
        if (-not (Test-Path -Path ".\data")) 
        {
            New-Item -ItemType Directory -Path $folderPath
        } 
        Remove-Item -Path ".\data\Permissions.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Permissions_Readable.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Groups.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Projects.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Repositories.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Queries.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Users.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Identities.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\AnalyticsViews.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\ServiceEndpoint.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Processes.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Dashboards.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Errors.log" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Plans.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Areas.json" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ".\data\Iterations.json" -Force -ErrorAction SilentlyContinue
        #Remove-Item -Path ".\data\Permissions_LookupMisses.log" -Force -ErrorAction SilentlyContinue
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
            @{ Name = "GetPermissionsJob         "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsPermissions         -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; Streaming = $Host },
            @{ Name = "GetProjectsJob            "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsProjects            -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; },
            @{ Name = "GetGroupsJob              "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsGroups              -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; },
            @{ Name = "GetUsersJob               "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsUsers               -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; Streaming = $Host },
            @{ Name = "GetReposJob               "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsRepositories        -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; },
            @{ Name = "GetProcessesJob           "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsProcesses           -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 0; },
            @{ Name = "GetAnalyticsViewsJob      "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsAnalyticsViews      -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 1; },
            @{ Name = "GetServiceEndpointsJob    "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsServiceEndpoints    -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 1; },
            @{ Name = "GetQueriesJob             "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsQueries             -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 1; },
            @{ Name = "GetDashboardsJob          "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsDashboards          -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 1; },
            @{ Name = "GetPlansJob               "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsPlans               -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 1; }
            @{ Name = "GetClassificationNodesJob "; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsClassificationNodes -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Order = 1; }
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
                    if (($Name -eq "GetProjectsJob            ") -and ($null -eq ($jobs | Where-Object { $_.Name -eq "GetClassificationNodesJob " } )) )
                    {
                        $next = $jobSpecs | Where-Object { $_.name -eq "GetClassificationNodesJob " }
                        $jobs += Start-ThreadJob -ScriptBlock $next.Script -ArgumentList $next.Args -Name $next.Name -StreamingHost $spec.Streaming
                    }
                    if (($Name -eq "GetProjectsJob            ") -and ($null -eq ($jobs | Where-Object { $_.Name -eq "GetQueriesJob             " } )) )
                    {
                        $next = $jobSpecs | Where-Object { $_.name -eq "GetQueriesJob             " }
                        $jobs += Start-ThreadJob -ScriptBlock $next.Script -ArgumentList $next.Args -Name $next.Name -StreamingHost $spec.Streaming
                    }
                    if (($Name -eq "GetProjectsJob            ") -and ($null -eq ($jobs | Where-Object { $_.Name -eq "GetAnalyticsViewsJob      " } )) )
                    {
                        $next = $jobSpecs | Where-Object { $_.name -eq "GetAnalyticsViewsJob      " }
                        $jobs += Start-ThreadJob -ScriptBlock $next.Script -ArgumentList $next.Args -Name $next.Name -StreamingHost $spec.Streaming
                    }
                    if (($Name -eq "GetProjectsJob            ") -and ($null -eq ($jobs | Where-Object { $_.Name -eq "GetServiceEndpointsJob    " } )) )
                    {
                        $next = $jobSpecs | Where-Object { $_.name -eq "GetServiceEndpointsJob    " }
                        $jobs += Start-ThreadJob -ScriptBlock $next.Script -ArgumentList $next.Args -Name $next.Name -StreamingHost $spec.Streaming
                    }
                    if (($Name -eq "GetProjectsJob            ") -and ($null -eq ($jobs | Where-Object { $_.Name -eq "GetDashboardsJob          " } )) )
                    {
                        $next = $jobSpecs | Where-Object { $_.name -eq "GetDashboardsJob          " }
                        $jobs += Start-ThreadJob -ScriptBlock $next.Script -ArgumentList $next.Args -Name $next.Name -StreamingHost $spec.Streaming
                    }
                    if (($Name -eq "GetProjectsJob            ") -and ($null -eq ($jobs | Where-Object { $_.Name -eq "GetPlansJob               " } )) )
                    {
                        $next = $jobSpecs | Where-Object { $_.name -eq "GetPlansJob               " }
                        $jobs += Start-ThreadJob -ScriptBlock $next.Script -ArgumentList $next.Args -Name $next.Name -StreamingHost $spec.Streaming
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
            Update-ConsoleLine -Line $timerpos -Message ("Execution time            : {0:hh\:mm\:ss}" -f $stopwatch.Elapsed)
            Start-Sleep -Milliseconds 200
        }
        Clear-Host
        Update-ConsoleLine -line 1 -Message "Performing Post Processing to give friendly tokens and descriptors..."    
        Convert-Permissions -Authheader $Authheader -orgUrl $orgUrl
        $files = @(
            ".\data\Groups.json",
            ".\data\Projects.json",
            ".\data\Repositories.json",
            ".\data\Queries.json",
            ".\data\Users.json",
            ".\data\Identities.json",
            ".\data\AnalyticsViews.json",
            ".\data\ServiceEndpoint.json",
            ".\data\Processes.json",
            ".\data\Dashboards.json",
            ".\data\Plans.json",
            ".\data\Areas.json",
            ".\data\Iterations.json",
            ".\data\Permissions_Readable.json",
            ".\data\Errors.log"
            ".\data\Permissions.json"
        )
        $zipName = "$($OrgName)Info_$(Get-Date -Format "yyyyMMdd_hhmmss")"
        $zipFolder = "./data/$zipname"
        $zipName = $zipName += ".zip" 
        New-Item -ItemType Directory -Path $zipFolder | Out-Null
        Update-ConsoleLine -line 1 -Message "Consolidating Data files for archival (it may take up to a minute to begin moving Permissions.json)..."
        Update-ConsoleLine -line 2
        foreach ($file in $files) {
            Update-ConsoleLine -Line 3
            Update-ConsoleLine -Line 2
            Move-Item -Path $file -Destination $zipFolder -Force -Verbose
        }
        Update-ConsoleLine -Line 3
        Update-ConsoleLine -Line 1 -Message "Archiving files to $zipFolder\$zipName..."
        Update-ConsoleLine -Line 2
        Compress-Archive -Path "$zipFolder\*" -DestinationPath "$zipFolder\$zipName" -Force -CompressionLevel Optimal
        Update-ConsoleLine -Line 1 -Message "Cleaning up Data files..."
        Update-ConsoleLine -Line 2
        $files = $files | Select-Object { $_ -ne ".\data\Permissions_Readable.json"}
        $remove = Get-ChildItem -Path $zipFolder -File | Where-Object { $_.Name -ne "Permissions_Readable.json" -and $_.Name -ne $zipName } 
        foreach ($file in $remove)
        {
            Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
        }
        $stopwatch.Stop()
        [Console]::CursorVisible = $true
        Update-ConsoleLine -Line 1 -Message  "Permissions file     : $($scriptPath.Replace("\PermissionHelper.ps1",''))$($zipFolder.Replace(".",'').Replace("/","\"))\Permissions_Readable.json" 
        Update-ConsoleLine -Line 2 -Message  "Data files           : $($scriptPath.Replace("\PermissionHelper.ps1",''))$($zipFolder.Replace(".",'').Replace("/","\"))\$($zipName.Replace("/","\"))"
        Update-ConsoleLine -Line 3 -Message ("Total Execution time : {0:hh\:mm\:ss}" -f $stopwatch.Elapsed)
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
        $sysvars = @("__VSCodeState","$","^","args","Error","input","IsCoreCLR","IsLinux","IsMacOS","IsWindows","MyInvocation","PROFILE","PSBoundParameters","PSCommandPath","PSScriptRoot","PWD","StackTrace")
        Get-Variable | Where-Object { $_.Name -notin $sysvars -and $_.Description -eq "" } | Format-List | Remove-Variable -Force -ErrorAction SilentlyContinue
        Get-Module | Remove-Module -ErrorAction SilentlyContinue
        #Get-Command -CommandType Function | ForEach-Object { Remove-Item "function:$($_.Name)" -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue
    }
}

if (-not $env:IS_CHILD_JOB) {
    Main
}