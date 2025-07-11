
function Get-MSALToken {
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
    $AuthHeader = "Bearer $plaintoken"
    $result | Add-Member -NotePropertyName 'AuthHeader' -NotePropertyValue $AuthHeader -Force
    return $result
}
function Update-ConsoleLine {
    param (
        [int]$Line = 0,
        [string]$Message = ""
    )
    #$xAxis = [Console]::CursorLeft
    #$yAxis = [Console]::CursorTop
    [Console]::SetCursorPosition(0, $Line)
    [Console]::Write(" " * ([Console]::BufferWidth))
    [Console]::SetCursorPosition(0, $Line)
    if ($Message -ne "") {
            Write-Host $Message -NoNewline
    }
    #[Console]::SetCursorPosition($xAxis, $yAxis)
}
function GET-AzureDevOpsRestAPI {
    param (
        [string]$Authheader,
        [string]$RestAPIUrl
    )
    #Write-Host "Calling Azure DevOps Rest API"
    #Write-Host "URL: $RestAPIUrl"
    #Write-Host "AuthHeader: $Authheader"
    #$debug = $false
    $Headers = @{
        Authorization           = $Authheader
        "X-TFS-FedAuthRedirect" = "Suppress"
    }
    $params = @{
        Uri                     = $RestAPIUrl
        Headers                 = $headers
        Method                  = 'GET'
        ContentType             = 'application/json'
        StatusCodeVariable      = 'statusCode' # this is a parameter to pass the variable (no $) to retain the status code of the HTTP Response.
        ResponseHeadersVariable = 'responseHeaders' #This is the parameter to pass the variable (no $) to retain the http headers from the response.
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
        if (($null -ne $responseHeaders."Retry-After") -and ($responseHeaders."Retry-After" -gt 0)){
            $RetryAfter = 30.0
            [double]::TryParse($responseHeaders."Retry-After", [ref]$RetryAfter)
            Update-ConsoleLine -Line 15 -Message "$RestAPIURL returned: "
            Update-ConsoleLine -Line 16 -Message "X-RateLimit-Remaining: $RetryAfter)"
            Update-ConsoleLine -Line 17 -Message "Sleeping for $RetryAfter seconds to avoid throttling."
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
        Update-ConsoleLine -Line 18 "ERROR:" +
        Update-ConsoleLine -Line 19 "RestAPIUrl: $RestAPIUrl"
        Update-ConsoleLine -Line 20 "StatusCode: $($_.Exception.Response.StatusCode.value__)"
        Update-ConsoleLine -Line 21 "ErrorDescription: $($_)"
        Update-ConsoleLine -Line 22 "at line $($_.InvocationInfo.ScriptLineNumber)"
        break
    }
}
function Get-AzureDevOpsPermissions {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    $namespaceUrl = "$($orgUrl)/_apis/securitynamespaces?api-version=7.2-preview.1"
    $namespaces = GET-AzureDevOpsRestAPI -RestAPIUrl $namespaceUrl -Authheader $Authheader
    $queue = @()
    $i = 0
    $namespaces.results.value | ForEach-Object {
        $namespace        = $_
        $permissionUrl = $orgUrl + "/_apis/accesscontrollists/" + $namespace.namespaceId + "?includeExtendedInfo=true&recurse=true&api-version=7.2-preview.1"
        $permissionResult = GET-AzureDevOpsRestAPI -RestAPIUrl $permissionUrl -Authheader $Authheader
        $i +=  $permissionResult.results.Count
        Update-ConsoleLine -Line 8 -Message "Aces Total: $i working on NamespaceId: $($namespace.namespaceId)"
        $queue += $permissionResult.results.value           
    }
    $queue | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Permissions.json" -Force
    Update-ConsoleLine -Line 8
}
function Process-Permissions {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    $queue = @()
    $permissionResult = Get-Content -Path ".\data\Permissions.json" | ConvertFrom-Json
    foreach ($permission in $permissionResult)
        {
            foreach ($descriptor in ((($permission.acesDictionary).psobject.Properties).Value))
            {  
                $_descriptor = $descriptor.descriptor
                $allowNullSafe                = ($null -eq $permission.acesDictionary."$_descriptor".allow) ? 0 : $permission.acesDictionary."$_descriptor".allow
                $denyNullSafe                 = ($null -eq $permission.acesDictionary."$_descriptor".deny) ? 0 : $permission.acesDictionary."$_descriptor".deny
                $effectiveAllowNullSafe       = ($null -eq $permission.acesDictionary."$_descriptor".extendedInfo.effectiveAllow) ? 0 : $permission.acesDictionary."$_descriptor".extendedInfo.effectiveAllow
                $effectiveDenyNullSafe        = ($null -eq $permission.acesDictionary."$_descriptor".extendedInfo.effectiveDeny) ? 0 : $permission.acesDictionary."$_descriptor".extendedInfo.effectiveDeny
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
                    allow                = $allowNullSafe
                    deny                 = $denyNullSafe
                    effectiveAllow       = $effectiveAllowNullSafe
                    effectiveDeny        = $effectiveDenyNullSafe
                    enumactions          = $enumactions | ConvertTo-Json | ConvertFrom-Json
                } 

                if ($permissionitem.allow -gt 0 -or $permissionitem.deny -gt 0 -or $permissionitem.effectiveAllow -gt 0 -or $permissionitem.effectiveDeny -gt 0)
                {
                    $queue += $permissionitem
                }
            }
        }
    $queue | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\ProcessedPermissions.json" -Force
}
function Get-AzureDevOpsProjects {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    $projectsurl = $orgUrl + "/_apis/projects?stateFilter=All&api-version=2.2"
    $projectResult =  GET-AzureDevOpsRestAPI -RestAPIUrl $projectsurl -Authheader $Authheader
    $projectResult.results | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Projects.json" -Force
}
function Get-AzureDevOpsGroups {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
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
        #$Result.results.value | ForEach-Object {
        #    $group = $_
        #    $allGroups += $group
        #}
    }
    While  ($null -ne $Result.responseHeaders."x-ms-continuationtoken")
    foreach ($group in $allGroups)
    {
        #Write-Host $group.descriptor
        $descriptor = ($group.descriptor).Split(".")
        $crumb = $descriptor[1]
        #Write-Host $crumb
        switch ($crumb.Length % 4) {
            2 { $crumb += '==' }
            3 { $crumb += '=' }
        }
        $decode = $([Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($crumb)))
        $group | Add-Member -NotePropertyName 'SID' -NotePropertyValue $decode.ToString()
    }
    $allGroups | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Groups.json" -Force
}
function Get-AzureDevOpsRepositories {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    $reposUrl = "$($orgUrl)/_apis/git/repositories?api-version=7.2-preview.1"
    $reposResult = GET-AzureDevOpsRestAPI -RestAPIUrl $reposUrl -Authheader $Authheader
    $reposResult.results | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Repositories.json" -Force
}
function Get-AzureDevOpsUsers {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    $allIdentities = @()
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
        Update-ConsoleLine -Line 9 -Message "Users Total: $($allUsers.Count)"
        $allUsers += $Result.results.value
        
    }
    While ($null -ne $Result.responseHeaders."x-ms-continuationtoken")

    Update-ConsoleLine -Line 9 -Message "Saving Users to file"
    $allUsers | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Users.json" -Force
    $descriptors = $allUsers | Select-Object -ExpandProperty descriptor
    $allUsers = $null
    #this works but is inefficent, might want to add parallel processing later
    for ($i = 0; $i -lt $descriptors.Count; $i += 60) {
        $batch = $descriptors[$i..([math]::Min($i+59, $descriptors.Count-1))]
        $descriptorString = $batch -join ','
        $identityUrl = "$($orgUrl)/_apis/identities?subjectDescriptors=$descriptorString&queryMembership=Direct&api-version=7.2-preview.1"
        $Result = GET-AzureDevOpsRestAPI -RestAPIUrl $identityUrl -Authheader $Authheader
        Update-ConsoleLine -Line 9 -Message "Users Total: $i of $($descriptors.Count)" 
        $queue += $permissionResult.results.value 
        $allIdentities += $Result.results.value
    }
    $allIdentities | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\data\Identites.json" -Force
    Update-ConsoleLine -Line 9
}
function Main {
    Write-Host "Please enter your Org Name"
    $orgName = Read-Host
    $orgUrl = "https://dev.azure.com/$orgname"
    $token = Get-MSALToken
    $Authheader = $token.AuthHeader
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        $scriptPath = Get-ChildItem -Path "$((Get-Location).Path)\PermissionHelper.ps1" -ErrorAction Stop | Select-Object -ExpandProperty FullName -First 1
    }
    $jobSpecs = @(
        @{ Name = "GetPermissionsJob"; Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsPermissions -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Streaming = $Host },
        @{ Name = "GetProjectsJob";    Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsProjects -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath) },
        @{ Name = "GetGroupsJob";      Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsGroups -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath) },
        @{ Name = "GetUsersJob";       Script = { param($Authheader, $orgUrl, $scriptPath); $env:IS_CHILD_JOB = $true; . "$scriptPath"; Get-AzureDevOpsUsers -Authheader $Authheader -orgUrl $orgUrl }; Args = @($Authheader, $orgUrl, $scriptPath); Streaming = $Host }
    )
    $jobs = @()
    foreach ($spec in $jobSpecs) {
        if ($spec.Streaming) {
            $jobs += Start-ThreadJob -ScriptBlock $spec.Script -ArgumentList $spec.Args -Name $spec.Name -StreamingHost $spec.Streaming
        } else {
            $jobs += Start-ThreadJob -ScriptBlock $spec.Script -ArgumentList $spec.Args -Name $spec.Name
        }
    }
    clear-host
    [Console]::CursorVisible = $false
    $timerpos = $jobs.Count + 1
    while ($jobs.Count -gt 0) {
        $complete = @()
        foreach ($job in $jobs) {
            $state = $job.State
            if ($state -eq "Completed") {
                Receive-Job -Job $job *>$null
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue *>$null
                $jobs = $jobs | Where-Object { $_.Id -ne $job.Id }
                $done = [pscustomobject]@{
                    id = $job.Id
                    Name = $job.Name
                    State = $state
                }
                $complete += $done
                Update-ConsoleLine -Line $job.Id -Message "$($job.Name): $state"
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
        foreach ($job in $complete) {
            Update-ConsoleLine -Line $job.Id -Message "$($job.Name): $($job.State)"
        }
        Update-ConsoleLine -Line $timerpos -Message ("Execution time: {0:mm\:ss}" -f $stopwatch.Elapsed)
        Update-ConsoleLine -Line 10
        Update-ConsoleLine -Line 11
        Update-ConsoleLine -Line 12
        Update-ConsoleLine -Line 13
        Update-ConsoleLine -Line 14
        Start-Sleep -Seconds 1
    }
    [Console]::CursorVisible = $true
    $stopwatch.Stop()
    Update-ConsoleLine -Line $timerpos -Message ("Total Execution time: {0:mm\:ss}" -f $stopwatch.Elapsed)
    Update-ConsoleLine -Line ($timerpos + 1) -Message "All jobs completed successfully."
    Update-ConsoleLine -Line ($timerpos + 2)
}

# Only run Main if not running as a job (i.e., if $env:IS_CHILD_JOB is not set)
if (-not $env:IS_CHILD_JOB) {
    Main
}