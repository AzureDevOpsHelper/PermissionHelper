
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
    return $result
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
        $WarningPreference = $WP
        $ProgressPreference = $PP
        return $results
    }
    Catch {
        
        throw ("ERROR: `r`n" + 
        "StatusCode: $($_.Exception.Response.StatusCode.value__) `r`n" +
        "StatusDescription: $($_.Exception.Response.StatusDescription) `r`n" +
        "ErrorDescription: $($_) `r`n" +
        "at line $($_.InvocationInfo.ScriptLineNumber) `r`n`r`n" + 
        "StatusCode: $statusCode`r`n" +
        "Headers: + $responseHeaders`r`n" +
        "Body: $Response`r`n" +
        $_.Exception.Message)
    }
<#    finally {
        #region Debug&Throttle
        if #in theory this should add the details if debug is turned on OR if there is a non 200 pass OR if there is throttling happening 
        (
                ($Debug) `
            -or (($null -ne $responseHeaders."Retry-After")           -and ($responseHeaders."Retry-After"           -gt 0)) `
            -or (($null -ne $responseHeaders."X-RateLimit-Resource")  -and ($responseHeaders."X-RateLimit-Resource"  -ne "")) `
            -or (($null -ne $responseHeaders."X-RateLimit-Delay")     -and ($responseHeaders."X-RateLimit-Delay"     -gt 0)) `
            -or (($null -ne $responseHeaders."X-RateLimit-Limit")     -and ($responseHeaders."X-RateLimit-Limit"     -gt 0)) `
            -or (($null -ne $responseHeaders."X-RateLimit-Remaining") -and ($responseHeaders."X-RateLimit-Remaining" -gt 0)) `
            -or (($null -ne $responseHeaders."X-RateLimit-Reset")     -and ($responseHeaders."X-RateLimit-Reset"     -gt 0)) `
        )
        {
            Write-Host "StatusCode: $statusCode`r`n"
            Write-Host "Headers:"
            Write-Host $responseHeaders
            Write-Host "`r`nBody:`r`n"
            Write-Host $Response | ConvertTo-Json -depth 100 
        }
        #endregion Debug&Throttle
    }
    $results.Add("responseHeaders", $responseHeaders)
    $results.Add("statusCode", $statusCode)

    return $results
}#>
}

function Get-AzureDevOpsPermissions {
    param (
        [string]$Authheader,
        [string]$orgUrl
    )
    # This function retrieves the permissions for all namespaces in the Azure DevOps organization.
    # It uses the MSAL token to authenticate and make REST API calls to Azure DevOps.
    # The results are returned as a collection of permission items.
    $namespaceUrl = "$($orgUrl)/_apis/securitynamespaces?api-version=7.2-preview.1"
    $namespaces = GET-AzureDevOpsRestAPI -RestAPIUrl $namespaceUrl -Authheader $Authheader
    $queue = @()
    $namespaces.results.value | ForEach-Object {
        $namespace        = $_
        $permissionUrl = $orgUrl + "/_apis/accesscontrollists/" + $namespace.namespaceId + "?includeExtendedInfo=true&recurse=true&api-version=7.2-preview.1"
        $permissionResult = GET-AzureDevOpsRestAPI -RestAPIUrl $permissionUrl -Authheader $Authheader
        foreach ($permission in $permissionResult.results.value)
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
    }
#    $queue | Export-Csv -Path ".\Permissions.csv" -NoTypeInformation -Force
    $queue | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\Permissions.json" -Force
}

function Main {
    Write-Host "Please enter your Org Name"
    $orgName = Read-Host
    $orgUrl = "https://dev.azure.com/$orgname"
    $token = Get-MSALToken
    $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token.Token))
    $Authheader = "Bearer $plaintoken"
    Write-Host "Token acquired for User: $($token.UserId) in TenantID: $($token.TenantId). Good until $($token.ExpiresOn)"     
    Write-Host "Retrieving Azure DevOps permissions for Org: $orgName"

    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        Write-Host "Script path not found. Using current directory."
        $scriptPath = Get-ChildItem -Path "$((Get-Location).Path)\PermissionHelper.ps1" -ErrorAction Stop | Select-Object -First 1
    }
    Write-Host "Script path: $scriptPath"
    $job = Start-ThreadJob -ScriptBlock {
        param($Authheader, $orgUrl, $scriptPath)
        $env:IS_CHILD_JOB = $true
        . "$scriptPath"
        Get-AzureDevOpsPermissions -Authheader $Authheader -orgUrl $orgUrl
    } -ArgumentList $Authheader, $orgUrl, $scriptPath
    # We should be able to continue to start functions on threads here
    # We will need to Gather things like Identities, Groups, Teams, and Projects
    # I plan to save each result set to a file, and then combine them at the end.
    # this seems to be the best way to do this, as it allows us to run multiple jobs in parallel.
    # and also for large orgs, not overwhelm system memory trying to hold all the results in memory at once.
    # we will also need to handle throttling, as we will be making a lot of heavy API calls.
    # we can watch for the Retry-After header in the response, and if it is present, we can wait that many seconds before retrying the request.
    # We can also use the X-RateLimit-Remaining header to determine how many requests we have left before we hit the rate limit.
    # If we hit the rate limit, we can wait for the X-RateLimit-Reset header to determine when we can start making requests again.
    # We can also use the X-RateLimit-Delay header to determine how long we need to wait before making the next request
    Write-Host "Waiting for job to complete..."
    Wait-Job -Job $job -Timeout 300
    Write-Host "Job completed."
    Receive-Job -Job $job
}

# Only run Main if not running as a job (i.e., if $env:IS_CHILD_JOB is not set)
if (-not $env:IS_CHILD_JOB) {
    Main
}