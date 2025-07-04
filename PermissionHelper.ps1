
function Get-MSALToken 
{
    try
    {
        Write-Host "AZ login will open a modal identity picker in the top left of the screen, please choose the account you want to use."
        Write-Host "It may take a few seconds to load, please be patient."  
        Write-Host "It will then ask you to pick a subscription, please choose a subscription that is associated with the tenant that backs your org."
        Connect-AzAccount 
        $result = Get-AzAccessToken -ResourceUrl '499b84ac-1321-427f-aa17-267ca6975798'
        Clear-Host
    }
    catch
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

# PowerShell doesn't have a Main function like C# or Java, so we can just call the functions directly.
    $orgname = "sagranvso"
    $orgUrl = "https://dev.azure.com/$orgname"
    $token = Get-MSALToken
    $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token.Token))
    $Authheader = "Bearer $plaintoken"
    Write-Host "Token acquired for User: $($token.UserId) in TenantID: $($token.TenantId). Good until $($token.ExpiresOn)"     
    $namespaceUrl = "$($orgUrl)/_apis/securitynamespaces?api-version=7.2-preview.1"
    $namespaces = GET-AzureDevOpsRestAPI -RestAPIUrl $namespaceUrl -Authheader $Authheader
    $queue = @()
    $namespaces.results.value | ForEach-Object {
        $namespace        = $_
        $permissionUrl = $orgUrl + "/_apis/accesscontrollists/" + $namespace.namespaceId + "?includeExtendedInfo=true&recurse=true&api-version=7.2-preview.1"
        $permissionResult = GET-AzureDevOpsRestAPI -RestAPIUrl $permissionUrl -Authheader $Authheader
        foreach ($permission in $permissionResult.results.value)
        {
            #((($permission.acesDictionary).psobject.Properties).Value)
            foreach ($descriptor in ((($permission.acesDictionary).psobject.Properties).Value))
            {  
                $_descriptor = $descriptor.descriptor
                #Write-Host "Processing Namespace: $($namespace.namespaceId) - $($namespace.displayName) - Token: $($permission.token)"
                #Write-Host "Descriptor: $($_descriptor)"
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
                    #Write-Host "Namespace: $($namespace.namespaceId) - $($namespace.displayName) - Token: $($permissionitem.friendlyToken) - $enumactions"
                }
            }
        }
    }
    $queue | Export-Csv -Path ".\Permissions.csv" -NoTypeInformation -Force