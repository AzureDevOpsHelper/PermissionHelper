
function Get-MSALToken 
{
    try
    {
        Write-Host "AZ login will open a modal identity picker in the top left of the screen, please choose the account you want to use."
        Write-Host "It may take a few seconds to load, please be patient."  
        Write-Host "It will then ask you to pick a subscription, please choose a subscription that is associated with the tenant that backs your org."
        Connect-AzAccount 
        $result = Get-AzAccessToken -ResourceUrl '499b84ac-1321-427f-aa17-267ca6975798'
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



$token = Get-MSALToken

