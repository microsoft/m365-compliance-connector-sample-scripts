param
(   
    [Parameter(mandatory = $true)]
    [string] $tenantId,
    [Parameter(mandatory = $true)]
    [string] $appId,
    [Parameter(mandatory = $true)]
    [string] $appSecret,
    [Parameter(mandatory = $true)]
    [string] $jobId,
    [Parameter(mandatory = $true)]
    [string] $filePath
)
# Access Token Config
$oAuthTokenEndpoint = "https://login.windows.net/$tenantId/oauth2/token"
$resource = 'https://microsoft.onmicrosoft.com/4e476d41-2395-42be-89ff-34cb9186a1ac'

# upload config
$eventApiURl = "https://webhook.ingestion.office.com"
$eventApiEndpoint = "api/signals"

function GetAccessToken () {
    # Token Authorization URI
    $uri = "$($oAuthTokenEndpoint)?api-version=1.0"

    # Access Token Body
    $formData = 
    @{
        client_id     = $appId;
        client_secret = $appSecret;
        grant_type    = 'client_credentials';
        resource      = $resource;
        tenant_id     = $tenantId;
    }

    # Parameters for Access Token call
    $params = 
    @{
        URI         = $uri
        Method      = 'Post'
        ContentType = 'application/x-www-form-urlencoded'
        Body        = $formData
    }

    $response = Invoke-RestMethod @params -ErrorAction Stop
    return $response.access_token
}

function RetryCommand {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Position = 1, Mandatory = $false)]
        [int]$Maximum = 15
    )

    Begin {
        $cnt = 0
    }

    Process {
        do {
            $cnt++
            try {
                $ScriptBlock.Invoke()
                return
            }
            catch {
                Write-Error $_.Exception.InnerException.Message -ErrorAction Continue
                Start-Sleep 60
                if ($cnt -lt $Maximum) {
                    Write-Output "Retrying"
                }
            }
            
        } while ($cnt -lt $Maximum)

        throw 'Execution failed.'
    }
}

function WriteErrorMessage($errorMessage) {
    $Exception = [Exception]::new($errorMessage)
    $ErrorRecord = [System.Management.Automation.ErrorRecord]::new(
        $Exception,
        "errorID",
        [System.Management.Automation.ErrorCategory]::NotSpecified,
        $TargetObject
    )
    $PSCmdlet.WriteError($ErrorRecord)
}

function UploadData ($access_token) {
    $nvCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty) 
    $nvCollection.Add('jobid', $jobId)
    $uriRequest = [System.UriBuilder]"$eventApiURl/$eventApiEndpoint"
    $uriRequest.Query = $nvCollection.ToString()

    $fieldName = 'file'
    $url = $uriRequest.Uri.OriginalString

    Add-Type -AssemblyName 'System.Net.Http'

    $client = New-Object System.Net.Http.HttpClient
    $content = New-Object System.Net.Http.MultipartFormDataContent
    try{
        $fileStream = [System.IO.File]::OpenRead($filePath)
        $fileName = [System.IO.Path]::GetFileName($filePath)
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
        $content.Add($fileContent, $fieldName, $fileName)
    }catch [System.IO.FileNotFoundException]{
        Write-Error("File not found. ")
        return
    }catch [System.IO.IOException]{
        Write-Error("File might be open")
        return
    }catch {
        Write-Error("Error reading from File")
        return
    }
    $client.DefaultRequestHeaders.Add("Authorization", "Bearer $access_token");
    $client.Timeout = New-Object System.TimeSpan(0, 0, 400)
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $result = $client.PostAsync($url, $content).Result
    }
    catch {
        WriteErrorMessage("Unknown failure while uploading.")
        return
    }
    $status_code = [int]$result.StatusCode
    if ($result.IsSuccessStatusCode) {
        Write-Output "Upload Successful"
        $responseStr = $result.Content.ReadAsStringAsync().Result
        if (! [string]::IsNullOrWhiteSpace($responseStr)) {
            Write-Output("Body : {0}" -f $responseStr)
        }
    }
    elseif ($status_code -eq 0 -or $status_code -eq 501 -or $status_code -eq 503) {
        throw "Service unavailable."
    }
    else {
        WriteErrorMessage("Failure with StatusCode [{0}] and ReasonPhrase [{1}]" -f $result.StatusCode, $result.ReasonPhrase)
        WriteErrorMessage("Error body : {0}" -f $result.Content.ReadAsStringAsync().Result)
    }
}

RetryCommand -ScriptBlock {
    $access_token = GetAccessToken
    UploadData($access_token)
}
