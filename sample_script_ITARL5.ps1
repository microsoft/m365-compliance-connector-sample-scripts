# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# 
# Sample Script to Push Data to M365 Compliance Connector 
# Examples
#
# Push data to M365 Compliance Connector:
# .\sample_script.ps1 -tenantId <Guid> -appId <App Id> -appSecret <App Secret> -jobId <Job id GUID> -filePath <File Path> -Verbose
<#
    .SYNOPSIS
        Sample Script to push Data to M365 Compliance Connector. Script Takes an Input file, chunks it to predefined size and does the data push
    .DESCRIPTION
        Take Input File. Use the metadata for checkpointing and then compute start point.
        Metadata has attributes corresponding to the last row for the file that was successfully sent. 
        If no metadata exists, create new metadata and start processing from start of File.
        If metadata exists start processing from point of last successful push.
        Create Temporary File Chunks of specified Line Count.
        Then fetch the access token and using the HttpClient generate a POST request
    .PARAMETER TenantId
        This is the Id for your Microsoft 365 organization. 
        This is used to identify your organization.
    .PARAMETER APPID
        This is the Azure AD application Id for the app that you created in Azure AD. 
        This is used by Azure AD for authentication when the script attempts to accesses your Microsoft 365 organization.
    .PARAMETER APPSECRET
        This is the Azure AD application secret for the app that you created in Azure AD. This also used for authentication.
    .PARAMETER JOBID
        The JobId retreived while setting up the Connector
    .PARAMETER FilePath
        This is the file path for the CSV file. Try to avoid spaces in the file path; otherwise use single quotation marks.
    .PARAMETER RecordsPerCall
        This is the chunk size to be used.
#>
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
    [string] $FilePath,
    [Parameter(mandatory = $false)]
    [Int] $RecordsPerCall = 50000,
    [Parameter(mandatory = $false)]
    [Int] $retryTimeout = 60
)
# Access Token Config
$oAuthTokenEndpoint = "https://login.microsoftonline.us/$tenantId/oauth2/token"
$resource = 'https://microsoft.onmicrosoft.com/86dfdabb-5089-4a0c-880a-cfa5a790c5b1'

# Csv upload config
$eventApiURl = "https://webhook-itarl5.ingestion.apps.mil"
$eventApiEndpoint = "api/signals"

$serviceName = "PushConnector"
$TmpDirName = $env:TEMP + "ctr###D"

class FileMetdata {
    [string]$FileHash
    [string]$NoOfRowsWritten
    [string]$Service
    [string]$LastModTime
}

function Get-AccessToken () {
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
                Write-Verbose("Will retry in [{0}] seconds" -f $retryTimeout)
                Start-Sleep $retryTimeout
                if ($cnt -lt $Maximum) {
                    Write-Output "Retrying"
                }
            }
            
        } while ($cnt -lt $Maximum)

        throw 'Execution failed.'
    }
}

function Write-ErrorMessage($errorMessage) {
    $Exception = [Exception]::new($errorMessage)
    $ErrorRecord = [System.Management.Automation.ErrorRecord]::new(
        $Exception,
        "errorID",
        [System.Management.Automation.ErrorCategory]::NotSpecified,
        $TargetObject
    )
    $PSCmdlet.WriteError($ErrorRecord)
}

function Push-Data ($access_token, $FileName) {
    $nvCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty) 
    $nvCollection.Add('jobid', $jobId)
    $uriRequest = [System.UriBuilder]"$eventApiURl/$eventApiEndpoint"
    $uriRequest.Query = $nvCollection.ToString()

    $fieldName = 'file'
    $url = $uriRequest.Uri.OriginalString

    Add-Type -AssemblyName 'System.Net.Http'

    $client = New-Object System.Net.Http.HttpClient
    $content = New-Object System.Net.Http.MultipartFormDataContent
	
    try {
		
        $fileStream = [System.IO.File]::OpenRead($FileName)
        $fileName = [System.IO.Path]::GetFileName($FileName)
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
        $content.Add($fileContent, $fieldName, $fileName)
		
    }
    catch [System.IO.FileNotFoundException] {
        Write-Error("Csv file not found. ")
        return
    }
    catch [System.IO.IOException] {
        Write-Error("Csv file might be open")
        return
    }
    catch {
        Write-Error("Error reading from csv file")
        return
    }
	
    $client.DefaultRequestHeaders.Add("Authorization", "Bearer $access_token");
    $client.Timeout = New-Object System.TimeSpan(0, 0, 400)
    
    try {

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $result = $client.PostAsync($url, $content).Result
    }
    catch {
        Write-ErrorMessage("Unknown failure while uploading.")
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
        $errorstring = "Failure with StatusCode [{0}] and ReasonPhrase [{1}]" -f $result.StatusCode, $result.ReasonPhrase
        Write-ErrorMessage($errorstring)
        Write-ErrorMessage("Error body : {0}" -f $result.Content.ReadAsStringAsync().Result)
        throw $errorstring
    }
}

function GetOrCreateMetadata($FileName) {
    # Handle Obsolete Metadata
    HandleObsoleteMetadata
    $fileHash = ComputeHashForInputFile($FileName)
    $metaDataFileName = GetMetaDataFileName($fileHash)
    if ([System.IO.File]::Exists($metaDataFileName)) {
        # GET metadata from file
        $metadata = [FileMetdata](Get-Content $metaDataFileName | Out-String | ConvertFrom-Json)
        if ($metadata.FileHash -eq $fileHash) {
            #return Appropriate Metadata
            return $metadata
        }
    }
    
    $newmetadata = [FileMetdata]::new()
    $newmetadata.FileHash = $fileHash
    $newmetadata.NoOfRowsWritten = 0
    $newmetadata.LastModTime = Get-Date -format "yyyy-MM-ddTHH:mm:ss"
    $newmetadata.Service = $serviceName
    return $newmetadata
}

function GetMetaDataFileName($FileHash) {
    return $TmpDirName + "\." + $FileHash + "####mdata.txt"
}

function UpdateMetadata($FileName, $noOfRowsWritten) {
    # Update metadata
    $filemetaData = [FileMetdata]::new()
    $fileHash = ComputeHashForInputFile($FileName)
    $filemetaData.FileHash = $fileHash
    $filemetaData.Service = $serviceName
    $filemetaData.NoOfRowsWritten = $noOfRowsWritten
    $filemetaData.LastModTime = Get-Date -format "yyyy-MM-ddTHH:mm:ss"
    $metaDataFilePath = GetMetaDataFileName($fileHash)
    $filemetaData | ConvertTo-Json -Depth 100 | Out-File $metaDataFilePath
}

function HandleObsoleteMetadata() {
    # Delete metadata which are over 14 days old
    $timeLimit = (Get-Date).AddDays(-14)
    $filePath = $TmpDirName
    Get-ChildItem -Path $filePath -Recurse -Force | 
    Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -lt $timeLimit } | 
    Where-Object { $_.Name -match '^.+\####mdata.txt$' } | 
    Remove-Item -Force
}


function ComputeHashForInputFile($FileName) {
    $stream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($stream)
    $date = ([datetime](Get-ItemProperty -Path $FileName -Name LastWriteTime).lastwritetime).ToString("yyyy-MM-ddTHH:mm:ss")
    $writer.write($FileName + $date)
    $writer.Flush()
    $stream.Position = 0
    $filemetaData = Get-FileHash -InputStream $stream | Select-Object Hash
    $stream.Dispose()
    $writer.Dispose()
    return $filemetaData
}

<#
    .SYNOPSIS
        Checks for existing file metadata. Computes start point and then chunks file into specified size and send
    .DESCRIPTION
        Checks for existing file metadata. Metadata has attributes corresponding to the last row for the file that was successfully sent. 
        Use the metadata for checkpointing and then compute start point. 
        Chunks file into specified size and send
    .PARAMETER FileName
        The File to be used for consumption and pushing Data
    .PARAMETER LinesPerFile
        Defines the Chunk Size
#>
function Send-ChunkedData($FileName, $linesperFile) {

    if ( !(Test-Path $TmpDirName -PathType Container)) {
        New-Item -ItemType directory -Path $TmpDirName
    }

    $TmpFileName = "\tmp" + "_" + [guid]::NewGuid().ToString()
    $ext = ".txt"
    $filecount = 1
    $reader = $null
  
    try {
        $reader = [io.file]::OpenText($Filename)
        # Create/Get Metadata
        $metaData = GetOrCreateMetadata($FileName)

        try {        
            $header = $reader.ReadLine();
            $activeLineCount = 0

            # Skip no of rows already written as per metadata
            while ($activeLineCount -lt $metaData.NoOfRowsWritten -and $reader.EndOfStream -ne $true) {
                $reader.ReadLine() | Out-Null
                $activeLineCount++
            }
            
            Write-Verbose "Rows already ingested from File Count: $activeLineCount"
            
            while ($reader.EndOfStream -ne $true) {              
                $linecount = 0
                $NewFile = "{0}{1}{2}{3}" -f ($TmpDirName, $TmpFileName, $filecount.ToString("0000"), $ext)
                Write-Verbose "Creating file $NewFile"
                $writer = [io.file]::CreateText($NewFile)
                $filecount++
                
                #"Adding header"
                $writer.WriteLine($header);

                #"Reading $linesperFile"
                while ( ($linecount -lt $linesperFile) -and ($reader.EndOfStream -ne $true)) {
                    $writer.WriteLine($reader.ReadLine());
                    $linecount++
                }

                # Update the active Linecount to be persisted in eventual metadata
                $activeLineCount = $activeLineCount + $linecount
                #"Closing file"
                $writer.Dispose();

                Write-Verbose "Created file with $linecount records"
                RetryCommand -ScriptBlock {
                    param($fileName)
                    $access_token = Get-AccessToken
                    Push-Data($access_token, $fileName) $NewFile
                }
                
                # Update metadata
                UpdateMetadata $FileName $activeLineCount
   
                Write-Verbose "Deleting file $NewFile"
                Remove-Item $NewFile
            }
        }
        finally {     
            if ($null -ne $writer) {
                $writer.Dispose();
            }
        }
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose();
        }
    }
}

Send-ChunkedData $FilePath $RecordsPerCall