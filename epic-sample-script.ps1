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
    [Int] $RecordsPerCall = 50000
)
# Access Token Config
$oAuthTokenEndpoint = "https://login.windows.net/$tenantId/oauth2/token"
$resource = 'https://microsoft.onmicrosoft.com/4e476d41-2395-42be-89ff-34cb9186a1ac'

# Csv upload config
$eventApiURl = "https://webhook.ingestion.office.com"
$eventApiEndpoint = "api/signals"

$serviceName = "PushConnector"

class FileMetdata {
    [string]$FileHash
    [string]$NoOfRowsWritten
    [string]$Service
}

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

function UploadData ($access_token, $FileName) {
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

function GetOrCreateMetadata($FileName) {
    $fileHash = ComputeHashForInputFile($FileName)
    $metaDataFileName = [System.IO.Path]::GetDirectoryName($FileName) + "\." + [System.IO.Path]::GetFileNameWithoutExtension($FileName) + "####mdata.txt"
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
    $newmetadata.Service = $serviceName
    return $newmetadata
}

function UpdateMetadata($FileName, $noOfRowsWritten) {
    # Update metadata
    $filemetaData = [FileMetdata]::new()
    $filemetaData.FileHash = ComputeHashForInputFile($FileName)
    $filemetaData.Service = $serviceName
    $filemetaData.NoOfRowsWritten = $noOfRowsWritten
    $metaDataFilePath = GetMetadataFilePath $FileName
    $filemetaData | ConvertTo-Json -Depth 100 | Out-File $metaDataFilePath
}

function HandleObseleteMetadata($FileName) {
    # Delete metadata which are over 30 days old
    $timeLimit = (Get-Date).AddDays(-30)
    $filePath = [System.IO.Path]::GetDirectoryName($FileName)
    Get-ChildItem -Path $filePath -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -lt $timeLimit } | Where-Object { $_.Name -match '^.+\####mdata.txt$' } | Remove-Item -Force
}

function GetMetadataFilePath($FileName) {
    return [System.IO.Path]::GetDirectoryName($FileName) + "\." + [System.IO.Path]::GetFileNameWithoutExtension($FileName) + "####mdata.txt"
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

function ChunkAndSend($FileName, $linesperFile) {
    $DirName = [System.IO.Path]::GetDirectoryName($FileName)
    $TmpFileName = "\tmp"
    $ext = ".txt"
    #$linesperFile = 10#100k
    $filecount = 1
    $reader = $null
  
    try {
        $reader = [io.file]::OpenText($Filename)
        # Handle Obselete Metadata
        HandleObseleteMetadata($FileName)
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
            
            while ($reader.EndOfStream -ne $true) {              
                $linecount = 0
                $NewFile = "{0}{1}{2}{3}" -f ($DirName, $TmpFileName, $filecount.ToString("0000"), $ext)
                "Creating file $NewFile"
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

                "Created file with $linecount records"
                RetryCommand -ScriptBlock {
                    param($fileName)
                    $access_token = GetAccessToken
                    UploadData($access_token, $fileName) $NewFile
                }
   
                "Deleting file $NewFile"
                Remove-Item $NewFile
            }
        }
        finally {
            # Update metadata 
            UpdateMetadata $FileName $activeLineCount            
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

ChunkAndSend $FilePath $RecordsPerCall