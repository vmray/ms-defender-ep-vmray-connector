$folder_name = "vmray_quarantined_files";
$computer_name = $env:COMPUTERNAME;
$folder_exist = $env:TEMP + "\$folder_name";

# Configuration
$signedAuthorizationKey = "<SAS_TOKEN"

function check_if_folder_exist
{
    if (Test-Path -Path $folder_exist) {
        # Remove the folder and its contents
        Remove-Item -Path $folder_exist -Recurse -Force
        Write-Host "Folder $folder_exist has been deleted at the start of the script."
    } else {
        Write-Host "Folder $folder_exist does not exist."
    }
}

function restore_quarantined_files
{
    param(
        [string]$ArgValue
    )

    Write-Host "Restoring Quarantined Files";

    # Creating temp file to keep quarantined files
    $folder = $env:TEMP + "\$folder_name";
    New-Item -ItemType Directory -Path $folder;
    Add-MpPreference -ExclusionPath $folder;
    $threat_name_list=$ArgValue -split 'vmray'
    Write-Host "Threat name $threat_name_list";

    foreach($threat_name in  $threat_name_list)
    {
      ."C:\Program Files\Windows Defender\MpCmdRun.exe" -Restore -Name $threat_name -Path $folder;
    }

}




function remove_quarantined_files
{
    Write-Host "Removing Quarantined Files";

    # Removing quarantined files and folder
    $folder = $env:TEMP + "\$folder_name";
    Remove-MpPreference -ExclusionPath $folder;
    Remove-Item -LiteralPath $folder -Force -Recurse;
}

function submit_sample_to_ms_blob
{
    param(
        [string]$accountName,
        [string]$containerName,
        [string]$evidences
    )

    # Validate account name and signed key
    if (-not $accountName)
    {
        Write-Error "AccountName missing."
        return
    }

    # Path to the folder containing the files
    $folderPath = $env:TEMP + "\$folder_name";
    $files = Get-ChildItem -Path $folderPath
    if ($files.Count -gt 0)
    {
        Write-Host "QuarantinedFilesFound"
        Write-Host "Count $( $files.Count )"
    }
    $evidance_list = $evidences -split "vmray"
    Write-Host "evidence $evidance_list"

    foreach ($file in $files)
    {
        $blobName = $file.Name
        $filePath = Join-Path -Path $folderPath -ChildPath $blobName

            Upload-BlobToAzure -accountName $accountName -containerName $containerName -blobName $blobName -filePath $filePath

    }
}

function Upload-BlobToAzure
{
    param(
        [string]$accountName,
        [string]$containerName,
        [string]$blobName,
        [string]$filePath
    )

    Write-Host "Uploading $blobName to container $containerName..."

    # Generate the Blob URL
    $blobUrl = "https://$accountName.blob.core.windows.net/$containerName/$blobName$signedAuthorizationKey"
    Write-Host $blobUrl

    # Read file content
    $fileContent = [System.IO.File]::ReadAllBytes($filePath)

    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
    }

    # Upload the file using REST API
    try
    {
        Invoke-RestMethod -Uri $blobUrl -Method Put -Headers $headers -Body $fileContent -ContentType "application/octet-stream"
        Write-Host "Uploaded $blobName successfully."
    }
    catch
    {
        Write-Error "Failed to upload $blobName : $_"
    }
}

check_if_folder_exist
restore_quarantined_files -ArgValue $args[0]
submit_sample_to_ms_blob -accountName $args[1] -containerName $args[2] -evidences $args[3]
remove_quarantined_files

