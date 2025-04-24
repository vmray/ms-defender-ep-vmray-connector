# This script does not require concurrent execution.
# It runs sequentially, as it operates through a live response command,
# and only one live response can run at a time on the machine.

$folder_name = "vmray_quarantined_files";
$computer_name = $env:COMPUTERNAME;
$signedAuthorizationKey = "${SAS_TOKEN}"

$folder = Join-Path -Path $env:TEMP -ChildPath $folder_name;

function check_if_folder_exist
{
    if (Test-Path -Path $folder)
    {
        # Remove the folder and its contents
        Remove-Item -Path $folder -Recurse -Force
        Write-Host "Folder $folder has been deleted at the start of the script."
    }
    else
    {
        Write-Host "Folder $folder does not exist."
    }
}

function restore_quarantined_files
{
    param(
        [string]$ArgValue
    )
    Write-Host "Restoring Quarantined Files";

    New-Item -ItemType Directory -Path $folder;
    Add-MpPreference -ExclusionPath $folder;

    $maxRetries = 10
    $retries = 0
    $exclusionAdded = $false

    while ($retries -lt $maxRetries -and !$exclusionAdded)
    {
        # Pausing for 10 seconds to give Windows Defender time to set the exclusion properly.
        Write-Host "Sleeping for 10 sec";
        Start-Sleep -Seconds 10
        $currentExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath;

        if ($currentExclusions -contains $folder)
        {
            $exclusionAdded = $true
            Write-Host "Folder successfully added to exclusion list."
        }
        else
        {
            Write-Host "Waiting for the folder to be added to the exclusion list..."
            Start-Sleep -Seconds 1
            $retries++
        }
    }

    if (-not $exclusionAdded)
    {
        Write-Host "Failed to add folder to exclusion list after $maxRetries attempts. Exiting."
        return
    }

    $mpCmdPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"
    if (-not (Test-Path $mpCmdPath))
    {
        Write-Host "Windows Defender MpCmdRun.exe not found. Skipping file restoration."
        return
    }
    $threat_name_list = $ArgValue -split 'vmray'
    Write-Host "Threat names: $threat_name_list"

    foreach ($threat_name in $threat_name_list)
    {
      if ($threatName -ne "None")
        {
            Write-Host "Restoring quarantined file with name: $threatName"

            & "$mpCmdPath" -Restore -Name $threat_name -All -Path $folder
        }
        else
        {
            & "$mpCmdPath" -Restore -All -Path $folder;
        }
    }

}

function remove_quarantined_files
{
    Write-Host "Removing Quarantined Files";

    Remove-Item -LiteralPath $folder -Force -Recurse;
    Remove-MpPreference -ExclusionPath $folder;
}

function submit_sample_to_ms_blob
{
    param(
        [string]$accountName,
        [string]$containerName,
        [string]$evidences
    )

    if (-not $accountName)
    {
        Write-Error "AccountName missing."
        return
    }

    $files = Get-ChildItem -Path $folder
    if ($files.Count -gt 0)
    {
        Write-Host "QuarantinedFilesFound"
        Write-Host "Count $( $files.Count )"
    }
    else
    {
        Write-Host "No Quarantined Files Found"
        return
    }
    $evidence_list = $evidences -split "vmray"
    Write-Host "evidence $evidence_list"

    $processedHashes = @{ }

    foreach ($file in $files)
    {
        $blobName = $file.Name
        $filePath = Join-Path -Path $folder -ChildPath $blobName

        try
        {
            $file_hash = (certutil -hashfile $filePath SHA256 | Select-Object -Skip 1 | Select-Object -First 1).Trim().ToLower()
            Write-Host "File Hash $file_hash"
        }
        catch
        {
            Write-Error "Error calculating hash for file $filePath. Skipping..."
            continue
        }

        if ( $processedHashes.ContainsKey($file_hash))
        {
            Write-Host "File with hash $file_hash already processed. Skipping..."
            continue
        }

        if ($file_hash -and ($file_hash -in $evidence_list))
        {
            $processedHashes[$file_hash] = $true
            Upload-BlobToAzure -accountName $accountName -containerName $containerName -blobName $blobName -filePath $filePath
        }
        else
        {
            Write-Host "File $filePath does not match any evidence hash. Skipping upload."
        }
    }
    if (($files.Count -gt 0) -and ($processedHashes.Keys.Count -eq 0))
    {
        Write-Host "NoMatchFound"
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
    $blobUrl = "https://$accountName.blob.core.windows.net/$containerName/$blobName$signedAuthorizationKey"

    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
    }
    try
    {
    	$fileContent = [System.IO.File]::ReadAllBytes($filePath)
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