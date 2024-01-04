$folder_name = "vmray_quarantined_files";
$computer_name = $env:COMPUTERNAME;

# Configuration
$API_KEY = "<VMRAY_API_KEY>";

# Enable or disable resubmission
$RESUBMIT = $false;

# Prepare headers
$headers = @{"Authorization" = "api_key $API_KEY"};

function check_sample_exists_in_vmray {
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $hash
    )

    # VMRay API URL
    $url = "https://eu.cloud.vmray.com/rest/sample/sha256/" + $hash;

    Write-Host "Checking $hash";

    try {
        $response = Invoke-RestMethod -UserAgent $USER_AGENT -Uri $url -Method Get -Headers $headers;

        if ($response.result -eq "ok"){
            if ($response.data.Length -ne 0){
                Write-Host "Sample $hash already submitted to VMRAY";
                return $true;
            }
        }
    }
    catch {
        Write-Error "Error occurred: $_";
    }

    return $false;
}

function submit_sample_to_vmray {
    # VMRay API URL
    $url = "https://eu.cloud.vmray.com/rest/sample/submit";

    Write-Host "Submitting Samples to VMRAY";

    $folder = $env:TEMP+"\$folder_name";

    Get-ChildItem -Path $folder | ForEach-Object {

        $file_name = $_;

        $file_path = "$folder\$_";

        $file_hash = $(Get-FileHash -Path $file_path -Algorithm SHA256).Hash;

        $already_submitted = check_sample_exists_in_vmray($file_hash);
           
        if (-not $already_submitted)
        {
            Write-Host "Submitting $file_name";

            $boundary = [System.Guid]::NewGuid().ToString();
            $file_content = [System.IO.File]::ReadAllBytes($file_path);
            $file_content_encoded = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString($file_content);

            $LF = "`r`n";
            $bodyLines = (
                "--$boundary",
                "Content-Disposition: form-data; name=`"tags`"$LF",
                "MicrosoftDefenferForEndpoint,SubmittedFromEndpoint",
                "--$boundary",
                "Content-Disposition: form-data; name=`"comment`"$LF",
                "Sample from VMRay Analyzer - Microsoft Defender for Endpoint Connector, ComputerName:$computer_name",
                "--$boundary",
                "Content-Disposition: form-data; name=`"user_config`"$LF",
                "{`"timeout`":120}",
                "--$boundary",
                "Content-Disposition: form-data; name=`"sample_file`"; filename=`"$file_name`"",
                "Content-Type: application/octet-stream$LF",
                $file_content_encoded,
                "--$boundary--$LF"
            ) -join $LF;

            try {

                $response = Invoke-RestMethod -UserAgent $USER_AGENT -Uri $url -Method Post -Headers $headers -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines;

                # Check response and handle accordingly
                if ($response.result -eq "ok") {
                    Write-Output "Sample submitted successfully.";
                } else {
                    Write-Error "Failed to submit sample: $($response.error_msg)";
                }
            }
            catch {
                Write-Error "Error occurred: $_";
            }
        }
        
        else {
            
            if ($RESUBMIT){
            
                Write-Host "Resubmitting $file_name";

                $boundary = [System.Guid]::NewGuid().ToString();
                $file_content = [System.IO.File]::ReadAllBytes($file_path);
                $file_content_encoded = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString($file_content);

                $LF = "`r`n";
                $bodyLines = (
                    "--$boundary",
                    "Content-Disposition: form-data; name=`"tags`"$LF",
                    "MicrosoftDefenferForEndpoint,SubmittedFromEndpoint",
                    "--$boundary",
                    "Content-Disposition: form-data; name=`"comment`"$LF",
                    "Sample from VMRay Analyzer - Microsoft Defender for Endpoint Connector, ComputerName:$computer_name",
                    "--$boundary",
                    "Content-Disposition: form-data; name=`"user_config`"$LF",
                    "{`"timeout`":120}",
                    "--$boundary",
                    "Content-Disposition: form-data; name=`"sample_file`"; filename=`"$file_name`"",
                    "Content-Type: application/octet-stream$LF",
                    $file_content_encoded,
                    "--$boundary--$LF"
                ) -join $LF;

                try {

                    $response = Invoke-RestMethod -UserAgent $USER_AGENT -Uri $url -Method Post -Headers $headers -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines;

                    # Check response and handle accordingly
                    if ($response.result -eq "ok") {
                        Write-Output "Sample resubmitted successfully.";
                    } else {
                        Write-Error "Failed to resubmit sample: $($response.error_msg)";
                    }
                }
                catch {
                    Write-Error "Error occurred: $_";
                }
            }
        }
    }
}

function restore_quarantined_files {
    Write-Host "Restoring Quarantined Files";

    # Creating temp file to keep quarantined files
    $folder = $env:TEMP+"\$folder_name";
    New-Item -ItemType Directory -Path $folder;

    # Restoring quarantined files
    ."C:\Program Files\Windows Defender\MpCmdRun.exe" -Restore -All -Path $folder;
}

function remove_quarantined_files {
    Write-Host "Removing Quarantined Files";

    # Removing quarantined files and folder
    $folder = $env:TEMP+"\$folder_name";
    Remove-Item -LiteralPath $folder -Force -Recurse;
}

restore_quarantined_files
submit_sample_to_vmray
remove_quarantined_files