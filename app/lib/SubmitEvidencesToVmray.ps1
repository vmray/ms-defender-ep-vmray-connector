$folder_name = "vmray_quarantined_files";
$computer_name = $env:COMPUTERNAME;

function submit_sample_to_vmray {
    Write-Host "Submitting Samples to VMRAY";

    $folder = $env:TEMP+"\$folder_name";

    Get-ChildItem -Path $folder | ForEach-Object {
        Write-Host "Submitting $_"

        $file_path = "$folder\$_";

        $file_name = $_;

        # VMRay API URL
        $url = "https://eu.cloud.vmray.com/rest/sample/submit";

        # Configuration
        $API_KEY = "<VMRAY_API_KEY>";

        # Prepare headers
        $headers = @{"Authorization" = "api_key $API_KEY"};

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