# Quick script for scanning all loaded modules on system
# It lists all processes and loaded modules, then submit hash to VirusTotal
# By gvl610 (https://github.com/raspiduino)

function getModulePaths {
    $filePaths = @()
    $modules = Get-Process -Module -ErrorAction Ignore
    foreach ($module in $modules) {
        $filePaths += ($module.FileName -replace "\\", "\\")
    }

    return $filePaths | select -Unique
}

$requestBody = "["
$hashMap = @{}

function addFileVT($path) {
    # Get file hash
    $hash = (Get-FileHash $path).Hash

    # Get file creation date time in the right format
    $creationDateTime = ([DateTime]((Get-Item $path).CreationTime)).ToString('yyyy/MM/dd HH:mm:ss')

    # Add hash and path to hashMap
    $hashMap[$hash] = $path

    # Request body
    return $requestBody + "{`"autostart_entry`":`"`",`"autostart_location`":`"`",`"creation_datetime`":`"" + $creationDateTime + "`",`"hash`":`"" + $hash + "`",`"image_path`":`"" + $path + "`"},"
}

function sendVT() {
    # Finalize the body
    $body = $requestBody.Substring(0, $requestBody.Length - 1) + "]"

    # Decrypt VT key (you may not want to know where it came from)
    $key = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("NGUzMjAyZmRiZTk1M2Q2MjhmNjUwMjI5YWY1YjNlYjQ5Y2Q0NmIyZDNiZmU1NTQ2YWUzYzVmYTQ4YjU1NGUwYw=="))

    # Send request
    $uri = 'https://www.virustotal.com/partners/sysinternals/file-reports?apikey=' + $key
    $response = Invoke-WebRequest -Uri $uri -Method Post -UserAgent "VirusTotal" -ContentType "application/json" -Body $body

    # Handle status code
    if ($response.StatusCode -eq 200) {
        return $response.Content
    } else {
        Write-Error "Unexpected response from VirusTotal: $($response.StatusCode)"
        return $null
    }
}

# Table holding VT results
$resultTable = New-Object System.Collections.Generic.List[System.Object]

function Add-DataItem($hash, $path, $positives, $total, $link) {
    # Create a new PSObject with properties
    $newItem = New-Object PSObject -Property @{
        hash = $hash
        path = $path
        positives = $positives
        total = $total
        link = $link
    }

    $resultTable.Add($newItem)
}

function parseVT($res) {
    # Split JSON string by comma
    $l = $res.Split(",")

    # Ignore if it's not found
    # TODO: Upload missing files
    $link = $l[2].Split("`"")[3]
    if ($link -eq $null) {
        return
    }

    # Parse some fields
    $hash = $l[0].split("`"")[3]
    $positives = [int]($l[3].Split("`"")[2].split(" ")[-1])
    $total = [int]($l[4].Split("`"")[2].split(" ")[-1])

    $path = $hashMap[$hash]
    Add-DataItem $hash $path $positives $total $link
}

# List modules
$paths = getModulePaths

# Iterate through each module
foreach ($path in $paths) {
    # Add to VT request body
    $requestBody = addFileVT($path)
}

# Actually send request to VT
$results = sendVT

# Split result string
$results = $results.split("[{")

# Iterate through each result
for ($i = 3; $i -lt ($results.Length - 3); $i++) {
    parseVT $results[$i]
}

# Sort result table by positives
$resultTable = $resultTable | Sort-Object { $_.positives }

# Print result
foreach ($result in $resultTable) {
    Write-Host "Hash: " $result.hash
    Write-Host "Path: " $result.path
    Write-Host "Positives: " $result.positives
    Write-Host "Total: " $result.total
    Write-Host "Link: " $result.link
    Write-Host "---"
}
