[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-Web-Download($url,$DownloadFolder)
{

    # obtain download location
    $download_filename = $url.Split("/")[-1]
    $download_path = "$DownloadFolder\$download_filename"

    # remove any previously downloaded fies
    if (test-path $download_path) {
        Remove-Item -Path $download_path -Force
    }

    # download the file
    write-host "Downloading $url" 
    $client = new-object System.Net.WebClient 
    $client.DownloadFile($url, $download_path) 

    # return the path to file
    return $download_path
}

function Expand-ZIPFile($file, $destination)
{
    $shell = new-object -com shell.application
    $zip = $shell.NameSpace($file)
    foreach($item in $zip.items())
    {
        $shell.Namespace($destination).copyhere($item)
    }
}

# remove previous downloads
if (test-path "$env:temp\master.zip") { Remove-Item "$env:temp\master.zip" -Force }
if (test-path "$env:temp\sigma-master") { Remove-Item "$env:temp\sigma-master" -Force -Recurse }
New-Item -ItemType Directory -Path "$env:temp\sigma-master"
Get-Web-Download -url "https://github.com/Neo23x0/sigma/archive/master.zip" -DownloadFolder "$env:temp"
Expand-ZIPFile -file "$env:temp\master.zip" -destination "$env:temp\sigma-master"

import-module powershell-yaml
# https://dist.nuget.org/win-x86-commandline/latest/nuget.exe
# install-package powershell-yaml
# https://github.com/cloudbase/powershell-yaml

$RulePath = "$env:temp\sigma-master\sigma-master\rules\*.yml"
$SavedSearchesPath = "C:\Development\TA-Sigma-Searches\default\savedsearches.conf"
$RuleSet = Get-ChildItem $RulePath -Filter "*.yml"  -Recurse

$PythonPath = "C:\Program Files (x86)\Python\Python35-32\python.exe"
$SigmacPath = "C:\Development\sigma-master\tools\sigmac.py"
$RulePath = "C:\Development\sigma-master\rules\windows\sysmon"
$env:PATHEXT += ";.py"

if (test-path $SavedSearchesPath) { remove-item $SavedSearchesPath -Force }

$SPL_critical = Out-Null
$SPL_high = Out-Null
$SPL_medium = Out-Null
$SPL_low = Out-Null

foreach ($Rule in $RuleSet)
{

    $SPL= & $PythonPath $SigmacPath -t splunk $($Rule.FullName)
    if (!($SPL))
    {
        continue
    }

    $RuleData = Get-Content $($Rule.FullName) -Raw

    $obj = ConvertFrom-Yaml $RuleData

    $product = $($obj.logsource.product)
    $service = $($obj.logsource.service)
    if (!($product)) { $product = "unknown" }
    if (!($service)) { $service = "unknown" }
    $prefix = "$product`:$service"

    $level = $($obj.level)
    if (!($level)) { $level = "unknown" }

    switch -Wildcard ($prefix)
    {
        windows:sysmon          {$SourceType="*WinEventLog:Microsoft-Windows-Sysmon/Operational"}
        windows:security        {$SourceType="*WinEventLog:Security"}
        windows:powershell      {$SourceType="*Microsoft-Windows-PowerShell/Operational"}
        windows:system          {$SourceType="*WinEventLog:System"}
        windows:application     {$SourceType="*WinEventLog:Application"}
        windows:taskscheduler   {$SourceType="*WinEventLog:Microsoft-Windows-TaskScheduler/Operational"}        
        default                 {$SourceType="*"}
    }

    $SPL = $SPL.Replace("EventID","EventCode")
    $SPL = "sourcetype=`"$SourceType`" $SPL"

    # append the critical multisearch
    if ($level -eq "critical") 
    {
        if (!($SPL_critical))
        {
            $SPL_critical = "($SPL)"
        }
        else
        {
            $SPL_critical = "$SPL_critical OR ($SPL)"
        }
    }

    # append the high multisearch
    if ($level -eq "high") 
    {
        if (!($SPL_high))
        {
            $SPL_high = "($SPL)"
        }
        else
        {
            $SPL_high = "$SPL_high OR ($SPL)"
        }
    }


    # append the medium multisearch
    if ($level -eq "medium") 
    {
        if (!($SPL_medium))
        {
            $SPL_medium = "($SPL)"
        }
        else
        {
            $SPL_medium = "$SPL_medium OR ($SPL)"
        }
    }

    # append the medium multisearch
    if ($level -eq "low") 
    {
        if (!($SPL_low))
        {
            $SPL_low = "($SPL)"
        }
        else
        {
            $SPL_low = "$SPL_low OR ($SPL)"
        }
    }

    $description = "$($obj.description). Author: $($obj.author)  Status: $($obj.status) Level: $($obj.level) FalsePositives: $($obj.falsepositives)"

    $section = @("
[$level`:$prefix - $($obj.title)]
search = $SPL
dispatch.earliest_time = -24h@h
description = $description")

    write-host $section
    $section | Out-File $SavedSearchesPath -Append
}

$section = @("
[All Critical Severity Signatures]
search = $SPL_critical
dispatch.earliest_time = -24h@h
description = combined search of critical severity signatures")
write-host $section
$section | Out-File $SavedSearchesPath -Append

$section = @("
[All High Severity Signatures]
search = $SPL_high
dispatch.earliest_time = -24h@h
description = combined search of high severity signatures")
write-host $section
$section | Out-File $SavedSearchesPath -Append

$section = @("
[All Medium Severity Signatures]
search = $SPL_medium
dispatch.earliest_time = -24h@h
description = combined search of medium severity signatures")
write-host $section
$section | Out-File $SavedSearchesPath -Append

$section = @("
[All Low Severity Signatures]
search = $SPL_low
dispatch.earliest_time = -24h@h
description = combined search of low severity signatures")
write-host $section
$section | Out-File $SavedSearchesPath -Append
