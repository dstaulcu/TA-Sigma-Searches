import-module powershell-yaml
# https://dist.nuget.org/win-x86-commandline/latest/nuget.exe
# install-package powershell-yaml
# https://github.com/cloudbase/powershell-yaml

$RulePath = "C:\Development\sigma-master\rules\*.yml"
$SavedSearchesPath = "C:\Development\TA-Sigma-Searches\default\savedsearches.conf"
$RuleSet = Get-ChildItem $RulePath -Filter "*.yml"  -Recurse

$PythonPath = "C:\Program Files (x86)\Python\Python35-32\python.exe"
$SigmacPath = "C:\Development\sigma-master\tools\sigmac.py"
$RulePath = "C:\Development\sigma-master\rules\windows\sysmon"
$env:PATHEXT += ";.py"

if (test-path $SavedSearchesPath) { remove-item $SavedSearchesPath -Force }


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

    switch -Wildcard ($prefix)
    {
        windows:sysmon          {$SourceType="*WinEventLog:Microsoft-Windows-Sysmon/Operational"}
        windows:security        {$SourceType="*WinEventLog:Security"}
        windows:powershell      {$SourceType="*Microsoft-Windows-PowerShell/Operational"}
        windows:system          {$SourceType="*WinEventLog:System"}
        windows:application     {$SourceType="*WinEventLog:Application"}
        windows:taskscheduler   {$SourceType="*WinEventLog:Microsoft-Windows-TaskScheduler/Operational"}
        #linux:unknown        
        #linux:modsecurity    
        #linux:clamav         
        #linux:syslog         
        #apache:unknown             
        default                 {$SourceType="*"}
    }

    $SPL = $SPL.Replace("EventID","EventCode")

    $description = "$($obj.description). Author: $($obj.author)  Status: $($obj.status) Level: $($obj.level) FalsePositives: $($obj.falsepositives)"

    $section = @("
[$prefix`:$($obj.level) - $($obj.title)]
search = sourcetype=`"$SourceType`" $SPL
dispatch.earliest_time = -24h
description = $description")

    write-host $section
    $section | Out-File $SavedSearchesPath -Append
}

