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

    switch -Wildcard ($obj.logsource.service)
    {
        sysmon*    {$SourceType="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"}
        default     {$SourceType="*"}
    }

    $SPL = $SPL.Replace("EventID","EventCode")

    $product = $($obj.logsource.product)
    $service = $($obj.logsource.service)
    if (!($product)) { $product = "unknown" }
    if (!($service)) { $service = "unknown" }
    $prefix = "$product`:$service"

    $description = "$($obj.description). Author: $($obj.author)  Status: $($obj.status) Level: $($obj.level) FalsePositives: $($obj.falsepositives)"

    $section = @("
[$prefix - $($obj.title)]
search = sourcetype=`"$SourceType`" $SPL
dispatch.earliest_time = -24h
description = $description")

    write-host $section
    $section | Out-File $SavedSearchesPath -Append
}

