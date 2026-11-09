<#
Core category/tag creation only. No inventory assignments or DRS operations.
Plan is read-only. Apply creates missing definitions. Verify is read-only.
Existing category scope/cardinality mismatches block Apply; never auto-corrected.
Version 1.1: VCF SSO API token authentication is the default.
Requires PowerShell 7 and VCF PowerCLI with Connect-VIServer -VcfApiToken support.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$VCenter,
 [ValidateSet('VcfApiToken','Credential')][string]$AuthMode='VcfApiToken',
 [System.Security.SecureString]$ApiToken,
 [string]$IdentityBrokerHostname,
 [string]$Tenant,
 [string]$CsvPath = (Join-Path $PSScriptRoot 'core-tags-creation.csv'),
 [ValidateSet('Plan','Apply','Verify')][string]$Mode='Plan',
 [string]$ReportPath=(Join-Path $PSScriptRoot ('CoreTags-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff')+'.csv'))
)
$ErrorActionPreference='Stop'
Import-Module VMware.VimAutomation.Core -ErrorAction Stop
function Normalize-Types($Types) {
 $result=@(foreach($t in $Types) {
  switch -Regex ($t.ToString()) {
   '^(All|\*)$' {'All';break}
   '^(VMHost|HostSystem|Host|urn:vim25:HostSystem)$' {'VMHost';break}
   '^(VM|VirtualMachine|urn:vim25:VirtualMachine)$' {'VirtualMachine';break}
   '^(DistributedPortGroup|DistributedVirtualPortgroup|urn:vim25:DistributedVirtualPortgroup)$' {'DistributedPortGroup';break}
   '^(DatastoreCluster|StoragePod|urn:vim25:StoragePod)$' {'DatastoreCluster';break}
   '^(Datastore|urn:vim25:Datastore)$' {'Datastore';break}
   '^(Network|urn:vim25:Network)$' {'Network';break}
   default {$t.ToString()}
  }
 })
 if($result.Count -eq 0 -or $result -contains 'All'){return 'All'}
 return (($result | Sort-Object -Unique) -join ';')
}
$rows=@(Import-Csv -LiteralPath $CsvPath)
if(!$rows.Count){throw 'CSV has no rows.'}
foreach($col in 'Category','TagName','ObjectTypes','Cardinality','Create') {
 if($rows[0].PSObject.Properties.Name -notcontains $col){throw "Missing CSV column: $col"}
}
$keys=@{}
foreach($r in $rows){
 if($r.Category -notmatch '^core\.infra-' -or [string]::IsNullOrWhiteSpace($r.TagName)){throw 'Only nonempty core.infra- category/tag rows are permitted.'}
 if($r.Cardinality -ne 'Single'){throw "Core category must be Single: $($r.Category)"}
 if($r.Create -notin @('true','false')){throw "Create must be true or false: $($r.Category)/$($r.TagName)"}
 if($r.TagName -in @('customer-defined','values-deferred','build-id-required','vmware-virtual-appliance','vendor-virtual-appliance')){throw "Prohibited placeholder: $($r.TagName)"}
 $key=$r.Category+'|'+$r.TagName
 if($keys.ContainsKey($key)){throw "Duplicate category/tag row: $key"};$keys[$key]=$true
 if($r.ObjectTypes -notin @('All','VMHost;VirtualMachine','Network;DistributedPortGroup','Datastore;DatastoreCluster')){throw "Unexpected scope: $($r.ObjectTypes)"}
}
$groups=@($rows | Group-Object Category)
foreach($g in $groups){
 if(@($g.Group.ObjectTypes | Select-Object -Unique).Count -ne 1 -or @($g.Group.Cardinality | Select-Object -Unique).Count -ne 1){throw "Inconsistent category definition: $($g.Name)"}
}
# Validate authentication capabilities before requesting any secret.
$connectCommand=Get-Command Connect-VIServer -ErrorAction Stop
if($AuthMode -eq 'Credential' -and ($ApiToken -or $IdentityBrokerHostname -or $Tenant)){
 throw 'ApiToken, IdentityBrokerHostname and Tenant apply only to VcfApiToken authentication.'
}
if($Tenant -and !$IdentityBrokerHostname){throw 'Tenant requires IdentityBrokerHostname.'}
if($AuthMode -eq 'VcfApiToken'){
 if($IdentityBrokerHostname){
  Import-Module VMware.Vcf.Sso -ErrorAction Stop
  if(!$connectCommand.Parameters.ContainsKey('VcfOAuthSecurityContext')){
   throw 'Installed PowerCLI lacks VcfOAuthSecurityContext. Install a compatible VCF PowerCLI 9.1 release.'
  }
  Get-Command New-VcfOAuthSecurityContext -ErrorAction Stop | Out-Null
 }elseif(!$connectCommand.Parameters.ContainsKey('VcfApiToken')){
  throw 'Installed PowerCLI lacks VcfApiToken. Install a compatible VCF PowerCLI 9.1 release.'
 }
}
$cred=$null
$oauthContext=$null
$ownsToken=$false
$vc=$null
$report=[System.Collections.Generic.List[object]]::new()
function Record($Kind,$Category,$Tag,$Status,$Detail){
 $report.Add([pscustomobject]@{Timestamp=(Get-Date).ToString('s');VCenter=$VCenter;Mode=$Mode;Kind=$Kind;Category=$Category;TagName=$Tag;Status=$Status;Detail=$Detail})
}
try {
 # Authentication failures are sanitized so provider errors cannot enter the report.
 try {
  if($AuthMode -eq 'VcfApiToken'){
   if(!$ApiToken){
    $ApiToken=Read-Host 'Paste VCF SSO API token (input hidden)' -AsSecureString
    $ownsToken=$true
   }
   if($ApiToken.Length -eq 0){throw 'Empty API token.'}
   if($IdentityBrokerHostname){
    $oauthParams=@{IdentityBrokerHostname=$IdentityBrokerHostname;ApiToken=$ApiToken;ErrorAction='Stop'}
    if($Tenant){$oauthParams.Tenant=$Tenant}
    $oauthContext=New-VcfOAuthSecurityContext @oauthParams
    $vc=Connect-VIServer -Server $VCenter -VcfOAuthSecurityContext $oauthContext -NotDefault -ErrorAction Stop
   }else{
    $vc=Connect-VIServer -Server $VCenter -VcfApiToken $ApiToken -NotDefault -ErrorAction Stop
   }
  }else{
   $cred=Get-Credential -Message "Connect only to target vCenter: $VCenter"
   $vc=Connect-VIServer -Server $VCenter -Credential $cred -NotDefault -ErrorAction Stop
  }
 }catch{
  throw 'Authentication failed. Check token expiry/revocation, VCF SSO domain federation, client role scope, DNS, TLS trust and PowerCLI compatibility. No automatic credential fallback was attempted.'
 }
 Record Authentication '' '' Connected "Authentication mode: $AuthMode. No secret recorded."
 # Read every existing category first. No changes until the entire preflight passes.
 $existing=@(Get-TagCategory -Server $vc -ErrorAction Stop)
 $cache=@{};$conflicts=[System.Collections.Generic.List[string]]::new()
 foreach($g in $groups){
  $r=$g.Group[0];$matches=@($existing | Where-Object Name -eq $g.Name)
  if($matches.Count -gt 1){throw "Ambiguous category: $($g.Name)"}
  if($matches.Count){
   $c=$matches[0];$cache[$g.Name]=$c
   $actual=Normalize-Types $c.EntityType
   $desired=Normalize-Types ($r.ObjectTypes -split ';')
   if($c.Cardinality.ToString() -ne $r.Cardinality -or $actual -ne $desired){
    $msg="Expected $($r.Cardinality)/$desired; found $($c.Cardinality)/$actual. No automatic change."
    $conflicts.Add($g.Name+': '+$msg);Record Category $g.Name '' Conflict $msg
   }else{Record Category $g.Name '' Match "Single; $desired"}
  }else{Record Category $g.Name '' Missing "Expected Single; $($r.ObjectTypes)"}
 }
 if($Mode -eq 'Apply' -and $conflicts.Count){throw ('Category conflicts block all creation: '+($conflicts -join ' | '))}
 foreach($g in $groups){
  $r=$g.Group[0];$c=$cache[$g.Name]
  if(!$c -and $Mode -eq 'Apply'){
   $c=New-TagCategory -Name $g.Name -Cardinality Single -EntityType ($r.ObjectTypes -split ';') -Description $r.CategoryDescription -Server $vc -ErrorAction Stop
   $cache[$g.Name]=$c;Record Category $g.Name '' Created $r.ObjectTypes
  }
  $tags=if($c){@(Get-Tag -Category $c -Server $vc -ErrorAction Stop)}else{@()}
  foreach($r in $g.Group){
   if($r.Create -eq 'false'){Record Tag $r.Category $r.TagName Disabled $r.CreationNotes;continue}
   $t=@($tags | Where-Object Name -eq $r.TagName)
   if($t.Count -gt 1){throw "Ambiguous tag: $($r.Category)/$($r.TagName)"}
   if($t.Count){Record Tag $r.Category $r.TagName Exists 'Existing tag retained; description not overwritten.'}
   elseif($Mode -eq 'Apply'){
    New-Tag -Name $r.TagName -Category $c -Description $r.TagDescription -Server $vc -ErrorAction Stop | Out-Null
    Record Tag $r.Category $r.TagName Created 'Definition only; no assignment.'
   }else{Record Tag $r.Category $r.TagName Missing 'Definition not found; read-only mode.'}
  }
 }
 if($Mode -eq 'Apply'){
  foreach($g in $groups){
   $c=@(Get-TagCategory -Server $vc -ErrorAction Stop | Where-Object Name -eq $g.Name)
   if($c.Count -ne 1 -or $c[0].Cardinality.ToString() -ne 'Single' -or (Normalize-Types $c[0].EntityType) -ne (Normalize-Types ($g.Group[0].ObjectTypes -split ';'))){throw "Post-creation category verification failed: $($g.Name)"}
   $actualTags=@(Get-Tag -Category $c[0] -Server $vc -ErrorAction Stop)
   foreach($r in @($g.Group | Where-Object Create -eq 'true')){
    if(@($actualTags | Where-Object Name -eq $r.TagName).Count -ne 1){throw "Post-creation tag verification failed: $($r.Category)/$($r.TagName)"}
   }
   Record Verification $g.Name '' Passed 'Enabled tags, cardinality, and object scope confirmed.'
  }
 }
 if($Mode -eq 'Verify' -and @($report | Where-Object {$_.Status -in @('Missing','Conflict')}).Count){throw 'Verification incomplete: missing definitions or category conflicts. Review report.'}
 Write-Host "$Mode completed. No inventory tag assignments or DRS changes were performed."
}catch{
 Record Execution '' '' Error $_.Exception.Message
 throw
}finally{
 $report | Export-Csv -LiteralPath $ReportPath -NoTypeInformation -Encoding utf8
 Write-Host "Report: $ReportPath"
 if($vc){Disconnect-VIServer -Server $vc -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}
 $cred=$null
 $oauthContext=$null
 if($ownsToken -and $ApiToken){$ApiToken.Dispose()}
 $ApiToken=$null
}
