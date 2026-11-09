#requires -Version 7.4
<#
VCF Tag Deployment v3.4 - lean Git edition, rebuilt standalone deployment runner.
Package: this PS1, core-catalog.csv, assignments-master.csv, vcenters.csv only.
Requires installed VCF PowerCLI with Connect-VIServer -VcfApiToken.
No TLS bypass, password fallback, secret persistence, DRS or migration operations.

EXAMPLES (from extracted folder)
.\VCF-TagDeploy.ps1 -Action Catalog -VCenterCsvPath .\vcenters.csv -CatalogCsvPath .\core-catalog.csv -Mode Plan
# Review plan.csv, repeat with Apply, then Verify.
.\VCF-TagDeploy.ps1 -Action Assignments -VCenterCsvPath .\vcenters.csv -CsvPath .\assignments-master.csv -Mode Plan
# Review plan.csv, repeat with Apply, then Verify.
# Optional: -ReplaceConflicts corrects wrong values in listed categories.
# Optional: -RemoveUnlistedAssignments -PruneCategories core.infra-datacenter,core.infra-region
# Pruning is ONLY for CSV-listed objects and exact named categories. Unresolved
# categories omitted from CSV are NOT authorization to prune; review scope first.
# Catalog default boundary core.infra-: extra definitions are deletion candidates.
# Create=false is undesired-present, NOT protected. Empty desired catalog rejected.
# Category recreation requires AllowCategoryRecreation. Assigned deletion/recreation
# requires AllowAssignmentLoss. Recreation changes IDs and does NOT restore assignments.
# External policies/permissions/references are not discovered, migrated or backed up.
# Runtime reports/snapshots are created under TagDeployReports; keep them out of Git.
# Snapshot is evidence, not rollback. No cross-target transaction; partial writes possible.
# No BuildAssignments or MergeAssignments in this lean deployment edition. Update
# reviewed CSVs separately after inventory/identity/governance changes.
# Static master is the supplied RVTools baseline, not live-verified desired state.
# Unattended Assignments requires ApiToken SecureString and approved MASTER hash.
# Protect target list, prune scope and flags too; master hash does not pin them.
# Start with Plan. No PowerCLI runtime testing performed during package preparation.
# Store this customer inventory only in an appropriately access-controlled Git repo.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Catalog','Assignments')][string]$Action,
 [string]$VCenter,
 [string]$VCenterCsvPath,
 [string]$CatalogCsvPath,
 [string]$CsvPath,
 [ValidateSet('Plan','Apply','Verify')][string]$Mode='Plan',
 [Security.SecureString]$ApiToken,
 [switch]$ReplaceConflicts,
 [switch]$RemoveUnlistedAssignments,
 [string[]]$PruneCategories,
 [switch]$AllowCategoryRecreation,
 [switch]$AllowAssignmentLoss,
 [switch]$ContinueOnError,
 [switch]$Unattended,
 [string]$ExpectedCsvSha256,
 [string]$ReportDirectory=(Join-Path (Get-Location).Path 'TagDeployReports')
)
$ErrorActionPreference='Stop'
function NormalizeTypes($items){
 $out=@(foreach($i in $items){switch -Regex ($i.ToString().Trim()){
 '^(All|\*)$' {'All';break}
 '^(VM|VirtualMachine|urn:vim25:VirtualMachine)$' {'VirtualMachine';break}
 '^(Host|VMHost|HostSystem|urn:vim25:HostSystem)$' {'VMHost';break}
 '^(Cluster|ClusterComputeResource|urn:vim25:ClusterComputeResource)$' {'Cluster';break}
 '^(DatastoreCluster|StoragePod|urn:vim25:StoragePod)$' {'DatastoreCluster';break}
 '^(DistributedPortGroup|DistributedVirtualPortgroup|urn:vim25:DistributedVirtualPortgroup)$' {'DistributedPortGroup';break}
 '^(DistributedSwitch|VmwareDistributedVirtualSwitch|urn:vim25:VmwareDistributedVirtualSwitch)$' {'DistributedSwitch';break}
 '^urn:vim25:(.+)$' {$Matches[1];break}
 default {$i.ToString().Trim()}
 }})
 if(!$out.Count -or $out -contains 'All'){return @('All')};return @($out | Sort-Object -Unique)
}
function ApiTypes($items){return @($items | ForEach-Object {if($_ -eq 'Network'){'urn:vim25:Network'}else{$_}})}
function HashFile($path){return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
function IsCore($name){return $name -and $name.StartsWith('core.infra-',[StringComparison]::OrdinalIgnoreCase)}
function AssertColumns($data,$cols){if(!$data.Count){throw 'Empty input rejected.'};foreach($c in $cols){if($data[0].PSObject.Properties.Name -notcontains $c){throw "Missing column: $c"}}}
if([bool]$VCenter -eq [bool]$VCenterCsvPath){throw 'Specify exactly one of VCenter or VCenterCsvPath.'}
if($Action -eq 'Catalog'){
 if(!$CatalogCsvPath -or $CsvPath -or $ReplaceConflicts -or $RemoveUnlistedAssignments -or $PruneCategories -or $Unattended){throw 'Catalog requires CatalogCsvPath and does not accept assignment options or unattended mode.'}
 $inputPath=(Resolve-Path -LiteralPath $CatalogCsvPath).Path
}else{
 if(!$CsvPath -or $CatalogCsvPath -or $AllowCategoryRecreation -or $AllowAssignmentLoss){throw 'Assignments requires CsvPath; catalog options are invalid.'}
 if([bool]$RemoveUnlistedAssignments -ne [bool]$PruneCategories){throw 'Removal requires both RemoveUnlistedAssignments and explicit PruneCategories.'}
 $inputPath=(Resolve-Path -LiteralPath $CsvPath).Path
}
$inputHash=HashFile $inputPath
if($ExpectedCsvSha256 -and $ExpectedCsvSha256 -ine $inputHash){throw 'Reviewed input SHA256 mismatch.'}
if($Unattended -and (!$ApiToken -or !$ExpectedCsvSha256)){throw 'Unattended requires SecureString ApiToken and approved master SHA256.'}
$rows=@(Import-Csv -LiteralPath $inputPath)
if((HashFile $inputPath) -ne $inputHash){throw 'Input changed during load.'}
$listPath=$null;$listHash=$null
if($VCenterCsvPath){
 $listPath=(Resolve-Path -LiteralPath $VCenterCsvPath).Path;$listHash=HashFile $listPath
 $list=@(Import-Csv -LiteralPath $listPath);AssertColumns $list @('VCenter')
}else{$list=@([pscustomobject]@{VCenter=$VCenter;Enabled='true';ExpectedInstanceUuid=''})}
$seen=@{};$targets=@(foreach($t in $list){
 if(!$t.VCenter -or $t.VCenter -ne $t.VCenter.Trim() -or $t.VCenter -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$' -or $seen.ContainsKey($t.VCenter)){throw 'Invalid or duplicate target hostname.'};$seen[$t.VCenter]=$true
 if($t.PSObject.Properties.Name -contains 'Enabled'){if($t.Enabled -notin @('true','false')){throw 'Enabled must be true/false.'};if($t.Enabled -eq 'false'){continue}}
 $t
})
if(!$targets.Count){throw 'No enabled targets.'}
$desired=@{};$entityTypes=@{VirtualMachine='VirtualMachine';VMHost='HostSystem';Cluster='ClusterComputeResource';Datastore='Datastore';DatastoreCluster='StoragePod';DistributedSwitch='VmwareDistributedVirtualSwitch';DistributedPortGroup='DistributedVirtualPortgroup';Datacenter='Datacenter';Network='Network'}
$coreCategories=@('core.infra-region','core.infra-datacenter','core.infra-environment','core.infra-vcf-instance','core.infra-workload-domain','core.infra-domain','core.infra-os-type','core.infra-os','core.infra-network-type','core.infra-datastore-type','core.infra-datastore-topology')
$common=$coreCategories[0..4]
$scopeRules=@{'core.infra-domain'=@('VirtualMachine','VMHost');'core.infra-os-type'=@('VirtualMachine','VMHost');'core.infra-os'=@('VirtualMachine','VMHost');'core.infra-network-type'=@('Network','DistributedPortGroup');'core.infra-datastore-type'=@('Datastore','DatastoreCluster');'core.infra-datastore-topology'=@('Datastore','DatastoreCluster')}
if($Action -eq 'Catalog'){
 AssertColumns $rows @('Category','TagName','Cardinality','ObjectTypes','Create','RenameFrom','CategoryDescription','TagDescription')
 $pairs=@{}
 foreach($r in $rows){
  if($r.Category -notin $coreCategories -or !$r.TagName -or $r.TagName -ne $r.TagName.Trim() -or $r.Create -notin @('true','false') -or $r.Cardinality -notin @('Single','Multiple') -or !$r.ObjectTypes){throw 'Invalid catalog row.'}
  $key=$r.Category+'|'+$r.TagName;if($pairs.ContainsKey($key)){throw 'Duplicate catalog pair.'};$pairs[$key]=$true
  $ts=@(NormalizeTypes ($r.ObjectTypes -split ';'));if(@($ts | Where-Object {$_ -notin (@('All')+@($entityTypes.Keys))}).Count){throw 'Unsupported catalog object type.'}
  if($r.Create -eq 'false'){continue}
  if($r.Category -eq 'core.infra-os' -and $r.TagName -match '^esxi' -and $r.TagName -ne 'esxi-9.1'){throw 'Only esxi-9.1 is authorized.'}
  if(!$desired.ContainsKey($r.Category)){$desired[$r.Category]=@{Name=$r.Category;Types=$ts;Cardinality=$r.Cardinality;Description=[string]$r.CategoryDescription;Tags=@{}}}
  $d=$desired[$r.Category]
  if(($d.Types -join ';') -ne ($ts -join ';') -or $d.Cardinality -ne $r.Cardinality -or $d.Description -cne [string]$r.CategoryDescription){throw 'Inconsistent category settings.'}
  $d.Tags[$r.TagName]=$r
 }
 if(!$desired.Count){throw 'No enabled desired categories; refusing empty prune.'}
 foreach($d in $desired.Values){$sources=@{};foreach($t in $d.Tags.Values){if($t.RenameFrom){if($d.Tags.ContainsKey($t.RenameFrom) -or $sources.ContainsKey($t.RenameFrom)){throw 'Invalid or duplicate rename source.'};$sources[$t.RenameFrom]=$true}}}
}else{
 AssertColumns $rows @('VCenter','VCenterUUID','EntityType','EntityId','EntityName','EntityUUID','Category','TagName','Approved')
 $pairs=@{};$identities=@{}
 foreach($r in $rows){
  if(!$r.VCenter -or !$r.VCenterUUID -or !$r.EntityId -or !$r.EntityName -or !$r.TagName -or $r.Approved -ine 'true' -or !$entityTypes.ContainsKey($r.EntityType) -or $r.Category -notin $coreCategories){throw 'Invalid desired assignment row.'}
  if($r.EntityType -in @('VMHost','VirtualMachine') -and !$r.EntityUUID){throw 'VM/host UUID required.'}
  if($r.Category -notin $common -and $r.EntityType -notin $scopeRules[$r.Category]){throw 'Governance object/category scope mismatch.'}
  $key=$r.VCenter+'|'+$r.EntityType+'|'+$r.EntityId+'|'+$r.Category;if($pairs.ContainsKey($key)){throw 'Duplicate desired object/category.'};$pairs[$key]=$true
  if($identities.ContainsKey($r.VCenter) -and $identities[$r.VCenter] -ine $r.VCenterUUID){throw 'Multiple UUIDs for one target.'};$identities[$r.VCenter]=$r.VCenterUUID
  if($VCenterCsvPath -and !$seen.ContainsKey($r.VCenter)){throw 'Master destination absent from target list; add disabled to explicitly exclude.'}
 }
 foreach($t in $targets){if(!$identities.ContainsKey($t.VCenter)){throw "No assignment rows for enabled target: $($t.VCenter)"};if($t.ExpectedInstanceUuid -and $t.ExpectedInstanceUuid -ine $identities[$t.VCenter]){throw 'List/master UUID mismatch.'}}
 if($PruneCategories){if(@($PruneCategories | Where-Object {$_ -notin $coreCategories}).Count -or @($PruneCategories | Select-Object -Unique).Count -ne $PruneCategories.Count){throw 'PruneCategories must be unique exact core names; no wildcard.'}}
}
Import-Module VMware.VimAutomation.Core -ErrorAction Stop
if(!(Get-Command Connect-VIServer).Parameters.ContainsKey('VcfApiToken')){throw 'Compatible VCF PowerCLI with VcfApiToken required.'}
New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
$run=Join-Path (Resolve-Path $ReportDirectory).Path ('Run-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'));New-Item -ItemType Directory -Path $run | Out-Null
[ordered]@{Version='3.4';Action=$Action;Mode=$Mode;Input=$inputPath;SHA256=$inputHash;TargetList=$listPath;TargetListSHA256=$listHash;PruneCategories=@($PruneCategories);RemoveUnlistedAssignments=[bool]$RemoveUnlistedAssignments;ReplaceConflicts=[bool]$ReplaceConflicts;AllowAssignmentLoss=[bool]$AllowAssignmentLoss;AllowCategoryRecreation=[bool]$AllowCategoryRecreation} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $run 'run.json')
function StateHash($data){$text=ConvertTo-Json -InputObject @($data) -Depth 12 -Compress;return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text)))}
function CatalogState($vc){
 $cats=@(Get-TagCategory -Server $vc -ErrorAction Stop | Where-Object {IsCore $_.Name} | Sort-Object Name)
 if(@($cats | Group-Object Name | Where-Object Count -gt 1).Count){throw 'Duplicate live category names.'}
 return @(foreach($c in $cats){
  $tags=@(Get-Tag -Category $c -Server $vc -ErrorAction Stop | Sort-Object Name)
  if(@($tags | Group-Object Name | Where-Object Count -gt 1).Count){throw 'Duplicate live tag names.'}
  [pscustomobject]@{Name=$c.Name;Id=$c.Id;Cardinality=$c.Cardinality.ToString();Types=@(NormalizeTypes $c.EntityType);Description=[string]$c.Description;Tags=@(foreach($t in $tags){[pscustomobject]@{Name=$t.Name;Id=$t.Id;Description=[string]$t.Description;Assignments=@(Get-TagAssignment -Tag $t -Server $vc -ErrorAction Stop | ForEach-Object {[pscustomobject]@{EntityId=$_.Entity.Id;EntityName=$_.Entity.Name;AssignmentId=$_.Id}} | Sort-Object EntityId)}})}
 })
}
function CatalogPlan($state){
 $ops=[Collections.Generic.List[object]]::new();$live=@{};foreach($c in $state){$live[$c.Name]=$c}
 function AddOp($op,$cn,$tn,$n,$blocked,$detail){$ops.Add([pscustomobject]@{Operation=$op;Category=$cn;TagName=$tn;AssignmentsAtRisk=$n;Blocked=$blocked;Detail=$detail})}
 foreach($c in $state){if(!$desired.ContainsKey($c.Name)){$n=@($c.Tags | ForEach-Object {$_.Assignments}).Count;AddOp 'DeleteCategory' $c.Name '' $n ($n -gt 0 -and !$AllowAssignmentLoss) 'Extra category in core.infra- boundary.'}}
 foreach($d in @($desired.Values | Sort-Object Name)){
  $c=$live[$d.Name];if(!$c){AddOp 'CreateCategory' $d.Name '' 0 $false 'Create category and desired values.';continue}
  $narrow=($c.Types -contains 'All' -and $d.Types -notcontains 'All') -or ($d.Types -notcontains 'All' -and @($c.Types | Where-Object {$_ -notin $d.Types}).Count -gt 0)
  if($narrow -or ($c.Cardinality -eq 'Multiple' -and $d.Cardinality -eq 'Single')){$n=@($c.Tags | ForEach-Object {$_.Assignments}).Count;AddOp 'RecreateCategory' $d.Name '' $n (!$AllowCategoryRecreation -or ($n -gt 0 -and !$AllowAssignmentLoss)) 'New IDs; assignments not restored; external references require review.';continue}
  if(($c.Types -join ';') -ne ($d.Types -join ';') -or $c.Cardinality -ne $d.Cardinality -or $c.Description -cne $d.Description){AddOp 'UpdateCategory' $d.Name '' 0 $false 'Edit only differing settings.'}
  $lt=@{};foreach($t in $c.Tags){$lt[$t.Name]=$t};$used=@{}
  foreach($t in @($d.Tags.Values | Sort-Object TagName)){
   $old=if($t.RenameFrom){$lt[$t.RenameFrom]}else{$null};$now=$lt[$t.TagName]
   if($old -and $now){AddOp 'RenameConflict' $d.Name $t.TagName 0 $true 'Both rename source/destination exist; manual merge.'}
   elseif($old){$used[$old.Name]=$true;AddOp 'RenameTag' $d.Name $t.TagName 0 $false ('Rename '+$old.Name+' retaining ID.')}
   elseif(!$now){AddOp 'CreateTag' $d.Name $t.TagName 0 $false 'Missing value.'}
   elseif($now.Description -cne [string]$t.TagDescription){AddOp 'UpdateTag' $d.Name $t.TagName 0 $false 'Description differs.'}
  }
  foreach($t in $c.Tags){if(!$d.Tags.ContainsKey($t.Name) -and !$used.ContainsKey($t.Name)){$n=@($t.Assignments).Count;AddOp 'DeleteTag' $d.Name $t.Name $n ($n -gt 0 -and !$AllowAssignmentLoss) 'Extra value, including disabled catalog values.'}}
 }
 return $ops.ToArray()
}
function CreateCategory($d,$vc){$c=New-TagCategory -Name $d.Name -Cardinality $d.Cardinality -EntityType (ApiTypes $d.Types) -Description $d.Description -Server $vc -ErrorAction Stop;foreach($t in $d.Tags.Values){New-Tag -Name $t.TagName -Category $c -Description $t.TagDescription -Server $vc -ErrorAction Stop | Out-Null}}
function AssignmentSnapshot($entities,$vc){return @(foreach($key in @($entities.Keys | Sort-Object)){[pscustomobject]@{ObjectKey=$key;Assignments=@(Get-TagAssignment -Entity $entities[$key] -Server $vc -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Category=$_.Tag.Category.Name;TagName=$_.Tag.Name;TagId=$_.Tag.Id;AssignmentId=$_.Id}} | Sort-Object Category,TagId)}})}
$owned=$false;$failed=0;$stop=$false;$summary=[Collections.Generic.List[object]]::new()
try{
 if(!$ApiToken){$ApiToken=Read-Host 'VCF SSO API token reused across selected vCenters (hidden)' -AsSecureString;$owned=$true};if(!$ApiToken.Length){throw 'Empty token.'}
 foreach($target in $targets){
  $name=$target.VCenter;$vc=$null
  if($stop){$summary.Add([pscustomobject]@{VCenter=$name;Status='NotAttempted';Detail='Stopped after earlier failure.'});continue}
  $dir=Join-Path $run $name;New-Item -ItemType Directory -Path $dir | Out-Null
  try{
   if((HashFile $inputPath) -ne $inputHash -or ($listPath -and (HashFile $listPath) -ne $listHash)){throw 'Input/list changed; no target writes.'}
   try{$vc=Connect-VIServer -Server $name -VcfApiToken $ApiToken -NotDefault -ErrorAction Stop}catch{throw 'Authentication failed; check token expiry/authorization, SSO federation, TLS and PowerCLI. No password fallback.'}
   $si=Get-View -Id ServiceInstance -Server $vc -ErrorAction Stop;$uuid=$si.Content.About.InstanceUuid
   if($target.ExpectedInstanceUuid -and $target.ExpectedInstanceUuid -ine $uuid){throw 'Target expected UUID mismatch.'}
   if($Action -eq 'Catalog'){
    $state=@(CatalogState $vc);$sig=StateHash $state;$ops=@(CatalogPlan $state)
    ConvertTo-Json -InputObject $state -Depth 12 | Set-Content (Join-Path $dir 'before.json')
   }else{
    if($uuid -ine $identities[$name]){throw 'Live vCenter UUID differs from master.'}
    $part=@($rows | Where-Object VCenter -eq $name);$part | Export-Csv (Join-Path $dir 'input.csv') -NoTypeInformation -Encoding utf8
    $entities=@{};$wanted=@{};$cats=@(Get-TagCategory -Server $vc -ErrorAction Stop);$tagCache=@{};$ops=[Collections.Generic.List[object]]::new()
    foreach($r in $part){
     $key=$r.EntityType+'|'+$r.EntityId
     if(!$entities.ContainsKey($key)){
      $mor=New-Object VMware.Vim.ManagedObjectReference;$mor.Type=$entityTypes[$r.EntityType];$mor.Value=$r.EntityId
      $view=Get-View -Id $mor -Server $vc -ErrorAction Stop
      if($view.Name -cne $r.EntityName){throw 'Object name mismatch; no name fallback.'}
      if($r.EntityType -eq 'VirtualMachine' -and $view.Config.Uuid -ine $r.EntityUUID){throw 'VM UUID mismatch.'}
      if($r.EntityType -eq 'VMHost' -and $view.Hardware.SystemInfo.Uuid -ine $r.EntityUUID){throw 'Host UUID mismatch.'}
      $entities[$key]=Get-VIObjectByVIView -VIView $view -ErrorAction Stop;$wanted[$key]=@{}
     }
     $e=$entities[$key];if($e.Name -cne $r.EntityName){throw 'Inconsistent object identity across rows.'}
     if($r.EntityType -eq 'VMHost'){
      if($e.ExtensionData.Hardware.SystemInfo.Uuid -ine $r.EntityUUID){throw 'Inconsistent host UUID.'}
      if($r.Category -in @('core.infra-os','core.infra-os-type')){
       $prod=$e.ExtensionData.Config.Product
       if($prod.Name -notmatch 'ESXi' -or $prod.Version -notmatch '^9\.1(?:\.|$)'){throw 'Host is not confirmed ESXi 9.1.'}
       if(($r.Category -eq 'core.infra-os' -and $r.TagName -ne 'esxi-9.1') -or ($r.Category -eq 'core.infra-os-type' -and $r.TagName -ne 'esxi')){throw 'Unauthorized host OS taxonomy.'}
      }
     }
     if($r.EntityType -eq 'VirtualMachine' -and $e.ExtensionData.Config.Uuid -ine $r.EntityUUID){throw 'Inconsistent VM UUID.'}
     $cat=@($cats | Where-Object Name -eq $r.Category);if($cat.Count -ne 1 -or $cat[0].Cardinality.ToString() -ne 'Single'){throw 'Category missing/ambiguous/not Single.'}
     $ts=@(NormalizeTypes $cat[0].EntityType);if($ts -notcontains 'All' -and $ts -notcontains $r.EntityType){throw 'Live object eligibility mismatch.'}
     if(!$tagCache.ContainsKey($r.Category)){$tagCache[$r.Category]=@(Get-Tag -Category $cat[0] -Server $vc -ErrorAction Stop)}
     $tag=@($tagCache[$r.Category] | Where-Object Name -eq $r.TagName);if($tag.Count -ne 1){throw 'Desired tag missing/ambiguous.'};$wanted[$key][$r.Category]=$tag[0]
    }
    foreach($cn in $PruneCategories){if(@($cats | Where-Object Name -eq $cn).Count -ne 1){throw 'Prune category missing/ambiguous.'}}
    $state=@(AssignmentSnapshot $entities $vc);$sig=StateHash $state
    ConvertTo-Json -InputObject $state -Depth 12 | Set-Content (Join-Path $dir 'before.json')
    foreach($o in $state){
     foreach($cn in $wanted[$o.ObjectKey].Keys){$tag=$wanted[$o.ObjectKey][$cn];$current=@($o.Assignments | Where-Object Category -eq $cn)
      if($current.Count -eq 1 -and $current[0].TagId -eq $tag.Id){continue}
      $op=if($current.Count){'ReplaceAssignment'}else{'AddAssignment'}
      $ops.Add([pscustomobject]@{Operation=$op;Category=$cn;TagName=$tag.Name;ObjectKey=$o.ObjectKey;TagId=$tag.Id;Blocked=($current.Count -gt 0 -and !$ReplaceConflicts);Detail=($current.TagName -join ';')})
     }
     if($RemoveUnlistedAssignments){foreach($a in $o.Assignments){if($a.Category -in $PruneCategories -and !$wanted[$o.ObjectKey].ContainsKey($a.Category)){$ops.Add([pscustomobject]@{Operation='RemoveUnlisted';Category=$a.Category;TagName=$a.TagName;ObjectKey=$o.ObjectKey;TagId=$a.TagId;Blocked=$false;Detail='Absent desired category on CSV-listed object.'})}}}
    }
    $ops=$ops.ToArray()
   }
   if($ops.Count){$ops | Export-Csv (Join-Path $dir 'plan.csv') -NoTypeInformation -Encoding utf8}else{'Operation,Category,TagName,Blocked,Detail' | Set-Content (Join-Path $dir 'plan.csv')}
   Write-Host "$name | $Action $Mode | planned operations=$($ops.Count) | report=$dir"
   if($Mode -eq 'Verify' -and $ops.Count){throw 'Drift found; see plan.csv.'}
   if($Mode -eq 'Apply' -and $ops.Count){
    if($Action -eq 'Catalog' -and @($ops | Where-Object Blocked).Count){throw 'Blocked catalog operations; no target writes. Review loss/recreation flags or rename conflict.'}
    if(!$Unattended -and (Read-Host "Review plan.csv. Type APPLY $name to authorize") -cne "APPLY $name"){throw 'Cancelled; no writes.'}
    if($RemoveUnlistedAssignments -and !$Unattended -and (Read-Host "DESTRUCTIVE: type PRUNE $name for categories $($PruneCategories -join ',')") -cne "PRUNE $name"){throw 'Pruning cancelled; no writes.'}
    if((HashFile $inputPath) -ne $inputHash -or ($listPath -and (HashFile $listPath) -ne $listHash)){throw 'Input/list changed before writes.'}
    $fresh=if($Action -eq 'Catalog'){@(CatalogState $vc)}else{@(AssignmentSnapshot $entities $vc)}
    if((StateHash $fresh) -ne $sig){throw 'Live state changed after preflight; no writes. Re-plan.'}
    foreach($op in $ops){
     if($op.Blocked){$op | Export-Csv (Join-Path $dir 'skipped.csv') -Append -NoTypeInformation;continue}
     [pscustomobject]@{Time=(Get-Date).ToString('o');Operation=$op.Operation;Category=$op.Category;TagName=$op.TagName;ObjectKey=$op.ObjectKey;Status='Starting'} | Export-Csv (Join-Path $dir 'actions.csv') -Append -NoTypeInformation -Encoding utf8
     if($Action -eq 'Catalog'){
      $d=$desired[$op.Category];$cs=@(Get-TagCategory -Server $vc -ErrorAction Stop | Where-Object Name -eq $op.Category);if($cs.Count -gt 1){throw 'Ambiguous category.'};$c=if($cs.Count){$cs[0]}else{$null}
      switch($op.Operation){
       CreateCategory {if($c){throw 'Concurrent category creation.'};CreateCategory $d $vc}
       {$_ -in @('DeleteCategory','RecreateCategory')} {
        if(!$c){throw 'Category disappeared.'};$aa=@(Get-TagAssignment -Category $c -Server $vc -ErrorAction Stop);if($aa.Count -and !$AllowAssignmentLoss){throw 'Assigned deletion blocked.'}
        Remove-TagCategory -Category $c -Server $vc -Confirm:$false -ErrorAction Stop
        if($op.Operation -eq 'RecreateCategory'){CreateCategory $d $vc}
       }
       UpdateCategory {
        if(!$c){throw 'Category disappeared.'};$sp=@{Category=$c;Server=$vc;ErrorAction='Stop'}
        if([string]$c.Description -cne $d.Description){$sp.Description=$d.Description}
        if($c.Cardinality.ToString() -ne $d.Cardinality){$sp.Cardinality=$d.Cardinality}
        $now=@(NormalizeTypes $c.EntityType);$add=@($d.Types | Where-Object {$_ -notin $now});if($add.Count){$sp.AddEntityType=ApiTypes $add}
        if($sp.Count -gt 3){Set-TagCategory @sp | Out-Null}
       }
       default {
        if(!$c){throw 'Category disappeared.'};$tags=@(Get-Tag -Category $c -Server $vc -ErrorAction Stop);$t=if($d){$d.Tags[$op.TagName]}else{$null};$match=@($tags | Where-Object Name -eq $op.TagName)
        switch($op.Operation){
         CreateTag {if($match.Count){throw 'Concurrent tag creation.'};New-Tag -Name $t.TagName -Category $c -Description $t.TagDescription -Server $vc -ErrorAction Stop | Out-Null}
         UpdateTag {if($match.Count -ne 1){throw 'Tag missing/ambiguous.'};Set-Tag -Tag $match[0] -Description $t.TagDescription -Server $vc -ErrorAction Stop | Out-Null}
         RenameTag {$old=@($tags | Where-Object Name -eq $t.RenameFrom);if($old.Count -ne 1 -or $match.Count){throw 'Rename conflict.'};Set-Tag -Tag $old[0] -Name $t.TagName -Description $t.TagDescription -Server $vc -ErrorAction Stop | Out-Null}
         DeleteTag {if($match.Count -ne 1){throw 'Tag missing/ambiguous.'};$aa=@(Get-TagAssignment -Tag $match[0] -Server $vc -ErrorAction Stop);if($aa.Count -and !$AllowAssignmentLoss){throw 'Assigned deletion blocked.'};Remove-Tag -Tag $match[0] -Server $vc -Confirm:$false -ErrorAction Stop}
         default {throw 'Unsupported catalog operation.'}
        }
       }
      }
     }else{
      $e=$entities[$op.ObjectKey];$current=@(Get-TagAssignment -Entity $e -Server $vc -ErrorAction Stop | Where-Object {$_.Tag.Category.Name -eq $op.Category})
      $beforeObject=@($state | Where-Object ObjectKey -eq $op.ObjectKey)[0];$expected=@($beforeObject.Assignments | Where-Object Category -eq $op.Category)
      if((@($current.Tag.Id | Sort-Object) -join '|') -ne (@($expected.TagId | Sort-Object) -join '|')){throw 'Concurrent category assignment change; stopped. Partial changes may exist.'}
      if($op.Operation -eq 'RemoveUnlisted'){
       $match=@($current | Where-Object {$_.Tag.Id -eq $op.TagId});if($match.Count -ne 1){throw 'Prune assignment missing/ambiguous.'};Remove-TagAssignment -TagAssignment $match[0] -Confirm:$false -ErrorAction Stop | Out-Null
       if(@(Get-TagAssignment -Entity $e -Server $vc | Where-Object {$_.Tag.Id -eq $op.TagId}).Count){throw 'Prune verification failed.'}
      }else{
       $old=@($current.Tag);if($current.Count){$current | Remove-TagAssignment -Confirm:$false -ErrorAction Stop | Out-Null}
       try{New-TagAssignment -Entity $e -Tag $wanted[$op.ObjectKey][$op.Category] -Server $vc -ErrorAction Stop | Out-Null}
       catch{$now=@(Get-TagAssignment -Entity $e -Server $vc | Where-Object {$_.Tag.Category.Name -eq $op.Category});if(!$now.Count){foreach($t in $old){New-TagAssignment -Entity $e -Tag $t -Server $vc -ErrorAction Stop | Out-Null}};throw 'Assignment add failed; prior-value recovery attempted only if empty.'}
       $after=@(Get-TagAssignment -Entity $e -Server $vc | Where-Object {$_.Tag.Category.Name -eq $op.Category});if($after.Count -ne 1 -or $after[0].Tag.Id -ne $op.TagId){throw 'Post-write verification failed.'}
      }
      # Update expected category state for subsequent removals on this object.
      $remaining=@($beforeObject.Assignments | Where-Object Category -ne $op.Category)
      $newState=@(Get-TagAssignment -Entity $e -Server $vc | Where-Object {$_.Tag.Category.Name -eq $op.Category} | ForEach-Object {[pscustomobject]@{Category=$_.Tag.Category.Name;TagName=$_.Tag.Name;TagId=$_.Tag.Id;AssignmentId=$_.Id}})
      $beforeObject.Assignments=@($remaining)+@($newState)
     }
     [pscustomobject]@{Time=(Get-Date).ToString('o');Operation=$op.Operation;Category=$op.Category;TagName=$op.TagName;ObjectKey=$op.ObjectKey;Status='Completed'} | Export-Csv (Join-Path $dir 'actions.csv') -Append -NoTypeInformation -Encoding utf8
    }
    if($Action -eq 'Catalog'){$after=@(CatalogState $vc);ConvertTo-Json -InputObject $after -Depth 12 | Set-Content (Join-Path $dir 'after.json');if(@(CatalogPlan $after).Count){throw 'Post-apply catalog drift remains.'}}
    else{
     $after=@(AssignmentSnapshot $entities $vc);ConvertTo-Json -InputObject $after -Depth 12 | Set-Content (Join-Path $dir 'after.json')
     foreach($o in $after){foreach($cn in $wanted[$o.ObjectKey].Keys){$aa=@($o.Assignments | Where-Object Category -eq $cn);if($aa.Count -ne 1 -or $aa[0].TagId -ne $wanted[$o.ObjectKey][$cn].Id){throw 'Desired assignment drift remains; conflicts may have been skipped.'}}
      if($RemoveUnlistedAssignments -and @($o.Assignments | Where-Object {$_.Category -in $PruneCategories -and !$wanted[$o.ObjectKey].ContainsKey($_.Category)}).Count){throw 'Unlisted assignments remain in pruning scope.'}
     }
    }
   }
   $summary.Add([pscustomobject]@{VCenter=$name;Status='Completed';Detail="$Action $Mode; operations=$($ops.Count)"})
  }catch{$failed++;$_.Exception.Message | Set-Content (Join-Path $dir 'error.txt');$summary.Add([pscustomobject]@{VCenter=$name;Status='Failed';Detail=$_.Exception.Message});if(!$ContinueOnError){$stop=$true}}
  finally{if($vc){Disconnect-VIServer -Server $vc -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}}
 }
}finally{$summary | Export-Csv (Join-Path $run 'summary.csv') -NoTypeInformation -Encoding utf8;if($owned -and $ApiToken){$ApiToken.Dispose()};Write-Host "Reports: $run"}
if($failed){throw "$failed target(s) failed. Inspect reports; no automatic rollback."}
