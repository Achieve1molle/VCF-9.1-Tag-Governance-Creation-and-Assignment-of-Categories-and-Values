#requires -Version 7.4
<# RevD consolidated Catalog + multi-object Assignments. No typed APPLY confirmation.
Catalog keep-list is CatalogCsvPath, NEVER the assignments CSV.
-Prune is Catalog-only: default boundary core.infra-; -PruneScope All explicitly
covers every category. Deleting definitions removes their assignments indirectly.
No assignment queries, VM/host/datastore enumeration in Catalog.
Multiple-to-Single / scope narrowing are reported, not automatically recreated.
Assignments: VirtualMachine, VMHost, Cluster, Datastore; exact name + type + vCenter.
No input IDs. No assignment pruning. Duplicate object/category rows rejected.
Token prompted once if omitted; -Unattended requires a supplied SecureString.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Catalog','Assignments')][string]$Action,
 [string]$CatalogCsvPath,
 [string]$CsvPath,
 [string]$VCenterCsvPath,
 [string]$VCenter,
 [ValidateSet('Plan','Apply','Verify')][string]$Mode='Plan',
 [switch]$Apply,
 [Security.SecureString]$ApiToken,
 [switch]$Unattended,
 [switch]$ReplaceConflicts,
 [switch]$Prune,
 [ValidateSet('Prefix','All')][string]$PruneScope='Prefix',
 [string]$ManagedPrefix='core.infra-',
 [string]$ReportDirectory=(Join-Path (Get-Location).Path 'TagDeployReports')
)
function Invoke-NameAssignments {
[CmdletBinding()]
param(
 [ValidateSet('Assignments')][string]$Action='Assignments',
 [Parameter(Mandatory)][string]$CsvPath,
 [string]$VCenterCsvPath,
 [string]$VCenter,
 [ValidateSet('Plan','Apply','Verify')][string]$Mode='Plan',
 [switch]$Apply,
 [Parameter(Mandatory)][Security.SecureString]$ApiToken,
 [switch]$ReplaceConflicts,
 [string]$ReportDirectory=(Join-Path (Get-Location).Path 'TagDeployReports')
)
$ErrorActionPreference='Stop'
$ConfirmPreference='None'
if($Apply){
 if($PSBoundParameters.ContainsKey('Mode') -and $Mode -ne 'Apply'){throw 'Do not combine -Apply with Plan or Verify.'}
 $Mode='Apply'
}
if($VCenter -and $VCenterCsvPath){throw 'Choose VCenter or VCenterCsvPath, not both.'}
$path=(Resolve-Path -LiteralPath $CsvPath).Path
$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
$rows=@(Import-Csv -LiteralPath $path)
if(!$rows.Count){throw 'Empty CSV.'}
foreach($col in 'VCenter','Category','TagName'){if($rows[0].PSObject.Properties.Name -notcontains $col){throw "Missing column $col"}}
if($rows[0].PSObject.Properties.Name -notcontains 'VMName' -and $rows[0].PSObject.Properties.Name -notcontains 'EntityName'){throw 'VMName or EntityName column required.'}
$seen=@{}
foreach($r in $rows){
 $n=if($r.VMName){$r.VMName}else{$r.EntityName}
 if($r.VMName -and $r.EntityName -and $r.VMName -ine $r.EntityName){throw 'Conflicting VMName and EntityName.'}
 if(!$n -or !$r.VCenter -or !$r.Category -or !$r.TagName){throw 'Blank vCenter/name/category/tag.'}
 foreach($value in @($n,$r.VCenter,$r.Category,$r.TagName)){if($value -ne $value.Trim()){throw 'Leading/trailing whitespace rejected.'}}
 $type=switch ([string]$r.EntityType) {
  {$_ -in @('','VM','VirtualMachine')} {'VirtualMachine';break}
  {$_ -in @('Host','VMHost','HostSystem')} {'VMHost';break}
  {$_ -in @('Cluster','ClusterComputeResource')} {'Cluster';break}
  'Datastore' {'Datastore';break}
  default {throw "Unsupported assignment EntityType: $($_). Supported: VirtualMachine, VMHost, Cluster, Datastore."}
 }
 $r | Add-Member -NotePropertyName ResolvedInputType -NotePropertyValue $type -Force
 if($r.PSObject.Properties.Name -contains 'Approved' -and $r.Approved -ine 'true'){throw 'Only Approved=true rows accepted.'}
 $r | Add-Member -NotePropertyName ResolvedInputName -NotePropertyValue $n -Force
 $key=$r.VCenter+'|'+$r.ResolvedInputType+'|'+$n+'|'+$r.Category
 if($seen.ContainsKey($key)){throw "Duplicate entity/type/category row: $key"};$seen[$key]=$true
}
if($VCenterCsvPath){
 $listPath=(Resolve-Path -LiteralPath $VCenterCsvPath).Path;$listHash=(Get-FileHash $listPath -Algorithm SHA256).Hash
 $list=@(Import-Csv -LiteralPath $listPath)
 if(!$list.Count -or $list[0].PSObject.Properties.Name -notcontains 'VCenter'){throw 'Target list needs VCenter column.'}
 $known=@{};$targets=@(foreach($t in $list){
  if(!$t.VCenter -or $known.ContainsKey($t.VCenter)){throw 'Blank/duplicate target.'};$known[$t.VCenter]=$true
  if($t.PSObject.Properties.Name -contains 'Enabled'){if($t.Enabled -notin @('true','false')){throw 'Enabled must be true/false.'};if($t.Enabled -eq 'false'){continue}}
  $t.VCenter
 })
 foreach($r in $rows){if(!$known.ContainsKey($r.VCenter)){throw 'Assignment target absent from target list.'}}
}elseif($VCenter){$targets=@($VCenter)}else{$targets=@($rows.VCenter | Sort-Object -Unique)}
if(!$targets.Count){throw 'No enabled targets.'}
foreach($name in $targets){if(!@($rows | Where-Object VCenter -eq $name).Count){throw "No assignment rows for enabled target $name"}}
Import-Module VMware.VimAutomation.Core -ErrorAction Stop
if(!(Get-Command Connect-VIServer).Parameters.ContainsKey('VcfApiToken')){throw 'VCF PowerCLI with VcfApiToken support required.'}
New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
$run=Join-Path (Resolve-Path $ReportDirectory).Path ('NameAssignments-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'));New-Item -ItemType Directory -Path $run | Out-Null
$log=Join-Path $run 'results.csv';$owned=$false;$failures=0
function Log($r,$status,$detail,$id,$uuid,$before){
 [pscustomobject]@{Time=(Get-Date).ToString('o');VCenter=$name;EntityType=$r.ResolvedInputType;EntityName=$r.ResolvedInputName;Category=$r.Category;TagName=$r.TagName;Status=$status;Detail=$detail;ResolvedEntityId=$id;ResolvedVMUUID=$uuid;Before=$before;Mode=$Mode;CsvSHA256=$hash} | Export-Csv $log -Append -NoTypeInformation -Encoding utf8
}
try{
 if(!$ApiToken.Length){throw 'Empty token.'}
 foreach($name in $targets){
  $vc=$null
  try{
   try{$vc=Connect-VIServer -Server $name -VcfApiToken $ApiToken -NotDefault -ErrorAction Stop}catch{throw 'Authentication failed. Check token authorization, SSO federation, TLS trust and PowerCLI.'}
   # Fetch from this connection only; exact literal filtering avoids wildcard matches.
   $inventory=@{};$tagCache=@{}
   foreach($type in @($rows | Where-Object VCenter -eq $name | Select-Object -ExpandProperty ResolvedInputType -Unique)) {
    $inventory[$type]=@(switch ($type) {
     'VirtualMachine' {Get-VM -Server $vc -ErrorAction Stop}
     'VMHost' {Get-VMHost -Server $vc -ErrorAction Stop}
     'Cluster' {Get-Cluster -Server $vc -ErrorAction Stop}
     'Datastore' {Get-Datastore -Server $vc -ErrorAction Stop}
    })
   }
   $cats=@(Get-TagCategory -Server $vc -ErrorAction Stop)
   $plan=[Collections.Generic.List[object]]::new()
   foreach($r in @($rows | Where-Object VCenter -eq $name)){
    try{
     $match=@($inventory[$r.ResolvedInputType] | Where-Object Name -eq $r.ResolvedInputName)
     if($match.Count -ne 1){throw "Exact $($r.ResolvedInputType) name match count=$($match.Count). Skipped; no first-match selection."}
     $c=@($cats | Where-Object Name -eq $r.Category)
     if($c.Count -ne 1){throw 'Category missing or ambiguous.'}
     if(!$tagCache.ContainsKey($c[0].Id)){$tagCache[$c[0].Id]=@(Get-Tag -Category $c[0] -Server $vc -ErrorAction Stop)}
     $t=@($tagCache[$c[0].Id] | Where-Object Name -eq $r.TagName)
     if($t.Count -ne 1){throw 'Tag missing or ambiguous; create definitions separately.'}
     $eligible=@($c[0].EntityType | ForEach-Object {$_.ToString()})
     $allowed=switch($r.ResolvedInputType){
      'VirtualMachine' {@('All','*','VM','VirtualMachine','urn:vim25:VirtualMachine')}
      'VMHost' {@('All','*','Host','VMHost','HostSystem','urn:vim25:HostSystem')}
      'Cluster' {@('All','*','Cluster','ClusterComputeResource','urn:vim25:ClusterComputeResource')}
      'Datastore' {@('All','*','Datastore','urn:vim25:Datastore')}
     }
     if($eligible.Count -and !@($eligible | Where-Object {$_ -in $allowed}).Count){throw "Category does not permit $($r.ResolvedInputType) assignments."}
     $uuid=if($r.ResolvedInputType -eq 'VirtualMachine'){[string]$match[0].ExtensionData.Config.Uuid}else{''}
     $before=@(Get-TagAssignment -Entity $match[0] -Category $c[0] -Server $vc -ErrorAction Stop)
     $plan.Add([pscustomobject]@{Row=$r;VM=$match[0];Category=$c[0];Tag=$t[0];UUID=$uuid})
     Log $r 'Resolved' 'Exact name resolved on selected vCenter; runtime IDs for audit only.' $match[0].Id $uuid ($before.Tag.Name -join ';')
    }catch{$failures++;Log $r 'SkippedError' $_.Exception.Message '' '' '';Write-Warning "$name / $($r.ResolvedInputName): $($_.Exception.Message)"}
   }
   # Explicit -Apply or -Mode Apply authorizes writes; no confirmation prompt.
   if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hash){throw 'CSV changed; target stopped.'}
   if($listPath -and (Get-FileHash -LiteralPath $listPath -Algorithm SHA256).Hash -ne $listHash){throw 'Target list changed; target stopped.'}
   foreach($item in $plan){
    $r=$item.Row;$before=@()
    try{
     $resolved=@(switch($r.ResolvedInputType){
      'VirtualMachine' {Get-VM -Id $item.VM.Id -Server $vc -ErrorAction Stop}
      'VMHost' {Get-VMHost -Id $item.VM.Id -Server $vc -ErrorAction Stop}
      'Cluster' {Get-Cluster -Id $item.VM.Id -Server $vc -ErrorAction Stop}
      'Datastore' {Get-Datastore -Id $item.VM.Id -Server $vc -ErrorAction Stop}
     })
     if($resolved.Count -ne 1){throw 'Runtime ID no longer resolves uniquely; skipped.'}
     $vm=$resolved[0]
     if($vm.Name -ine $r.ResolvedInputName){throw 'Entity renamed since resolution; skipped.'}
     if($r.ResolvedInputType -eq 'VirtualMachine' -and $vm.ExtensionData.Config.Uuid -ine $item.UUID){throw 'VM UUID changed since resolution; skipped.'}
     $before=@(Get-TagAssignment -Entity $vm -Category $item.Category -Server $vc -ErrorAction Stop)
     $has=@($before | Where-Object {$_.Tag.Id -eq $item.Tag.Id}).Count -gt 0
     $single=$item.Category.Cardinality.ToString() -eq 'Single'
     if($has -and (!$single -or $before.Count -eq 1)){$status='Compliant'}
     elseif($Mode -ne 'Apply'){$status=if($before.Count -and $single){'Conflict'}else{'Missing'};if($Mode -eq 'Verify'){$failures++}}
     elseif($single -and $before.Count -and !$ReplaceConflicts){$status='ConflictSkipped';$failures++}
     else{
      $old=@()
      if($single -and $before.Count){
       $old=@($before.Tag);Log $r 'ReplacementStarting' 'Non-atomic replacement; previous values logged.' $vm.Id $item.UUID ($before.Tag.Name -join ';')
       foreach($a in $before){Remove-TagAssignment -TagAssignment $a -Confirm:$false -ErrorAction Stop | Out-Null}
      }
      try{New-TagAssignment -Entity $vm -Tag $item.Tag -Server $vc -Confirm:$false -ErrorAction Stop | Out-Null}
      catch{
       $now=@(Get-TagAssignment -Entity $vm -Category $item.Category -Server $vc -ErrorAction Stop)
       if(!$now.Count){foreach($t in $old){New-TagAssignment -Entity $vm -Tag $t -Server $vc -Confirm:$false -ErrorAction Stop | Out-Null}}
       throw 'Desired add failed; recovery attempted only if empty. Inspect live state.'
      }
      $after=@(Get-TagAssignment -Entity $vm -Category $item.Category -Server $vc -ErrorAction Stop)
      if(!@($after | Where-Object {$_.Tag.Id -eq $item.Tag.Id}).Count){throw 'Post-write verification failed.'}
      $status=if($old.Count){'Replaced'}else{'Assigned'}
     }
     Log $r $status '' $vm.Id $item.UUID ($before.Tag.Name -join ';')
    }catch{$failures++;Log $r 'Error' $_.Exception.Message $item.VM.Id $item.UUID ($before.Tag.Name -join ';')}
   }
  }catch{$failures++;[pscustomobject]@{VCenter=$name;Error=$_.Exception.Message} | Export-Csv (Join-Path $run 'target-errors.csv') -Append -NoTypeInformation -Encoding utf8;Write-Warning "${name}: target failed; continuing."}
  finally{if($vc){Disconnect-VIServer -Server $vc -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}}
 }
}finally{if($owned -and $ApiToken){$ApiToken.Dispose()};Write-Host "Reports: $run"}
if($failures){throw "$failures error(s), skipped conflicts or Verify drift; successful changes retained. See reports."}

}

function Invoke-DefinitionCatalog {
 param([string]$Path,[string[]]$Targets,[Security.SecureString]$Token)
 function Norm($values){
  $a=@(foreach($v in $values){switch -Regex ($v.ToString().Trim()){
   '^(All|\*)$' {'All';break}
   '^(VM|VirtualMachine|urn:vim25:VirtualMachine)$' {'VirtualMachine';break}
   '^(Host|VMHost|HostSystem|urn:vim25:HostSystem)$' {'VMHost';break}
   '^(Cluster|ClusterComputeResource|urn:vim25:ClusterComputeResource)$' {'Cluster';break}
   '^(DatastoreCluster|StoragePod|urn:vim25:StoragePod)$' {'DatastoreCluster';break}
   '^(DistributedPortGroup|DistributedVirtualPortgroup|urn:vim25:DistributedVirtualPortgroup)$' {'DistributedPortGroup';break}
   '^(DistributedSwitch|VmwareDistributedVirtualSwitch|urn:vim25:VmwareDistributedVirtualSwitch)$' {'DistributedSwitch';break}
   '^urn:vim25:(.+)$' {$Matches[1];break}
   default {$v.ToString().Trim()}
  }})
  if(!$a.Count -or $a -contains 'All'){return @('All')};return @($a | Sort-Object -Unique)
 }
 function ApiTypes($a){return @($a | ForEach-Object {if($_ -eq 'Network'){'urn:vim25:Network'}else{$_}})}
 function InBoundary($n){return $PruneScope -eq 'All' -or $n.StartsWith($ManagedPrefix,[StringComparison]::OrdinalIgnoreCase)}
 $path=(Resolve-Path -LiteralPath $Path).Path;$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
 $rows=@(Import-Csv -LiteralPath $path);if(!$rows.Count){throw 'Empty catalog rejected.'}
 foreach($col in 'Category','TagName','Cardinality','ObjectTypes'){if($rows[0].PSObject.Properties.Name -notcontains $col){throw "Missing catalog column: $col"}}
 $desired=@{};$seen=@{};$renameKeys=@{}
 $validTypes='All','VirtualMachine','VMHost','Cluster','Datastore','DatastoreCluster','DistributedPortGroup','DistributedSwitch','Datacenter','Network','Folder','ResourcePool','VApp','ContentLibrary','ContentLibraryItem','HostNetwork','OpaqueNetwork'
 foreach($r in $rows){
  if(!$r.Category -or !$r.TagName -or !$r.ObjectTypes -or $r.Cardinality -notin @('Single','Multiple')){throw 'Invalid catalog names/cardinality/object types.'}
  foreach($v in @($r.Category,$r.TagName)){if($v -ne $v.Trim()){throw 'Catalog names have surrounding whitespace.'}}
  $key=$r.Category+'|'+$r.TagName;if($seen.ContainsKey($key)){throw 'Duplicate catalog pair.'};$seen[$key]=$true
  if($r.PSObject.Properties.Name -contains 'Create'){if($r.Create -notin @('true','false')){throw 'Create must be true/false.'};if($r.Create -eq 'false'){continue}}
  if($Prune -and !(InBoundary $r.Category)){throw 'Enabled catalog category outside prune boundary; select appropriate explicit scope.'}
  $types=@(Norm ($r.ObjectTypes -split ';'));if(@($types | Where-Object {$_ -notin $validTypes}).Count){throw 'Unsupported object type.'}
  if(!$desired.ContainsKey($r.Category)){$desired[$r.Category]=@{Name=$r.Category;Cardinality=$r.Cardinality;Types=$types;Description=[string]$r.CategoryDescription;Tags=@{}}}
  $d=$desired[$r.Category]
  if($d.Cardinality -ne $r.Cardinality -or ($d.Types -join ';') -ne ($types -join ';') -or $d.Description -cne [string]$r.CategoryDescription){throw 'Inconsistent repeated category settings.'}
  if($r.RenameFrom){$rk=$r.Category+'|'+$r.RenameFrom;if($renameKeys.ContainsKey($rk)){throw 'Duplicate rename source.'};$renameKeys[$rk]=$true}
  $d.Tags[$r.TagName]=$r
 }
 if(!$desired.Count){throw 'Zero enabled categories; refusing destructive empty keep-list.'}
 foreach($d in $desired.Values){foreach($t in $d.Tags.Values){if($t.RenameFrom -and $d.Tags.ContainsKey($t.RenameFrom)){throw 'Rename source is also a desired tag.'}}}
 if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hash){throw 'Catalog changed during load.'}
 New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
 $run=Join-Path (Resolve-Path $ReportDirectory).Path ('Catalog-RevC-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'));New-Item -ItemType Directory -Path $run | Out-Null
 [ordered]@{Action='Catalog';Mode=$Mode;Catalog=$path;SHA256=$hash;Prune=[bool]$Prune;PruneScope=$PruneScope;ManagedPrefix=$ManagedPrefix;Targets=$Targets} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $run 'run.json')
 $summary=[Collections.Generic.List[object]]::new();$failed=0
 function CLog($cat,$tag,$op,$status,$detail){[pscustomobject]@{Time=(Get-Date).ToString('o');VCenter=$name;Category=$cat;TagName=$tag;Operation=$op;Status=$status;Detail=$detail;Mode=$Mode;CatalogSHA256=$hash} | Export-Csv -LiteralPath $log -Append -NoTypeInformation -Encoding utf8}
 foreach($name in $Targets){
  $vc=$null;$issues=0;$drift=0;$changed=0;$log=Join-Path $run ($name+'-results.csv')
  try{
   try{$vc=Connect-VIServer -Server $name -VcfApiToken $Token -NotDefault -ErrorAction Stop}catch{throw 'Authentication failed; check token, federation, authorization and TLS trust.'}
   $initial=@(Get-TagCategory -Server $vc -ErrorAction Stop)
   if(@($initial | Group-Object Name | Where-Object Count -gt 1).Count){throw 'Ambiguous category names; target skipped.'}
   $snapshot=@(foreach($c in $initial){[pscustomobject]@{Name=$c.Name;Id=$c.Id;Cardinality=$c.Cardinality.ToString();EntityType=@($c.EntityType);Description=$c.Description;Tags=@(Get-Tag -Category $c -Server $vc -ErrorAction Stop | Select-Object Name,Id,Description)}})
   ConvertTo-Json -InputObject $snapshot -Depth 8 | Set-Content (Join-Path $run ($name+'-before-definitions.json'))
   foreach($d in @($desired.Values | Sort-Object Name)){
    $c=$null
    try{
     $matches=@(Get-TagCategory -Server $vc -ErrorAction Stop | Where-Object Name -eq $d.Name)
     if($matches.Count -gt 1){throw 'Ambiguous category.'}
     if(!$matches.Count){
      $drift++;CLog $d.Name '' 'CreateCategory' 'Missing' 'Required definition.'
      if($Mode -ne 'Apply'){foreach($t in $d.Tags.Values){CLog $d.Name $t.TagName 'CreateTag' 'Missing' 'Parent category absent.'};continue}
      $c=New-TagCategory -Name $d.Name -Cardinality $d.Cardinality -EntityType (ApiTypes $d.Types) -Description $d.Description -Server $vc -ErrorAction Stop;$changed++
      CLog $d.Name '' 'CreateCategory' 'Created' 'Definition only.'
     }else{$c=$matches[0]}
     $now=@(Norm $c.EntityType);$narrow=($now -contains 'All' -and $d.Types -notcontains 'All') -or ($d.Types -notcontains 'All' -and @($now | Where-Object {$_ -notin $d.Types}).Count -gt 0)
     $reverse=$c.Cardinality.ToString() -eq 'Multiple' -and $d.Cardinality -eq 'Single'
     if($narrow -or $reverse){$issues++;$drift++;CLog $d.Name '' 'Settings' 'RequiresManualCorrection' 'Narrowing/Multiple-to-Single requires recreation; no automatic recreation. Tags still processed.'}
     $sp=@{Category=$c;Server=$vc;ErrorAction='Stop'}
     if([string]$c.Description -cne $d.Description){$sp.Description=$d.Description}
     if(!$reverse -and $c.Cardinality.ToString() -ne $d.Cardinality){$sp.Cardinality=$d.Cardinality}
     if(!$narrow){$add=@($d.Types | Where-Object {$_ -notin $now});if($add.Count){$sp.AddEntityType=ApiTypes $add}}
     if($sp.Count -gt 3){$drift++;if($Mode -eq 'Apply'){Set-TagCategory @sp | Out-Null;$changed++;CLog $d.Name '' 'UpdateCategory' 'Updated' 'Safe in-place edit.'}else{CLog $d.Name '' 'UpdateCategory' 'Drift' 'Read-only.'}}
    }catch{$issues++;CLog $d.Name '' 'Category' 'Error' $_.Exception.Message;if(!$c){continue}}
    foreach($t in @($d.Tags.Values | Sort-Object TagName)){
     try{
      $tags=@(Get-Tag -Category $c -Server $vc -ErrorAction Stop);$match=@($tags | Where-Object Name -eq $t.TagName);$old=@(if($t.RenameFrom){$tags | Where-Object Name -eq $t.RenameFrom})
      if($match.Count -gt 1 -or $old.Count -gt 1 -or ($match.Count -and $old.Count)){throw 'Ambiguous tag or both rename names exist; no merge.'}
      if(!$match.Count){
       $drift++;$op=if($old.Count){'RenameTag'}else{'CreateTag'}
       if($Mode -eq 'Apply'){
        if($old.Count){Set-Tag -Tag $old[0] -Name $t.TagName -Description ([string]$t.TagDescription) -Server $vc -ErrorAction Stop | Out-Null}
        else{New-Tag -Name $t.TagName -Category $c -Description ([string]$t.TagDescription) -Server $vc -ErrorAction Stop | Out-Null}
        $check=@(Get-Tag -Category $c -Server $vc -ErrorAction Stop | Where-Object Name -eq $t.TagName);if($check.Count -ne 1){throw 'Definition verification failed.'}
        $changed++;CLog $d.Name $t.TagName $op 'Completed' 'Definition only.'
       }else{CLog $d.Name $t.TagName $op 'MissingOrRenameRequired' 'Read-only.'}
      }elseif([string]$match[0].Description -cne [string]$t.TagDescription){
       $drift++;if($Mode -eq 'Apply'){Set-Tag -Tag $match[0] -Description ([string]$t.TagDescription) -Server $vc -ErrorAction Stop | Out-Null;$changed++;CLog $d.Name $t.TagName 'UpdateTag' 'Updated' 'Description only.'}else{CLog $d.Name $t.TagName 'UpdateTag' 'Drift' 'Read-only.'}
      }else{CLog $d.Name $t.TagName 'Tag' 'Compliant' 'No change.'}
     }catch{$issues++;CLog $d.Name $t.TagName 'Tag' 'Error' $_.Exception.Message}
    }
   }
   if($Prune){
    # Do not prune a target with any creation/update ambiguity or error.
    if($issues){CLog '' '' 'Prune' 'Skipped' 'Definition processing had errors; no deletions on this target.'}
    else{
     $extras=@(Get-TagCategory -Server $vc -ErrorAction Stop | Where-Object {InBoundary $_.Name})
     foreach($c in $extras){
      if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hash){throw 'Catalog changed; pruning stopped.'}
      if($script:RevCTargetListPath -and (Get-FileHash -LiteralPath $script:RevCTargetListPath -Algorithm SHA256).Hash -ne $script:RevCTargetListHash){throw 'Target list changed; pruning stopped.'}
      if(!$desired.ContainsKey($c.Name)){
       $drift++
       try{
        CLog $c.Name '' 'DeleteCategory' $(if($Mode -eq 'Apply'){'Starting'}else{'WouldDelete'}) 'Absent from enabled catalog; deletion removes all child tags and their assignments.'
        if($Mode -eq 'Apply'){Remove-TagCategory -Category $c -Server $vc -Confirm:$false -ErrorAction Stop;$changed++;CLog $c.Name '' 'DeleteCategory' 'Deleted' 'No assignment query.'}
       }catch{$issues++;CLog $c.Name '' 'DeleteCategory' 'Error' $_.Exception.Message};continue
      }
      try{$tags=@(Get-Tag -Category $c -Server $vc -ErrorAction Stop)}catch{$issues++;CLog $c.Name '' 'ReadPruneTags' 'Error' $_.Exception.Message;continue}
      foreach($t in $tags){if(!$desired[$c.Name].Tags.ContainsKey($t.Name)){
       $drift++
       try{
        CLog $c.Name $t.Name 'DeleteTag' $(if($Mode -eq 'Apply'){'Starting'}else{'WouldDelete'}) 'Absent from enabled catalog; deletion removes its assignments.'
        if($Mode -eq 'Apply'){Remove-Tag -Tag $t -Server $vc -Confirm:$false -ErrorAction Stop;$changed++;CLog $c.Name $t.Name 'DeleteTag' 'Deleted' 'No assignment query.'}
       }catch{$issues++;CLog $c.Name $t.Name 'DeleteTag' 'Error' $_.Exception.Message}
      }}
     }
    }
   }
   if($issues -or ($Mode -eq 'Verify' -and $drift)){$failed++}
   $summary.Add([pscustomobject]@{VCenter=$name;Changed=$changed;DifferencesEncountered=$drift;Issues=$issues;Status=if($issues){'CompletedWithErrors'}elseif($Mode -eq 'Verify' -and $drift){'Drift'}else{'Completed'}})
  }catch{$failed++;CLog '' '' 'Target' 'Error' $_.Exception.Message;$summary.Add([pscustomobject]@{VCenter=$name;Changed=$changed;DifferencesEncountered=$drift;Issues=($issues+1);Status='TargetFailed'})}
  finally{if($vc){Disconnect-VIServer -Server $vc -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}}
 }
 $summary | Export-Csv (Join-Path $run 'summary.csv') -NoTypeInformation -Encoding utf8
 Write-Host "Catalog reports: $run"
 if($failed){throw "$failed target(s) had errors or Verify drift; successful changes retained. No rollback."}
}

$ErrorActionPreference='Stop';$ConfirmPreference='None'
if($Apply){if($PSBoundParameters.ContainsKey('Mode') -and $Mode -ne 'Apply'){throw 'Do not combine Apply with Plan/Verify.'};$Mode='Apply'}
if($VCenter -and $VCenterCsvPath){throw 'Choose one target or a target CSV, not both.'}
if($Action -eq 'Assignments' -and ($Prune -or $PSBoundParameters.ContainsKey('PruneScope') -or $PSBoundParameters.ContainsKey('ManagedPrefix'))){throw 'Prune options are Catalog-only, not assignment pruning.'}
if($Action -eq 'Catalog' -and ($CsvPath -or $ReplaceConflicts)){throw 'Catalog uses CatalogCsvPath, not assignment CsvPath/ReplaceConflicts.'}
if($Action -eq 'Assignments' -and (!$CsvPath -or $CatalogCsvPath)){throw 'Assignments requires CsvPath and does not use CatalogCsvPath.'}
if($Action -eq 'Catalog' -and (!$CatalogCsvPath -or (!$VCenter -and !$VCenterCsvPath))){throw 'Catalog requires CatalogCsvPath and a target or target list.'}
if($Prune -and $PruneScope -eq 'Prefix' -and [string]::IsNullOrWhiteSpace($ManagedPrefix)){throw 'Prune prefix cannot be empty; use explicit PruneScope All for all categories.'}
if($Unattended -and !$ApiToken){throw 'Unattended requires ApiToken SecureString from your secret provider; no token prompt.'}
Import-Module VMware.VimAutomation.Core -ErrorAction Stop
if(!(Get-Command Connect-VIServer).Parameters.ContainsKey('VcfApiToken')){throw 'Compatible VCF PowerCLI with VcfApiToken support required.'}
$owned=$false
try{
 if(!$ApiToken){$ApiToken=Read-Host 'VCF SSO API token reused across selected vCenters (hidden)' -AsSecureString;$owned=$true}
 if(!$ApiToken.Length){throw 'Empty token.'}
 if($Action -eq 'Assignments'){
  $a=@{Action='Assignments';CsvPath=$CsvPath;Mode=$Mode;ApiToken=$ApiToken;ReplaceConflicts=$ReplaceConflicts;ReportDirectory=$ReportDirectory}
  if($VCenter){$a.VCenter=$VCenter};if($VCenterCsvPath){$a.VCenterCsvPath=$VCenterCsvPath}
  Invoke-NameAssignments @a
 }else{
  $targets=@()
  if($VCenter){$targets=@($VCenter)}else{
   $script:RevCTargetListPath=(Resolve-Path -LiteralPath $VCenterCsvPath).Path;$script:RevCTargetListHash=(Get-FileHash -LiteralPath $script:RevCTargetListPath -Algorithm SHA256).Hash
   $list=@(Import-Csv -LiteralPath $script:RevCTargetListPath);$seen=@{}
   if(!$list.Count -or $list[0].PSObject.Properties.Name -notcontains 'VCenter'){throw 'Target CSV needs VCenter column.'}
   $targets=@(foreach($t in $list){
    if(!$t.VCenter -or $seen.ContainsKey($t.VCenter)){throw 'Blank or duplicate target.'};$seen[$t.VCenter]=$true
    if($t.PSObject.Properties.Name -contains 'Enabled'){if($t.Enabled -notin @('true','false')){throw 'Enabled must be true/false.'};if($t.Enabled -eq 'false'){continue}}
    $t.VCenter
   })
  }
  if(!$targets.Count){throw 'No enabled targets.'}
  foreach($n in $targets){if($n -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$'){throw 'Invalid target hostname.'}}
  Invoke-DefinitionCatalog -Path $CatalogCsvPath -Targets $targets -Token $ApiToken
 }
}finally{if($owned -and $ApiToken){$ApiToken.Dispose()}}
