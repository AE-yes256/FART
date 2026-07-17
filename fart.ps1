<#
.SYNOPSIS
Exports all NSG rules (custom + default) across one or all Azure subscriptions,
optionally enriched with per-rule hit counts from NSG rule-counter diagnostics.

.DESCRIPTION
Produces one record per NSG rule with source/destination, ports, priority,
attached subnets/NICs, and (optionally) a hit count derived from the
NetworkSecurityGroupRuleCounter category in AzureDiagnostics. Also flags
whether each NSG is actually sending those diagnostics to the workspace, so a
zero hit count can be distinguished from an unmonitored NSG. Emits objects to
the pipeline; use -OutputPath to also write a CSV.

.PARAMETER All
Review every enabled subscription the current identity can access.

.PARAMETER SubscriptionId
Review a single subscription. If omitted (and -All not set), you'll be
prompted with a list.

.PARAMETER HitCount
Enrich each rule with a hit count from NSG rule-counter diagnostics feeding
the specified Log Analytics workspace.

.PARAMETER OutputPath
Optional CSV path. Defaults to pipeline output only.

.EXAMPLE
Get-AzNSGReview -All -HitCount -OutputPath "$home\nsg-review.csv"

.NOTES
Created   : 02-September-2022
Updated   : 17-July-2026
Version   : 4
Author    : Sam Greaves
Disclaimer: Provided "AS IS" with no warranties.
#>
function Get-AzNSGReview {
    [CmdletBinding(DefaultParameterSetName = 'Select')]
    param (
        [Parameter(ParameterSetName = 'All', Mandatory)]
        [switch]$All,

        [Parameter(ParameterSetName = 'Select', Position = 0)]
        [string]$SubscriptionId,

        [switch]$HitCount,

        [string]$TenantId,

        # Log Analytics workspace receiving NSG rule-counter diagnostics
        [string]$WorkspaceName,
        [string]$WorkspaceResourceGroup =,
        [string]$WorkspaceSubscriptionId = 'XXXXXXX',

        [ValidateRange(1, 90)]
        [int]$HitCountDays = 15,

        [string]$OutputPath
    )

    begin {
        if (-not (Get-AzContext)) {
            $connectParams = @{}
            if ($TenantId) { $connectParams.TenantId = $TenantId }
            Connect-AzAccount @connectParams | Out-Null
        }

        # Resolve workspace ID (customer GUID) and full ARM ID once, up front.
        $workspaceId = $null
        $workspaceResourceId = $null
        if ($HitCount) {
            if ($WorkspaceSubscriptionId) {
                Set-AzContext -Subscription $WorkspaceSubscriptionId | Out-Null
            }
            $ws = Get-AzOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $WorkspaceResourceGroup
            $workspaceId = $ws.CustomerId
            $workspaceResourceId = $ws.ResourceId
            if (-not $workspaceId) {
                throw "Could not resolve workspace '$WorkspaceName' in RG '$WorkspaceResourceGroup'."
            }
        }
    }

    process {
        # --- Helpers -------------------------------------------------------

        # One KQL query per NSG — returns a lookup of normalized rule name -> hits,
        # from the NetworkSecurityGroupRuleCounter category in AzureDiagnostics.
        function Get-NsgRuleHitMap {
            param ([string]$NsgName)
            $query = @"
AzureDiagnostics
| where TimeGenerated >= ago(${HitCountDays}d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where Resource == "$($NsgName.ToUpper())"
| summarize Hits = sum(matchedConnections_d) by ruleName_s
"@
            $map = @{}
            try {
                $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $query -ErrorAction Stop
                foreach ($row in $result.Results) {
                    if ([string]::IsNullOrWhiteSpace($row.ruleName_s)) { continue }
                    # Rule-counter names are prefixed 'UserRule_<n>' / 'DefaultRule_<n>';
                    # the actual NSG rule name has no prefix. Strip it before keying.
                    $name = $row.ruleName_s -replace '^(UserRule_|DefaultRule_)', ''
                    $k = ($name.ToLower() -replace '[^a-z0-9_]', '')
                    $hits = if ($null -eq $row.Hits) { 0 } else { [int64][math]::Round([double]$row.Hits) }
                    $map[$k] = $hits
                }
            }
            catch {
                Write-Warning "Hit-count query failed for NSG '$NsgName': $_"
            }
            return $map
        }

        # Returns $true if the NSG has a diagnostic setting shipping the
        # NetworkSecurityGroupRuleCounter category to our workspace, $false if
        # not, or $null if the status can't be determined.
        function Test-NsgRuleCounterEnabled {
            param ($Nsg)
            try {
                $settings = Get-AzDiagnosticSetting -ResourceId $Nsg.Id -ErrorAction Stop
                foreach ($s in $settings) {
                    # Must target our workspace...
                    if ($workspaceResourceId -and $s.WorkspaceId -ne $workspaceResourceId) { continue }
                    # ...and have the rule-counter log category enabled.
                    $ruleLog = $s.Log | Where-Object {
                        $_.Category -eq 'NetworkSecurityGroupRuleCounter' -and $_.Enabled
                    }
                    if ($ruleLog) { return $true }
                }
                return $false
            }
            catch {
                Write-Verbose "Diagnostic-setting check failed for '$($Nsg.Name)': $_"
                return $null
            }
        }

        # Flattens one rule into a report record
        function ConvertTo-RuleRecord {
            param ($Nsg, $Rule, [bool]$IsDefault, [string]$SubName, [hashtable]$HitMap, $Monitored)

            $hits = $null
            if ($HitCount) {
                if ($HitMap -and $HitMap.Count -gt 0) {
                    # We have data for this NSG - a miss here is a genuine zero.
                    $key = ($Rule.Name.ToLower() -replace '[^a-z0-9_]', '')
                    $hits = if ($HitMap.ContainsKey($key)) { $HitMap[$key] } else { 0 }
                }
                elseif ($Monitored -eq $false) {
                    $hits = 'N/A - diagnostics not enabled'
                }
                elseif ($Monitored -eq $true) {
                    # Monitored but no records in the window - genuinely idle.
                    $hits = 0
                }
                else {
                    # Couldn't confirm monitoring status.
                    $hits = 'Unknown - status check failed'
                }
            }

            [PSCustomObject][ordered]@{
                'Subscription'           = $SubName
                'Resource Group Name'    = $Nsg.ResourceGroupName
                'NSG Name'               = $Nsg.Name
                'NSG Location'           = $Nsg.Location
                'Rule Name'              = $Rule.Name
                'Rule Type'              = $(if ($IsDefault) { 'Default' } else { 'Custom' })
                'Priority'               = $Rule.Priority
                'Direction'              = $Rule.Direction
                'Access'                 = $Rule.Access
                'Source'                 = ($Rule.SourceAddressPrefix -join ', ')
                'Source Port Range'      = ($Rule.SourcePortRange -join ', ')
                'Destination'            = ($Rule.DestinationAddressPrefix -join ', ')
                'Destination Port Range' = ($Rule.DestinationPortRange -join ', ')
                'Hit Count'              = $hits
                'Monitoring'             = $(
                    if (-not $HitCount) { 'Not checked' }
                    elseif ($Monitored -eq $true) { 'Rule counter enabled' }
                    elseif ($Monitored -eq $false) { 'NOT MONITORED' }
                    elseif ($HitMap -and $HitMap.Count -gt 0) { 'Rule counter enabled' }
                    else { 'Status unknown' }
                )
                'Attached Subnet(s)'     = (($Nsg.Subnets.Id           | ForEach-Object { ($_ -split '/')[-1] }) -join ', ')
                'Attached NIC(s)'        = (($Nsg.NetworkInterfaces.Id | ForEach-Object { ($_ -split '/')[-1] }) -join ', ')
            }
        }

        # Processes every NSG in the *current* subscription context
        function Export-SubscriptionNsgRules {
            param ([string]$SubName, [System.Collections.Generic.List[object]]$Sink)

            $nsgs = Get-AzNetworkSecurityGroup
            $i = 0
            foreach ($nsg in $nsgs) {
                $i++
                Write-Progress -Activity "Gathering NSGs in '$SubName'" `
                    -Status $nsg.Name `
                    -PercentComplete (($i / [math]::Max($nsgs.Count, 1)) * 100)

                $hitMap = if ($HitCount) { Get-NsgRuleHitMap -NsgName $nsg.Name } else { $null }
                $monitored = if ($HitCount) { Test-NsgRuleCounterEnabled -Nsg $nsg } else { $null }
                if ($HitCount) {
                    Write-Verbose ("NSG '{0}': hit-map {1} rule(s), rule counter enabled = {2}" -f `
                            $nsg.Name, $hitMap.Count, $monitored)
                }

                foreach ($rule in (Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg)) {
                    $Sink.Add((ConvertTo-RuleRecord -Nsg $nsg -Rule $rule -IsDefault:$false -SubName $SubName -HitMap $hitMap -Monitored $monitored))
                }
                foreach ($rule in (Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -DefaultRules)) {
                    $Sink.Add((ConvertTo-RuleRecord -Nsg $nsg -Rule $rule -IsDefault:$true -SubName $SubName -HitMap $hitMap -Monitored $monitored))
                }
            }
            Write-Progress -Activity "Gathering NSGs in '$SubName'" -Completed
        }

        # --- Main ----------------------------------------------------------

        $results = [System.Collections.Generic.List[object]]::new()

        if ($All) {
            $subs = Get-AzSubscription | Where-Object State -eq 'Enabled'
            $c = 0
            foreach ($sub in $subs) {
                $c++
                Write-Progress -Id 1 -Activity 'Subscriptions' -Status $sub.Name `
                    -PercentComplete (($c / $subs.Count) * 100)
                try {
                    Set-AzContext -Subscription $sub.Id | Out-Null
                    Export-SubscriptionNsgRules -SubName $sub.Name -Sink $results
                }
                catch {
                    Write-Warning "Skipping subscription '$($sub.Name)': $_"
                }
            }
            Write-Progress -Id 1 -Activity 'Subscriptions' -Completed
        }
        else {
            if (-not $SubscriptionId) {
                $subs = Get-AzSubscription
                $subs | Format-Table Name, Id, State | Out-String | Write-Host
                do {
                    $SubscriptionId = Read-Host 'Enter target Subscription ID'
                    $valid = $subs.Id -contains $SubscriptionId
                    if (-not $valid) { Write-Warning 'Invalid subscription ID - try again.' }
                } until ($valid)
            }
            Set-AzContext -Subscription $SubscriptionId | Out-Null
            $subName = (Get-AzSubscription -SubscriptionId $SubscriptionId).Name
            Export-SubscriptionNsgRules -SubName $subName -Sink $results
        }

        if ($OutputPath) {
            $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Verbose "Exported $($results.Count) rules to $OutputPath"
        }

        $results
    }
}
