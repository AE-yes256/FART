<#
.Synopsis
A function used to export all NSGs rules in all your Azure Subscriptions

.DESCRIPTION
# PowerShell function perform NSG Review

.Notes
Created   : 02-September-2022
Updated   : 14-November-2023
Version   : 2
Author    : Sam Greaves
Disclaimer: This script is provided "AS IS" with no warranties.
#>
Function Get-AzNSGReview {
    [cmdletbinding()]
    Param (
        [switch]$All, 
        [switch]$SelectSub, 
        [switch]$HitCount,  # Add this line
        [string]$Output
    )
    # End of Parameters

    Process {
        if (-not (Get-AzContext)) {
            Connect-AzAccount -TenantId XXXXXXXXXXXXXXXXXXXXXXXXXXXX
        }
        $sub = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        Set-AzContext -Subscription $sub | Out-Null
        $outputarray = @()

        $workspaceName = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        $workspaceRG = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        $WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID

        function get-hitcount ($rule, $nsName) {
            $query = "AzureNetworkAnalytics_CL 
    | where TimeGenerated > ago(15d)
    | where SubType_s == `"FlowLog`"
    | where NSGRule_s contains `"$rule`"
    | where NSGList_s endswith `"$nsName`"
    | summarize count()
    "
            $kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query
            $kqlQuery.Results | Select-Object -ExpandProperty count_

        }

        $counter = 0
        if ($All) {
            Clear-Host "All selected to export all NSG's to review all subscriptions you can access"
            $azSubs = Get-AzSubscription
            foreach ( $azSub in $azSubs ) {
                $counter++
                Write-Progress -Activity "Gathering NSG's for "$azSub.Name"" -CurrentOperation $azSub -PercentComplete (($counter / $azSubs.count) * 100)
                Set-AzContext -Subscription $azSub | Out-Null
                $azSubName = $azSub.Name
                $azNewSubName = $azSubName -replace '(\W)', '_'
                $azNsgs = Get-AzNetworkSecurityGroup
                $azNsgs = Get-AzNetworkSecurityGroup
                foreach ( $azNsg in $azNsgs ) {
                    $attachedSubnets = $azNsg.Subnets.Id | ForEach-Object { ($_ -split '/')[-1] }
                    $attachedNics = $azNsg.NetworkInterfaces.Id | ForEach-Object { ($_ -split '/')[-1] }
                    # Export custom rules
                    $CustomNSGRules = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg
                    foreach ( $rule in $CustomNSGRules ) {
                        $CustomRules = [ordered]@{
                            'NSG Name'               = $azNsg.Name | Out-String
                            'NSG Location'           = $azNsg.Location | Out-String
                            'Rule Name'              = $rule.Name | Out-String
                            'Source'                 = $rule.SourceAddressPrefix | Out-String
                            'Source Port Range'      = $rule.SourcePortRange | Out-String
                            'Access'                 = $rule.Access | Out-String
                            'Priority'               = $rule.Priority | Out-String 
                            'Direction'              = $rule.Direction | Out-String
                            'Destination'            = $rule.DestinationAddressPrefix | Out-String
                            'Destination Port Range' = $rule.DestinationPortRange | Out-String
                            'Resource Group Name'    = $azNsg.ResourceGroupName | Out-String
                            'Hit Count'              = if ($HitCount) { get-hitcount $rule.Name $azNsg.Name } else { $null }
                            'Attached Subnet(s)'     = $attachedSubnets | Out-String
                            'Attached nic(s)'        = $attachedNics | Out-String

                        }
                        $customrulesobj = new-object -Type PSObject -Property $CustomRules
                        $outputarray += $customrulesobj
                    }# EO Foreach


                    $DefaultNSGRules = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg -Defaultrules
                    foreach ( $rule in $DefaultNSGRules ) {
                        $CustomRules = [ordered]@{
                            'NSG Name'               = $azNsg.Name | Out-String
                            'NSG Location'           = $azNsg.Location | Out-String
                            'Rule Name'              = $rule.Name | Out-String
                            'Source'                 = $rule.SourceAddressPrefix | Out-String
                            'Source Port Range'      = $rule.SourcePortRange | Out-String
                            'Access'                 = $rule.Access | Out-String
                            'Priority'               = $rule.Priority | Out-String 
                            'Direction'              = $rule.Direction | Out-String
                            'Destination'            = $rule.DestinationAddressPrefix | Out-String
                            'Destination Port Range' = $rule.DestinationPortRange | Out-String
                            'Resource Group Name'    = $azNsg.ResourceGroupName | Out-String
                            'Hit Count'              = if ($HitCount) { get-hitcount $rule.Name $azNsg.Name } else { $null }
                            'Attached Subnet(s)'     = $attachedSubnets | Out-String
                            'Attached nic(s)'        = $attachedNics | Out-String
                        }
                        $customrulesobj = new-object -Type PSObject -Property $CustomRules
                        $outputarray += $customrulesobj
                    }# EO Foreach
                }# EO Foreach
            }#EO Foreach
        }#EO If
        if ($SelectSub) {
            $azSubs = Get-AzSubscription
            Clear-Host "-SelectSub selected to export a particular sub's NSG's to. Please make a selection from the below list of subs..."
            Write-Output ($azSubs | Format-Table | Out-String)
            $sub = Read-Host "Please enter Target Sub ID"
            # Validate the input to ensure it's a valid subscription ID
            while (-not ($azSubs.SubscriptionId -contains $sub)) {
                Write-Warning "Invalid subscription ID. Please enter a valid Subscription ID."
                $sub = Read-Host "Please enter Target Sub ID"
            }
            Write-Output "$sub, selected"
            Set-AzContext -Subscription $sub | Out-Null
            Set-AzContext -Subscription $sub | Out-Null
            $Subactual = Get-AzSubscription -SubscriptionId $sub
            $azSubName = $Subactual.Name
            $azNewSubName = $azSubName -replace '(\W)', '_'
            $azNsgs = Get-AzNetworkSecurityGroup   
            foreach ( $azNsg in $azNsgs ) {
                $counter++
                Write-Progress -Activity "Gathering NSG's for "$azSubName"" -CurrentOperation $azNsg -PercentComplete (($counter / $azNsgs.count) * 100)
                $attachedSubnets = $azNsg.Subnets.Id | ForEach-Object { ($_ -split '/')[-1] }
                $attachedNics = $azNsg.NetworkInterfaces.Id | ForEach-Object { ($_ -split '/')[-1] }
                # Export custom rules
                $CustomNSGRules = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg
                foreach ( $rule in $CustomNSGRules ) {
                    $CustomRules = [ordered]@{
                        'NSG Name'               = $azNsg.Name | Out-String
                        'NSG Location'           = $azNsg.Location | Out-String
                        'Rule Name'              = $rule.Name | Out-String
                        'Source'                 = $rule.SourceAddressPrefix | Out-String
                        'Source Port Range'      = $rule.SourcePortRange | Out-String
                        'Access'                 = $rule.Access | Out-String
                        'Priority'               = $rule.Priority | Out-String 
                        'Direction'              = $rule.Direction | Out-String
                        'Destination'            = $rule.DestinationAddressPrefix | Out-String
                        'Destination Port Range' = $rule.DestinationPortRange | Out-String
                        'Resource Group Name'    = $azNsg.ResourceGroupName | Out-String
                        'Hit Count'              = if ($HitCount) { get-hitcount $rule.Name $azNsg.Name } else { $null }
                        'Attached Subnet(s)'     = $attachedSubnets | Out-String
                        'Attached nic(s)'        = $attachedNics | Out-String
                
                
                    }
                    $customrulesobj = new-object -Type PSObject -Property $CustomRules
                    $outputarray += $customrulesobj
                }# EO Foreach
                
                
                $DefaultNSGRules = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg -Defaultrules
                foreach ( $rule in $DefaultNSGRules ) {
                    $CustomRules = [ordered]@{
                        'NSG Name'               = $azNsg.Name | Out-String
                        'NSG Location'           = $azNsg.Location | Out-String
                        'Rule Name'              = $rule.Name | Out-String
                        'Source'                 = $rule.SourceAddressPrefix | Out-String
                        'Source Port Range'      = $rule.SourcePortRange | Out-String
                        'Access'                 = $rule.Access | Out-String
                        'Priority'               = $rule.Priority | Out-String 
                        'Direction'              = $rule.Direction | Out-String
                        'Destination'            = $rule.DestinationAddressPrefix | Out-String
                        'Destination Port Range' = $rule.DestinationPortRange | Out-String
                        'Resource Group Name'    = $azNsg.ResourceGroupName | Out-String
                        'Hit Count'              = if ($HitCount) { get-hitcount $rule.Name $azNsg.Name } else { $null }
                        'Attached Subnet(s)'     = $attachedSubnets | Out-String
                        'Attached nic(s)'        = $attachedNics | Out-String
                    }
                    $customrulesobj = new-object -Type PSObject -Property $CustomRules
                    $outputarray += $customrulesobj
                }# EO Foreach
                
                   
            }
        } #End of IF
        $outputarray | Export-Csv  -Path "$($home)\$azNewSubName-nsg-rules.csv" -NoTypeInformation -Append -Encoding UTF8 -Force
    }#EO Process
}#EO Function
