<#
.Synopsis
A function used to export all NSGs rules, check your Azure flow logs for hits relating to these NSG's in all your Azure Subscriptions and format them in a .csv

.DESCRIPTION
# PowerShell function perform NSG Review

.Notes
Created   : 11-October-2023
Updated   : 11-October-2023
Version   : 1.0
Author    : NoodleStorm

Replace hashed out valued '###' with your values

Disclaimer: This script is provided "AS IS" with no warranties.
#>

$sub = ###############################"
Set-AzContext -Subscription $sub | Out-Null
$outputarray = @()

$workspaceName = "###############################""
$workspaceRG = "###############################""
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
    $kqlQuery.Results
    

}

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
            'Hit Count'              = get-hitcount $rule.Name $azNsg.Name | Out-String
            'Attached Subnet(s)'     = $attachedSubnets | Out-String
            'Attached nic(s)'        = $attachedNics | Out-String


        }
        $customrulesobj = new-object -Type PSObject -Property $CustomRules
        $outputarray += $customrulesobj
    }


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
            'Hit Count'              = get-hitcount $rule.Name $azNsg.Name | Out-String
            'Attached Subnet(s)'     = $attachedSubnets | Out-String
            'Attached nic(s)'        = $attachedNics | Out-String
        }
        $customrulesobj = new-object -Type PSObject -Property $CustomRules
        $outputarray += $customrulesobj
    }

   
}
$outputarray
$outputarray | Export-Csv  -NoTypeInformation -path C:\FART.csv  -Encoding UTF8 -Force
