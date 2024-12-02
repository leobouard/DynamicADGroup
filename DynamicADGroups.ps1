#Requires -Version 5.1
#Requires -Modules @{ModuleName='ActiveDirectory';ModuleVersion='1.0.1.0'}

[CmdletBinding(SupportsShouldProcess=$True)]
Param(
    [Parameter(Mandatory=$True)][System.IO.FileInfo]$JsonFile,
    [Parameter(Mandatory=$True)][string[]]$ReportTo,
    [string]$DefaultSearchBase = (Get-ADDomain).DistinguishedName,
    [string[]]$Properties = ('CanonicalName','City','Company','Country','Department','DirectReports','EmailAddress','MemberOf','Office','Title'),
    [string]$TestRecipient,
    [string]$SmtpServer = 'smtp.contoso.com',
    [string]$FromAddress = 'noreply@contoso.com',
    [int]$LogHistory = 15
)

# Default parameter values
$PSDefaultParameterValues = @{
    'Import-Module:Verbose'            = $false
    'Remove-Variable:WhatIf'           = $false
    'Remove-Variable:ErrorAction'      = 'SilentlyContinue'
    'Get-ADGroup*:ErrorAction'         = 'Continue'
    'Add-ADGroupMember:ErrorAction'    = 'Stop'
    'Remove-ADGroupMember:ErrorAction' = 'Stop'
}

# Create log file
$JsonFileName = (Get-Item -Path $JsonFile).BaseName -replace ' ','-'
$logPath = "$PSScriptRoot\logs\DynamicADGroups_$JsonFileName`_$(Get-Date -Format 'yyyy-MM-dd-HHmmss').txt"
Start-Transcript -Path $logPath

# Remove old log files
Get-ChildItem -Path $PSScriptRoot\logs -Recurse | Where-Object {
    $_.BaseName -like "DynamicADGroups_$JsonFileName`*" -and 
    $_.Extension -eq ".txt" -and 
    $_.LastWriteTime -lt (Get-Date).AddDays(-$LogHistory)
} | Remove-Item -Force -Confirm:$false -Verbose

# Get JSON data
$data = Get-Content -Path $JsonFile -Encoding UTF8 | ConvertFrom-Json

# Get Active Directory users
try { $users = Get-ADUser -Filter * -Properties $Properties -SearchBase $DefaultSearchBase -EA Stop }
catch { Write-Error -Exception "$($_.Exception.Message)" ; exit }

# Add new properties
$data | Add-Member -MemberType 'NoteProperty' -Name 'DistinguishedName' -Value $null -Force
$data | Add-Member -MemberType 'NoteProperty' -Name 'CurrentMember' -Value $null -Force
$data | Add-Member -MemberType 'NoteProperty' -Name 'CalculatedMember' -Value $null -Force
$data | Add-Member -MemberType 'NoteProperty' -Name 'Report' -Value @() -Force

# Add new information and collect groups not found
$groupsNotFound = $data | ForEach-Object {

    # Get Active Directory group
    $groupName = $_.Group
    $group = Get-ADGroup -Filter {Name -eq $groupName -or DisplayName -eq $groupName} -Properties Members | Select-Object -First 1
    $filter = $_.Filter

    # Add information to the report
    if ($group) {

        # Current members of the group
        $currentMember = $group.Members | Get-ADObject -Properties SamAccountName | Where-Object {$_.ObjectClass -eq 'user'} | Get-ADUser -Properties $Properties

        # Add custom searchbase if needed
        if ($_.SearchBase) { $searchBase = "*,$($_.SearchBase)" }
        else { $searchBase = "*,$DefaultSearchBase" }

        # Add preset filter if needed
        $preset = switch ($_.Preset) {
            'UserWithMail'        { '$_.EmailAddress' }
            'UserEnabled'         { '$_.Enabled -eq $true' }
            'UserEnabledWithMail' { '$_.Enabled -eq $true -and $_.EmailAddress' }
            default               { '$_.objectClass' }
        }

        # Calculated members of the group
        $exceptions = $_.Exceptions
        $calculatedMember = $users | Where-Object {
            ($_.DistinguishedName -like $searchBase -and
            (Invoke-Expression $preset) -and
            (Invoke-Expression $filter)) -or 
            $_.SamAccountName -in $exceptions
        }

        # Fill the new properties
        $_.DistinguishedName = $group.DistinguishedName
        $_.CurrentMember = $currentMember | Sort-Object -Property SamAccountName
        $_.CalculatedMember = $calculatedMember | Sort-Object -Property SamAccountName

        Remove-Variable searchBase, currentMember, calculatedMember
    }
    # Report all groups that couldn't be found
    else {
        $_.Group
    }

    Remove-Variable group, filter
}

# Update group membership
$data | Where-Object {$_.Group} | ForEach-Object {

    Write-Host "Updating members of the group '$($_.Group)'"
    Write-Host "--Filter used: {$($_.Filter)}"

    $dn = $_.DistinguishedName
    $currentMember = $_.CurrentMember
    $calculatedMember = $_.CalculatedMember

    # Get all the properties needed for the report
    $filterProperties = [Regex]::Matches($_.Filter, '\$_\.\w+') | ForEach-Object { $_ -replace '\$_.','' }
    $filterProperties = $filterProperties | Where-Object {$_ -notin 'Name','Enabled','SamAccountName'}
    $reportProperties = @('Name','Enabled','SamAccountName')
    $filterProperties | Sort-Object -Unique | ForEach-Object { $reportProperties += $_ }

    # Add new members
    $addedMembers = $calculatedMember | Where-Object {$_.SamAccountName -notin $currentMember.SamAccountName}
    if ($null -ne $addedMembers) {
        $_.Report += $addedMembers | ForEach-Object {
            Write-Host "----Add $($_.SamAccountName) to group"
            Add-ADGroupMember -Identity $dn -Members $_.SamAccountName
            $_ | Select-Object $reportProperties | Select-Object *,@{N='Status';E={'<font color=008000>Added</font>'}}
        }
    }

    # Remove old members
    $removedMembers = $currentMember | Where-Object {$_.SamAccountName -notin $calculatedMember.SamAccountName}
    if ($null -ne $removedMembers) {
        $_.Report += $removedMembers | ForEach-Object {
            Write-Host "----Remove $($_.SamAccountName) from group"
            Remove-ADGroupMember -Identity $dn -Members $_.SamAccountName -Confirm:$false
            $_ | Select-Object $reportProperties | Select-Object *,@{N='Status';E={'<font color=518EC9>Removed</font>'}}
        }
    }
    
    Remove-Variable dn, currentMember, calculatedMember, filterProperties, reportProperties, addedMembers, removedMembers
}

Stop-Transcript

# Create report
if ($null -ne $data.Report -and $ReportTo) {

    [string]$content = ''
        
    # Section for groups that haven't been found
    if ($groupsNotFound) {
        $content += "<h3>Groups not found</h3><p>Here's the list of groups that couldn't be found in Active Directory using the provided name in the JSON file:<ul>"
        $groupsNotFound | ForEach-Object { $content += "<li>$_</li>" }
        $content += '</ul></p>'
    }

    # Section for added & removed members
    if ($data.Report) {
        $data | Where-Object {$_.Report} | ForEach-Object {
            $content += "<h3>$($_.Group)</h3>"
            $content += [string]($_.Report | ConvertTo-Html -Fragment)
        }
    }

    # Create HTML body
    $content = $content -replace '&lt;','<'
    $content = $content -replace '&gt;','>'
    $body = [string](Get-Content -Path "$PSScriptRoot\body.html" -Encoding UTF8)
    $body = $body -replace '{{ content }}',$content

    # Send mail message
    $mailParams = @{
        Body        = $body
        BodyAsHtml  = $True
        Encoding    = "UTF8"
        From        = $FromAddress
        Subject     = "$JsonFileName - DynamicADGroups $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        SmtpServer  = $SmtpServer
        To          = $ReportTo
    }
    if ((Test-Path -Path $logPath) -eq $true) { $mailParams.Attachments = Get-Item -Path $logPath }
    if ($TestRecipient) { $mailParams.To = $TestRecipient }
    Send-MailMessage @mailParams
}