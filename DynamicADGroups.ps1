#Requires -Version 5.1
#Requires -Modules @{ModuleName="ActiveDirectory";ModuleVersion="1.0.1.0"}

[CmdletBinding(SupportsShouldProcess=$True)]
Param(
    [Parameter(Mandatory=$True)][System.IO.FileInfo]$JsonFile,
    [Parameter(Mandatory=$True)][System.Object[]]$ReportTo,
    [System.String]$DefaultSearchBase = (Get-ADDomain).DistinguishedName,
    [System.String]$TestRecipient,
    [System.String]$SmtpServer = "smtp.contoso.com",
    [System.String]$FromAddress = "noreply@contoso.com",
    [System.Int32]$LogHistory = 15
)

begin {

    $JsonFileName = (Get-Item -Path $JsonFile).BaseName -replace ' ','-'

    $logPath = "$PSScriptRoot\logs\DynamicADGroups_$JsonFileName`_$(Get-Date -Format 'yyyy-MM-dd-HHmmss').txt"
    Start-Transcript -Path $logPath
    $PSDefaultParameterValues = @{
        "Import-Module:Verbose"            = $false
        "Remove-Variable:WhatIf"           = $false
        "Remove-Variable:ErrorAction"      = "SilentlyContinue"
        "Get-ADGroup*:ErrorAction"         = "Continue"
        "Add-ADGroupMember:ErrorAction"    = "Stop"
        "Remove-ADGroupMember:ErrorAction" = "Stop"
    }
    
    # Remove old log files
    Get-ChildItem -Path $PSScriptRoot\logs -Recurse | Where-Object {
        $_.BaseName -like "DynamicADGroups_$JsonFileName`*" -and 
        $_.Extension -eq ".txt" -and 
        $_.LastWriteTime -lt (Get-Date).AddDays(-$LogHistory)
    } | Remove-Item -Force -Confirm:$false -Verbose

    # Get all users from Active Directory
    Import-Module ActiveDirectory
    try {
        Write-Verbose -Message "Get all users from search base: '$DefaultSearchBase'"
        $allUsers = Get-ADUser -Filter * -Properties * -SearchBase $DefaultSearchBase
        Write-Verbose -Message "Accounts found: $(($allUsers | Measure-Object).Count)"
    } catch {
        Write-Error -Exception "$($_.Exception.Message)"
        exit
    }

    # Get data from JSON file
    Write-Verbose -Message "Getting data from JSON file: $JsonFile"
    $data = Get-Content -Path $JsonFile -Encoding UTF8
    Write-Verbose -Message "Convert data from JSON"
    $data = $data | ConvertFrom-Json

    $finalReport    = [System.Collections.Generic.List[PSCustomObject]]@()
    $groupsNotFound = [System.Collections.Generic.List[PSCustomObject]]@()
}

process {

    foreach ($_ in $data) {

        # Get Active Directory group
        $groupName = $_.Group
        Write-Verbose -Message "Getting Active Directory group '$($_.Group)'"
        $group = Get-ADGroup -Filter {Name -eq $groupName -or DisplayName -eq $groupName}
        if ($null -eq $group) { 
            Write-Error -Exception "Couldn't found group '$($_.Group)' in Active Directory!"
            $groupsNotFound.Add($_)
        } else {

            # Get Active Directory group members
            Write-Verbose -Message "Getting group members (direct membership only)"
            $groupMembers = (Get-ADGroup -Identity $group -Properties Members).Members | ForEach-Object { Get-ADObject $_ -Properties SamAccountName -ErrorAction SilentlyContinue }
            $groupMembers = $groupMembers | Where-Object {$_.objectClass -eq 'user'}
            Write-Verbose -Message "User members found: $(($groupMembers | Measure-Object).Count)"

            # Get all users on searchbase
            if ($_.SearchBase) { 
                if ($_.SearchBase -notlike "OU=*") {
                    $searchBase = 'OU=' + $_.SearchBase + ',' + $DefaultSearchBase
                } else {
                    $searchBase = $_.SearchBase
                }
                Write-Verbose -Message "Using custom searchbase: $searchBase"
            } else { $searchBase = $DefaultSearchBase }
            $users = $allUsers | Where-Object {$_.DistinguishedName -match $searchBase}

            # Filter out using presets
            switch ($_.Preset) {
                "Messaging"    { $users = $users | Where-Object {$_.Enabled -eq $true -and $_.EmailAddress} }
                "EnabledOnly"  { $users = $users | Where-Object {$_.Enabled -eq $true} }
                "DisabledOnly" { $users = $users | Where-Object {$_.Enabled -eq $false} }
            }

            # Filter out using the custom filter
            if ($_.Filter) {
                $filter = $_.Filter
                $users = $users | Where-Object {Invoke-Expression $filter}
                Remove-Variable filter
            }
            
            # Compare filter results vs. current group members
            $compare = [System.Collections.Generic.List[PSCustomObject]]@()

                # 1. The group is empty
                if ($null -eq $groupMembers) {
                    $users | ForEach-Object {
                        $compare.Add([PSCustomObject]@{
                            Identity     = $_.SamAccountName
                            Name         = $_.Name
                            Company      = $_.Company
                            Title        = $_.Title
                            Department   = $_.Department
                            EmailAddress = $_.EmailAddress
                            Action       = "Add"
                        })
                    }
                }

                # 2. Everyone in the group should be removed
                elseif ($null -eq $users) {
                    $groupMembers | ForEach-Object {
                        $sam    = $_.SamAccountName
                        $member = $allUsers | Where-Object {$_.SamAccountName -eq $sam}
                        $compare.Add([PSCustomObject]@{
                            Identity     = $sam
                            Name         = $member.Name
                            Company      = $member.Company
                            Title        = $member.Title
                            Department   = $member.Department
                            EmailAddress = $member.EmailAddress
                            Action       = "Remove"
                        })
                        Remove-Variable sam,member
                    }
                }

                # 3. Regular case (add & remove members)
                else {
                    Compare-Object -ReferenceObject $users.SamAccountName -DifferenceObject $groupMembers.SamAccountName -IncludeEqual | Foreach-Object { 
                        $sam    = $_.InputObject
                        $member = $allUsers | Where-Object {$_.SamAccountName -eq $sam}
                        switch ($_.SideIndicator) {
                            "==" { $action = "Keep" }
                            "=>" { $action = "Remove" }
                            "<=" { $action = "Add" }
                        }
                        $compare.Add([PSCustomObject]@{
                            Identity     = $_.InputObject
                            Name         = $member.Name
                            Company      = $member.Company
                            Title        = $member.Title
                            Department   = $member.Department
                            EmailAddress = $member.EmailAddress
                            Action       = $action
                        })
                        Remove-Variable sam,member,action
                    }
                }

            # Filter out exceptions
            if ($null -ne $_.Exceptions) {
                $exceptions = $_.Exceptions
                $compare | Where-Object {$_.Identity -in $exceptions -and $_.Action -eq "Remove"} | Foreach-Object {$_.Action = "Keep"}
                Remove-Variable exceptions
            }

            Write-Output -InputObject "Processing group $($_.Group)"
            Write-Output -InputObject ($compare | Select-Object Identity,Name,Action | Format-Table)

            # Add & remove group members
            $compare | Where-Object {$_.Action -ne "Keep"} | ForEach-Object {
                # Add members
                if ($_.Action -eq "Add") {
                    Write-Verbose -Message "Add $($_.Identity) to group $($group.Name)"
                    try { 
                        Add-ADGroupMember -Identity $group -Members $_.Identity -Confirm:$false
                        $colorHex = "008000"
                        $text     = "Added"
                    } catch {
                        Write-Error -Exception "$($_.Exception.Message)"
                        $colorHex = "ff0000"
                        $text     = "Error! Couldn't add user to group"
                    }
                }
                # Remove members
                if ($_.Action -eq "Remove") {
                    Write-Verbose -Message "Remove $($_.Identity) from group $($group.Name)"
                    try {
                        Remove-ADGroupMember -Identity $group -Members $_.Identity -Confirm:$false
                        $colorHex = "518EC9"
                        $text     = "Removed"
                    } catch {
                        Write-Error -Exception "$($_.Exception.Message)"
                        $colorHex = "ff0000"
                        $text = "Error! Couldn't remove user from group"
                    }
                }

                $_ | Add-Member -MemberType NoteProperty -Name Status -Value "<font color=$colorHex>$text</font>" -Force
                Remove-Variable colorHex,text
            }

            $compare = $compare | Select-Object @{N="Group";E={$groupName}},Name,Title,Department,EmailAddress,Status
            $count = ($compare | Where-Object {$_.Status} | Measure-Object).Count

            # Send group report
            if ($_.ReportTo -and $count -gt 0) {

                # Create mail body
                $content = @"
<h2>$groupName</h2>
<h3>Modified members</h3>
$([System.String]($compare | Where-Object {$_.Status} | Select-Object Name,Title,Department,Status | ConvertTo-Html -Fragment))
<h3>Members retained</h3>
$([System.String]($compare | Where-Object {!$_.Status} | Select-Object Name,Title,Department,@{N="Status";E={"Kept"}} | ConvertTo-Html -Fragment))
"@
                $content = $content -replace "&lt;","<"
                $content = $content -replace "&gt;",">"
                $body    = [System.String](Get-Content -Path "$PSScriptRoot\body.html" -Encoding UTF8)
                $body    = $body -replace "{{ content }}",$content

                # Send mail message
                $mailParams = @{
                    Body       = $body
                    BodyAsHtml = $True
                    Encoding   = "UTF8"
                    From       = $FromAddress
                    Subject    = "Updates to group $groupName"
                    SmtpServer = $SmtpServer
                    To         = $_.ReportTo
                }
                if ($TestRecipient) { $mailParams.To = $TestRecipient }
                Write-Verbose -Message "Send group report to $([System.String]($mailParams.To))"
                Send-MailMessage @mailParams

                Remove-Variable content,body,mailParams
            }

            $compare | Where-Object {$_.Status} | ForEach-Object { $finalReport.Add($_) }
        }
    }
}

end {

    Stop-Transcript

    if (($finalReport | Measure-Object).Count -gt 0) {

        # Create mail body
        $content = "<h2>Dynamic groups updates</h2><p>The synthesis of the processing of the JSON file by the PowerShell script 'DynamicADGroup.ps1' for the automatic populating of Active Directory groups</p>"
        if ($groupsNotFound.Count -ne 0) { 
            $content += "<h3>Groups not found</h3><p>Here's the list of groups that couldn't be found in Active Directory using the provided name in the JSON file:<ul>"
            $groupsNotFound.Group | ForEach-Object { $content += "<li>$_</li>" }
            $content += "</ul></p>"
        }
        ($finalReport | Sort-Object Group).Group | Get-Unique | Foreach-Object {
            $groupName = $_
            $content += "<h3>$groupName</h3>"
            $content += [System.String]($finalReport | Where-Object {$_.Group -eq $groupName} | Select-Object Name,EmailAddress,Title,Department,Status | ConvertTo-Html -Fragment)
            Remove-Variable groupName,description
        }
        $content = $content -replace "&lt;","<"
        $content = $content -replace "&gt;",">"
        $body = [System.String](Get-Content -Path "$PSScriptRoot\body.html" -Encoding UTF8)
        $body = $body -replace "{{ content }}",$content

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
        Write-Verbose -Message "Send final report to $([System.String]($mailParams.To))"
        Send-MailMessage @mailParams

    }

}