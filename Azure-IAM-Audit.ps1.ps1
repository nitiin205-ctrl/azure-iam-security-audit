# Azure IAM Security Audit Tool
# Author: NITIN TIWARI
# Run as: Connect-AzAccount with Global Admin or PIM activated

Write-Host "Azure IAM Security Audit Starting..." -ForegroundColor Cyan

# Require Az modules
Import-Module Az.Accounts -ErrorAction SilentlyContinue
Import-Module Az.Resources -ErrorAction SilentlyContinue

if (!(Get-AzContext)) {
    Connect-AzAccount}

$report = @()

# 1. Classic Administrators
Write-Host "Checking Classic Administrators..." -ForegroundColor Yellow
$classic = Get-AzRoleAssignment -IncludeClassicAdministrators | Where-Object {$_.Scope -eq "/" -and $_.SignInName}
foreach ($c in $classic) {
    $report += [PSCustomObject]@{
        Check = "Classic Administrator"
        User = $c.SignInName
        Role = $c.RoleDefinitionName
        Risk = "HIGH - Classic admins bypass PIM & MFA enforcement"
    }
}

# 2. Global Administrators & other dangerous roles
$dangerRoles = @("Global Administrator", "Privileged Role Administrator", "User Administrator", "Authentication Administrator")
Write-Host "Checking PIM Eligible & Permanent high privilege roles..." -ForegroundColor Yellow

foreach ($roleName in $dangerRoles) {
    $roleId = (Get-AzRoleDefinition -Name $roleName).Id
    $assignments = Get-AzRoleAssignment -RoleDefinitionId $roleId

    foreach ($a in $assignments) {
        $pimStatus = if($a.RoleEligibilityScheduleId) { "PIM Eligible" } else { "Permanent" }
        $mfa = "Unknown"
        if($a.ObjectType -eq "User") {
            $user = Get-AzADUser -ObjectId $a.ObjectId
            $mfa = (Get-AzADUser -ObjectId $a.ObjectId).StrongAuthenticationMethods.Count -gt 0 ? "Enabled" : "Disabled"
        }

        $report += [PSCustomObject]@{
            Check = "High Privilege Role"
            UserSP = $a.DisplayName
            Email = $a.SignInName
            Role = $roleName
            Scope = $a.Scope
            AssignmentType = $pimStatus
            MFA = $mfa
            Risk = if($pimStatus -eq "Permanent") {"CRITICAL"} else {"Medium"}
        }
    }
}

# 3. Subscription Owners
Write-Host "Checking Subscription Owners..." -ForegroundColor Yellow
$subs = Get-AzSubscription
foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    $owners = Get-AzRoleAssignment -RoleDefinitionName "Owner" -Scope "/subscriptions/$($sub.Id)"
    foreach ($o in $owners) {
        $report += [PSCustomObject]@{
            Check = "Subscription Owner"
            UserSP = $o.DisplayName
            Email = $o.SignInName
            Subscription = $sub.Name
            Risk = "HIGH"
        }
    }
}

# 4. Service Principals with Owner/Contributor at root scope
Write-Host "Checking dangerous Service Principals..." -ForegroundColor Yellow
$sps = Get-AzADServicePrincipal | Where-Object {$_.AppRoleAssignmentRequired -eq $false}
foreach ($sp in $sps) {
    $spAssignments = Get-AzRoleAssignment -ObjectId $sp.Id | Where-Object {$_.RoleDefinitionName -in ("Owner","Contributor") -and $_.Scope -eq "/"}
    if ($spAssignments) {
        $report += [PSCustomObject]@{
            Check = "Dangerous SPN at Root"
            UserSP = $sp.DisplayName
            AppId = $sp.AppId
            Role = $spAssignments.RoleDefinitionName
            Scope = "/"
            Risk = "CRITICAL"
        }
    }
}

# Final Report
$report | Format-Table -AutoSize
$report | Export-Csv -Path "Azure-IAM-Audit-Report-$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation

Write-Host "`nReport saved as CSV bhi ho gaya!" -ForegroundColor Green