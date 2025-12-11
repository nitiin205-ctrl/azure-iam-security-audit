# azure-iam-security-audit
Azure IAM Security Audit Tool: PowerShell script to audit high-privilege roles, classic admins, PIM, MFA status &amp; more. Export to CSV for easy review. 🔒
# Azure IAM Security Audit Tool 🔒

Ye PowerShell script Azure Active Directory (Entra ID) aur Resource Manager (RBAC) ke IAM permissions ka full security audit karta hai. High-risk configurations jaise permanent Global Admins, classic administrators, over-privileged service principals, aur subscription owners ko detect karta hai. Report CSV me export hota hai taaki Excel me analyze kar sakein.

## Why Use This? 
- **Compliance Ready**: Azure Well-Architected Framework aur CIS benchmarks ke hisab se IAM risks highlight karta hai.
- **Quick Insights**: Ek run me sab dangerous stuff list kar deta hai – no manual digging.
- **PIM & MFA Focus**: Eligible vs permanent roles check karta hai, plus rough MFA status.
- **Free & Open-Source**: Bilkul free, extend kar sakte ho apne needs ke hisab se.

## Features
- ✅ Classic Administrators (legacy, hatane chahiye – bypass PIM/MFA)
- ✅ High-Privilege Roles (Global Admin, Privileged Role Admin, User Admin etc.) – PIM eligible/permanent
- ✅ Subscription Owners/Contributors at root scope
- ✅ Dangerous Service Principals (Owner/Contributor at tenant level)
- ✅ Basic MFA Status for privileged users
- ✅ Export to CSV with Risk Levels (CRITICAL/HIGH/Medium)
- ✅ Console Output for quick scan

## Prerequisites
- PowerShell 5.1+ (Windows/Linux/macOS)
- Az PowerShell Module: `Install-Module Az -Scope CurrentUser`
- Global Admin or Privileged Role Admin access (PIM activate kar lo if needed)

## Installation
1. Clone/Download ye repo: `git clone https://github.com/tumharusername/azure-iam-security-audit.git`
2. Open PowerShell as Admin (if needed for module install).

## Usage
```powershell
# Login to Azure (Global Admin ya PIM role se)
Connect-AzAccount

# Run the script
.\Azure-IAM-Audit.ps1

# Output: Console table + CSV file (e.g., Azure-IAM-Audit-Report-20251211.csv)
