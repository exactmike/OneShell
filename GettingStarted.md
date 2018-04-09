# Getting Started With OneShell

## <a name="TOC"></a>Table Of Contents
- [Setting Up The Module](#SettingUp)
- [Importing And Using Your Connections](#ImportingAndUsing)
## <a name="SettingUp"></a>Setting Up The Module
[Back to Table of Contents](#TOC)
In order to use OneShell effectively, you'll need to have the module files stored in a place where you can import them easily. If you're already familiar with administering PowerShell Modules, you can ignore this paragraph. If you're not, perhaps the best place to put them is in %UserProfile%\Documents\WindowsPowerShell\Modules. On a vanilla Windows installation, this will be c:\users\<username>\Documents\WindowsPowerShell\Modules. The WindowsPowerShell and Modules folders will not exist. You can create them.

Once you've decided where to store the module, you can either download it by clicking the Download button or clone the repo using git. Either way, you should end up with a folder named OneShell underneath the Modules folder, and you'll be ready to go!

- To get started, open PowerShell.
- Import the module by issuing this cmdlet. If you get warnings about script signing or execution, follow the instructions provided or search the internet for the required instructions to get your computer ready to run downloaded PowerShell code. I won't re-invent the wheel by documenting those steps here.
```PowerShell
Import-Module -Name OneShell
```
- Tell OneShell Where it should store _orgnization_ profiles. This will be $env:\programdata\OneShell by default. You can add a -Path parameter to the below cmdlet if you want to store them somewhere else. By default, $env:\programdata\OneShell will still be created and will be used to tell OneShell where to find your org profiles. If you don't have Admin rights on the workstation you're installing on, you can specify -Scope User to store them in $env:localappdata\OneShell. If you do not want to persist this storage location at all, you can specify -DoNotPersist.
```PowerShell
Set-OneShellOrgProfileDirectory
```
- Tell OneShell Where it should store _admin user_ profiles. This will be $env:\localappdata\OneShell by default. You can add a -Path parameter to the below cmdlet if you want to store them somewhere else. By default, $env:\localappdata\OneShell will still be created and will be used to tell OneShell where to find your admin user profiles. If you do not want to persist this storage location at all, you can specify -DoNotPersist.
```PowerShell
Set-OneShellAdminUserProfileDirectory
```
## Creating And Populating The Org Profile

- Create an empty Organization Profile. The Org Profile is where all of your systems to be administered will be configured. The Org profile can be shared by multiple admin user profiles in one or more user accounts, so you don't have to define the same systems to be administered multiple times. 
```PowerShell
New-OrgProfile -Name DemoOrg
```
- If you'd like to see what the created profile object looks like, you can issue
```PowerShell
Get-OrgProfile -Identity DemoOrg
```
##Creating And Populating the AdminUser Profile

## <a name="ImportingAndUsing"></a>Importing And Using Your Connections
[Back to Table of Contents](#TOC)
