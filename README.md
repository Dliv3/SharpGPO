# SharpGPO

SharpGPOAbuse is a Red Team tool written in C# that can be used to remotely manipulate Group Policy Object (GPO), Organizational Unit (OU), GPLink and Security Filtering.

## Usage

```
Usage:
    SharpGPO.exe --Action <Action> <Options>
        
    Actions:
        --Action
            GetOU                     List all OUs.
            NewOU                     Create an new OU.
            RemoveOU                  Remove an OU.
            MoveObject                Move an AD Object to an OU / Remove an AD Object from an OU.
            GetGPO                    List all names and GUIDs of GPOs.
            NewGPO                    Create a new GPO.
            RemoveGPO                 Delete the GPO.
            GetGPLink                 List all gPLinks of domain, ou and sites.
            NewGPLink                 Create a new GpLink.
            RemoveGPLink              Delete the GpLink from OU.
            GetSecurityFiltering      List security filterings of the target GPO.
            NewSecurityFiltering      Create a new security filtering.
            RemoveSecurityFiltering   Delete the security filtering from GPO.

    Options:
        --DomainController            Set ip/hostname of the domain controller.
        --Domain                      Set the target domain FQDN (e.g test.com).
        --OUName                      Set an OU name.
        --GPOName                     Set a GPO name.
        --GUID                        Set the GUID of the GPO.
        --DN                          Distinguished name of the target OU, domain or sites (e.g CN=IT Support,DC=testad,DC=com).
        --SrcDN                       Distinguished name of an AD Object, used by MoveObject.
        --DstDN                       Distinguished name of an AD Object, used by MoveObject.
        --BaseDN                      Distinguished name of an AD Object, used by NewOU.
        --DomainGroup                 Domain group name.
        --DomainUser                  Domain user name.
        --DomainComputer              Domain computer name.
        --NTAccount                   NtAccount name.
        -h/--Help                     Display help menu.
```

## Examples 

### Manipulate Organizational Unit (OU)

```
SharpGpo.exe --Action GetOU
SharpGpo.exe --Action GetOU --OUName "IT Support"

SharpGpo.exe --Action NewOU --OUName "IT Support"
SharpGpo.exe --Action NewOU --OUName "App Dev" --BaseDN "OU=IT Support,DC=testad,DC=com"

SharpGpo.exe --Action MoveObject --SrcDN "CN=user01,CN=Users,DC=testad,DC=com" --DstDN "OU=IT Support,DC=testad,DC=com"
SharpGpo.exe --Action MoveObject --SrcDN "CN=user01,OU=IT Support,DC=testad,DC=com" --DstDN "CN=Users,DC=testad,DC=com"

SharpGpo.exe --Action RemoveOU --OUName "IT Support"
SharpGpo.exe --Action RemoveOU --DN "OU=IT Support,DC=testad,DC=com"
```

### Manipulate Group Policy Object (GPO)

```
SharpGpo.exe --Action GetGPO
SharpGpo.exe --Action GetGPO --GPOName testgpo

SharpGpo.exe --Action NewGPO --GPOName testgpo

SharpGpo.exe --Action RemoveGPO --GPOName testgpo
SharpGpo.exe --Action RemoveGPO --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8
```

### Manipulate GPLink

```
SharpGpo.exe --Action GetGPLink
SharpGpo.exe --Action GetGPLink --DN "OU=IT Support,DC=testad,DC=com"
SharpGpo.exe --Action GetGPLink --GPOName testgpo
SharpGpo.exe --Action GetGPLink --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8

SharpGpo.exe --Action NewGPLink --DN "OU=IT Support,DC=testad,DC=com" --GPOName testgpo
SharpGpo.exe --Action NewGPLink --DN "OU=IT Support,DC=testad,DC=com" --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8

SharpGpo.exe --Action RemoveGPLink --DN "OU=IT Support,DC=testad,DC=com" --GPOName testgpo
SharpGpo.exe --Action RemoveGPLink --DN "OU=IT Support,DC=testad,DC=com" --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8
```

### Manipulate Security Filtering

```
SharpGpo.exe --Action GetSecurityFiltering --GPOName testgpo
SharpGpo.exe --Action GetSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8

SharpGpo.exe --Action NewSecurityFiltering --GPOName testgpo --DomainUser Alice
SharpGpo.exe --Action NewSecurityFiltering --GPOName testgpo --DomainGroup "Domain Users"
SharpGpo.exe --Action NewSecurityFiltering --GPOName testgpo --DomainComputer WIN-SERVER
SharpGpo.exe --Action NewSecurityFiltering --GPOName testgpo --NTAccount "Authenticated Users"
SharpGpo.exe --Action NewSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainUser Alice
SharpGpo.exe --Action NewSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainGroup "Domain Users"
SharpGpo.exe --Action NewSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainComputer WIN-SERVER
SharpGpo.exe --Action NewSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --NTAccount "Authenticated Users"

SharpGpo.exe --Action RemoveSecurityFiltering --GPOName testgpo --DomainUser Alice
SharpGpo.exe --Action RemoveSecurityFiltering --GPOName testgpo --DomainGroup "Domain Users"
SharpGpo.exe --Action RemoveSecurityFiltering --GPOName testgpo --DomainComputer WIN-SERVER
SharpGpo.exe --Action RemoveSecurityFiltering --GPOName testgpo --NTAccount "Authenticated Users"
SharpGpo.exe --Action RemoveSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainUser Alice
SharpGpo.exe --Action RemoveSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainGroup "Domain Users"
SharpGpo.exe --Action RemoveSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainComputer WIN-SERVER
SharpGpo.exe --Action RemoveSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --NTAccount "Authenticated Users"
```

## Build

Merge the SharpGPO.exe and the CommandLine.dll into one executable file

```powershell
.\ILMerge.exe /out:Z:\exps\SharpGPO.exe Z:\exps\SharpGPO\SharpGPO\bin\Release\SharpGPO.exe Z:\exps\SharpGPO\SharpGPO\bin\Release\CommandLine.dll
```