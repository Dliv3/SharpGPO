using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;
using CommandLine;

namespace SharpGPO
{
    class Program
    {
        static void Main(string[] args)
        {

            if (args.Length == 0)
            {
                Options.Usage();
                return;
            }

            Options options = new Options();
            if(!Parser.Default.ParseArguments(args, options))
            {
                Console.WriteLine("[-] Unknown arguments error.");
                return;
            }

            if(options.Help)
            {
                Options.Usage();
                return;
            }

            string GUID;

            try
            {
                AD ad = new AD(options.Domain, options.DomainController);
                OU ou = new OU(ad);
                GPO gpo = new GPO(ad);

                switch (options.Action.ToLower())
                {
                    case "getgpo":
                        // SharpGpo.exe --Action GetGPO
                        // SharpGpo.exe --Action GetGPO --GPOName testgpo
                        gpo.GetGPODetails(options.GPOName);
                        break;
                    case "newgpo":
                        // SharpGpo.exe --Action NewGPO --GPOName testgpo
                        // SharpGpo.exe --Action NewGPO --GPOName testgpo --Force
                        if (string.IsNullOrEmpty(options.GPOName))
                        {
                            Console.WriteLine("[-] GPOName is empty.");
                            break;
                        }
                        if(!options.Force && gpo.GetGPOByName(options.GPOName).Length !=0)
                        {
                            Console.WriteLine("[-] GPOName '{0}' exists. ", options.GPOName);
                            Console.WriteLine("[-] Still want to create a gpo named {0}? Add the --Force option", options.GPOName);
                            break;
                        }
                        gpo.NewGPO(options.GPOName);
                        break;
                    case "removegpo":
                        // SharpGpo.exe --Action RemoveGPO --GPOName testgpo
                        // SharpGpo.exe --Action RemoveGPO --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8
                        GUID = gpo.CheckAndGetGuid(options.GPOName, options.GUID);
                        if (string.IsNullOrEmpty(GUID)) break;
                        gpo.RemoveGPO(GUID);
                        break;
                    case "getgplink":
                        // SharpGpo.exe --Action GetGpLink
                        // SharpGpo.exe --Action GetGpLink --DN DC=testad,DC=com
                        // SharpGpo.exe --Action GetGpLink --GPOName testgpo
                        // SharpGpo.exe --Action GetGpLink --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8
                        if (!string.IsNullOrEmpty(options.GUID) || 
                            !string.IsNullOrEmpty(options.GPOName)) {
                            GUID = gpo.CheckAndGetGuid(options.GPOName, options.GUID);
                            if (string.IsNullOrEmpty(GUID)) break;
                            gpo.GetGpLinkByGuid(GUID);
                            break;
                        }
                        gpo.GetGpLinkByDN(options.DN);
                        break;
                    case "newgplink":
                        // SharpGpo.exe --Action NewGpLink --OU DC=testad,DC=com --GPOName testgpo
                        // SharpGpo.exe --Action NewGpLink --OU DC=testad,DC=com --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8
                        if (string.IsNullOrEmpty(options.DN))
                        {
                            Console.WriteLine("[-] OU is empty.");
                            break;
                        }
                        
                        GUID = gpo.CheckAndGetGuid(options.GPOName, options.GUID);
                        if (string.IsNullOrEmpty(GUID)) break;

                        gpo.NewGpLink(options.DN, GUID);
                        break;
                    case "removegplink":
                        // SharpGpo.exe --Action RemoveGpLink --DN DC=testad,DC=com --GPOName testgpo
                        // SharpGpo.exe --Action RemoveGpLink --DN DC=testad,DC=com --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8
                        if (string.IsNullOrEmpty(options.DN))
                        {
                            Console.WriteLine("[-] DN is empty.");
                            break;
                        }
                        GUID = gpo.CheckAndGetGuid(options.GPOName, options.GUID);
                        if (string.IsNullOrEmpty(GUID)) break;

                        gpo.RemoveGpLink(options.DN, GUID);
                        break;
                    case "getsecurityfiltering":
                        // SharpGpo.exe --Action GetSecurityFiltering --GPOName testgpo
                        // SharpGpo.exe --Action GetSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8
                        GUID = gpo.CheckAndGetGuid(options.GPOName, options.GUID);
                        if (string.IsNullOrEmpty(GUID)) break;
                        gpo.GetSecurityFiltering(GUID);
                        break;
                    case "newsecurityfiltering":
                        // SharpGpo.exe --Action NewSecurityFiltering --GPOName testgpo --DomainUser Alice
                        // SharpGpo.exe --Action NewSecurityFiltering --GPOName testgpo --DomainGroup "Domain Users"
                        // SharpGpo.exe --Action NewSecurityFiltering --GPOName testgpo --NTAccount "Authenticated Users"
                        // SharpGpo.exe --Action NewSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainUser Alice
                        // SharpGpo.exe --Action NewSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainGroup "Domain Users"
                        // SharpGpo.exe --Action NewSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --NTAccount "Authenticated Users"
                        GUID = gpo.CheckAndGetGuid(options.GPOName, options.GUID);
                        if (string.IsNullOrEmpty(GUID)) break;

                        SecurityIdentifier SID = ad.CheckAndGetSID(
                            options.DomainUser,
                            options.DomainComputer,
                            options.DomainGroup,
                            options.NTAccount
                        );
                        if (SID is null) return;

                        gpo.NewSecurityFiltering(GUID, SID);
                        break;
                    case "removesecurityfiltering":
                        // SharpGpo.exe --Action RemoveSecurityFiltering --GPOName testgpo --DomainUser Alice
                        // SharpGpo.exe --Action RemoveSecurityFiltering --GPOName testgpo --DomainGroup "Domain Users"
                        // SharpGpo.exe --Action RemoveSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainUser Alice
                        // SharpGpo.exe --Action RemoveSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --DomainGroup "Domain Users"
                        // SharpGpo.exe --sAction RemoveSecurityFiltering --GPOName testgpo --NTAccount "Authenticated Users"
                        // SharpGpo.exe --Action RemoveSecurityFiltering --GUID F3402420-8E2A-42CA-86BE-4C5594FA5BD8 --NTAccount "Authenticated Users"

                        GUID = gpo.CheckAndGetGuid(options.GPOName, options.GUID);
                        if (string.IsNullOrEmpty(GUID)) break;

                        SID = ad.CheckAndGetSID(
                            options.DomainUser,
                            options.DomainComputer,
                            options.DomainGroup,
                            options.NTAccount
                        );
                        if (SID is null) return;

                        gpo.RemoveSecurityFiltering(GUID, SID);
                        break;
                    case "getou":
                        // SharpGpo.exe --Action GetOU
                        // SharpGpo.exe --Action GetOU --OUName testou
                        ou.GetOUDetails(options.OUName);
                        break;
                    case "newou":
                        // SharpGpo.exe --Action NewOU --OUName "IT Support"
                        // SharpGpo.exe --Action NewOU --OUName "App Dev" --BaseDN "ou=IT Support,dc=xlab,dc=sec"
                        if (string.IsNullOrEmpty(options.OUName))
                        {
                            Console.WriteLine("[-] OUName is empty.");
                            break;
                        }
                        if(ou.Exists(options.OUName, options.BaseDN))
                        {
                            Console.WriteLine("[-] OUName '{0}' exists. ", options.OUName);
                            break;
                        }
                        ou.NewOU(options.OUName, options.BaseDN);
                        break;
                    case "removeou":
                        // SharpGpo.exe --Action RemveOU --DN "ou=IT Support,dc=xlab,dc=sec"
                        if (string.IsNullOrEmpty(options.DN) && string.IsNullOrEmpty(options.OUName))
                        {
                            Console.WriteLine("[-] DN is empty.");
                            break;
                        }
                        ou.RemoveOU(options.OUName, options.DN);
                        break;
                    case "moveobject":
                        // SharpGpo.exe --Action MoveObject --SrcDN "cn=user01,cn=Users,dc=xlab,dc=sec" --DstDN "ou=IT Support,dc=xlab,dc=sec"
                        // SharpGpo.exe --Action MoveObject --SrcDN "cn=user01,ou=IT Support,dc=xlab,dc=sec" --DstDN "cn=Users,dc=xlab,dc=sec"
                        ou.MoveObject(options.SrcDN, options.DstDN);
                        break;
                    default:
                        Console.WriteLine("[-] Unknown action error.");
                        break;
                }
            } catch(Exception ex)
            {
                Console.WriteLine("[-] Exception: {0}", ex);
            }

        }
    }
}
