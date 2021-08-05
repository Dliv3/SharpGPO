using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace SharpGPO
{
    class AD
    {
        public string DomainName { get; set; } // domain name FQDN
        public string DomainController { get; set; } // domain controller IP/FQDN
        public string DomainDistingushedName { get; set; }
        public string CurrentDomainUser { get; set; }
        private string username;
        private string password;

        public AD(string domainName = null, string domainController = null, string username = null, string password = null)
        {
            Domain currentDomain = null;
            DomainName = domainName;
            DomainController = domainController;
            this.username = username;
            this.password = password;

            if (!string.IsNullOrEmpty(DomainController))
            {
                DirectoryContext dc = new DirectoryContext(
                    DirectoryContextType.DirectoryServer,
                    DomainController,
                    username,
                    password
                );
                currentDomain = Domain.GetDomain(dc);
            }
            else if (!string.IsNullOrEmpty(DomainName))
            {
                DirectoryContext dc = new DirectoryContext(
                    DirectoryContextType.Domain,
                    DomainName,
                    username,
                    password
                );
                currentDomain = Domain.GetDomain(dc);
            }
            else
            {
                try
                {
                    currentDomain = Domain.GetCurrentDomain();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] GetCurrentDomain Error: {0}", ex.Message);
                    Environment.Exit(0);
                }
            }

            if (string.IsNullOrEmpty(DomainController))
            {
                DomainController = currentDomain.PdcRoleOwner.Name;
            }

            if (string.IsNullOrEmpty(DomainName))
            {
                DomainName = currentDomain.Name;
            }

            string[] dc_array = DomainName.Split('.');

            foreach (string dc in dc_array)
            {
                DomainDistingushedName += ",DC=" + dc;
            }

            DomainDistingushedName = DomainDistingushedName.Trim(',');

            if(string.IsNullOrEmpty(username))
            {
                CurrentDomainUser = Environment.UserName;
            } else
            {
                CurrentDomainUser = username;
            }

            Console.WriteLine("[*] Domain: {0}", DomainName);
            Console.WriteLine("[*] Domain Contorller: {0}", DomainController);
            Console.WriteLine("[*] Domain Distingushed Name: {0}", DomainDistingushedName);
        }

        public DirectoryEntry ConnectLdap()
        {
            return new DirectoryEntry(
                $@"LDAP://{DomainController}/{DomainDistingushedName}",
                username, password, AuthenticationTypes.Secure);
        }

        public DirectoryEntry ConnectLdap(string path)
        {
            return new DirectoryEntry(
                $@"LDAP://{DomainController}/{path}",
                username, password, AuthenticationTypes.Secure);
        }

        public bool Exists(string path)
        {
            return DirectoryEntry.Exists($@"LDAP://{DomainController}/{path}");
        }

        public SecurityIdentifier GetDomainUserSID(string userName)
        {
            PrincipalContext ctx = new PrincipalContext(
                ContextType.Domain,
                DomainController,
                username,
                password
            );
            UserPrincipal user = null;
            try
            {
                user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, userName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($@"[-] GetDomainUserSID Error: {ex}");
                Environment.Exit(0);
            }
            if (user is null)
            {
                Console.WriteLine($@"[-] Could not find domain user: {userName}");
                return null;
            }
            return user.Sid;
        }

        public SecurityIdentifier GetDomainComputerSID(string computerName)
        {
            PrincipalContext ctx = new PrincipalContext(
                ContextType.Domain,
                DomainController,
                username,
                password
            );
            ComputerPrincipal computer = null;
            try
            {
                computer = ComputerPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, computerName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($@"[-] GetDomainComputerSID Error: {ex}");
                Environment.Exit(0);
            }
            if (computer is null)
            {
                Console.WriteLine($@"[-] Could not find domain computer: {computerName}");
                return null;
            }
            return computer.Sid;
        }

        public string GetSamAccountName(string sid)
        {
            DirectoryEntry users = ConnectLdap($@"CN=Users,{DomainDistingushedName}");
            DirectorySearcher searcher = new DirectorySearcher(users);
            searcher.Filter = $@"(objectSid={sid})";
            SearchResult result = searcher.FindOne();
            return result.GetDirectoryEntry().Properties["sAMAccountName"].Value.ToString();
        }

        public SecurityIdentifier GetDomainGroupSID(string groupName)
        {
            PrincipalContext ctx = new PrincipalContext(
                ContextType.Domain,
                DomainController,
                username,
                password
            );
            GroupPrincipal group = null;
            try
            {
                group = GroupPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, groupName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($@"[-] GetDomainGroupSID Error: {ex}");
                Environment.Exit(0);
            }
            if (group is null)
            {
                Console.WriteLine($@"[-] Could not find doamin group: {groupName}");
                return null;
            }
            return group.Sid;
        }

        public SecurityIdentifier CheckAndGetSID(string domainUser, string domainComputer, string domainGroup, string ntAccount)
        {
            if (string.IsNullOrEmpty(domainUser) && string.IsNullOrEmpty(domainComputer)
                && string.IsNullOrEmpty(domainGroup) && string.IsNullOrEmpty(ntAccount))
            {
                Console.WriteLine("[-] DomainUser, DomainGroup and ntAccount are empty.");
                Console.WriteLine("[+] Use --DomainUser, --DomainComputer, --DomainGroup or --NTAccount to set their values");
                return null;
            }

            if (!string.IsNullOrEmpty(domainUser))
            {
                return GetDomainUserSID(domainUser);
            }

            if (!string.IsNullOrEmpty(domainComputer))
            {
                if (!domainComputer.EndsWith("$"))
                {
                    domainComputer += "$";
                }
                return GetDomainComputerSID(domainComputer);
            }

            if (!string.IsNullOrEmpty(domainGroup))
            {
                return GetDomainGroupSID(domainGroup);
            }

            try
            {
                SecurityIdentifier ntsid = (SecurityIdentifier)((new NTAccount(ntAccount)).Translate(typeof(SecurityIdentifier)));
                return ntsid;
            }
            catch
            {
                Console.WriteLine("[-] NTAccount not found.");
                return null;
            }
        }

    }
}
