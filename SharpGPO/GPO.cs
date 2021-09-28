using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Net;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.SqlServer.Server;
using System.Text.RegularExpressions;
using System.Collections;

namespace SharpGPO
{
    class GPO
    {
        public AD ad;
        public string policiesDistingushedName;

        public GPO(AD ad)
        {
            this.ad = ad;
            policiesDistingushedName = $@"CN=Policies,CN=System,{ad.DomainDistingushedName}";
        }

        private string StandardizeGuid(string guid)
        {
            if (!guid.StartsWith("{"))
            {
                return "{" + guid + "}";
            }
            return guid;
        }

        private DirectoryEntry ConnectLdapPolicies()
        {
            return ad.ConnectLdap(policiesDistingushedName);
        }

        public DirectoryEntry[] GetGPOByName(string gpoName)
        {
            if (gpoName is null)
            {
                gpoName = "*";
            }
            DirectoryEntry policies = ConnectLdapPolicies();
            DirectorySearcher searcher = new DirectorySearcher(policies);
            searcher.Filter = $@"(displayName={gpoName})";
            SearchResultCollection results = searcher.FindAll();
            List<DirectoryEntry> gpos = new List<DirectoryEntry>();
            foreach (SearchResult result in results)
            {
                gpos.Add(result.GetDirectoryEntry());
            }
            return gpos.ToArray();
        }

        public DirectoryEntry[] GetGPODetails(string gpoName)
        {
            DirectoryEntry[] results = GetGPOByName(gpoName);
            if(results.Length != 0)
                Console.WriteLine("[*] --------------------------------------------------------");
            foreach (DirectoryEntry entry in results)
            {
                Console.WriteLine("[*] GPO displayName: {0}", entry.Properties["displayName"].Value);
                Console.WriteLine("[*] GPO objectGUID: {0}", entry.Properties["cn"].Value);
                Console.WriteLine("[*] --------------------------------------------------------");
            }
            return results;
        }

        public DirectoryEntry GetGPOByGuid(string guid)
        {
            guid = StandardizeGuid(guid);
            DirectoryEntry policies = ConnectLdapPolicies();
            DirectorySearcher searcher = new DirectorySearcher(policies);
            searcher.Filter = $@"(cn={guid})";
            SearchResultCollection results = searcher.FindAll();
            if(results.Count != 0)
            {
                return results[0].GetDirectoryEntry();
            }
            return null;
        }

        public string NewGPO(string name)
        {
            DirectoryEntry policies = ConnectLdapPolicies();
            DirectoryEntries childrenEntries = policies.Children;

            string guid = Guid.NewGuid().ToString("B").ToUpper();
            Console.WriteLine($@"[*] Creating GPO with GUID {guid}");

            Console.WriteLine("[*] Creating LDAP GPO Entry");
            DirectoryEntry gpcontainer = childrenEntries.Add("CN=" + guid, "groupPolicyContainer");
            gpcontainer.Properties["displayName"].Value = name;
            gpcontainer.CommitChanges();

            Console.WriteLine("[*] Creating LDAP User and Machine Sub Entries");
            DirectoryEntry machine = gpcontainer.Children.Add("CN=Machine", "container");
            machine.CommitChanges();
            DirectoryEntry user = gpcontainer.Children.Add("CN=User", "container");
            user.CommitChanges();

            Console.WriteLine("[*] Creating GPO Dir in SYSVOL");
            string GPODirectory = $@"\\{ad.DomainController}\SYSVOL\{ad.DomainName}\Policies\{guid}";

            ActiveDirectorySecurity nTSecurityDescriptor = gpcontainer.ObjectSecurity;

            // Some permission correspondences are hard-coded here
            Directory.CreateDirectory(GPODirectory);
            SetGPOPathACL(GPODirectory, nTSecurityDescriptor);

            Console.WriteLine("[*] Creating GPT.ini");
            string gptPath = $@"{GPODirectory}\GPT.ini";
            string gptContent = "[General]\r\nVersion=0\r\n";
            File.WriteAllText(gptPath, gptContent);

            Console.WriteLine("[*] Creating User and Machine Sub Dirs");
            Directory.CreateDirectory($@"{GPODirectory}\Machine");
            Directory.CreateDirectory($@"{GPODirectory}\User");

            // In addition to operations mentioned in MSDN, following operations are required here too
            gpcontainer.Properties["flags"].Value = 0;
            gpcontainer.Properties["gPCFileSysPath"].Value = GPODirectory;
            gpcontainer.Properties["versionNumber"].Value = 0;
            gpcontainer.Properties["gPCFunctionalityVersion"].Value = 2;
            gpcontainer.CommitChanges();

            return guid;
        }

        public void RemoveGPO(string guid)
        {
            guid = StandardizeGuid(guid);

            // 1. Delete the GpLink related to the GPO in LDAP
            Console.WriteLine($@"[*] Step1: Delete all gPLink related to the GPO {guid}");
            DirectoryEntry[] DNs = GetGpLinkByGuid(guid);
            foreach(var dn in DNs)
            {
                RemoveGpLink(dn.Properties["distinguishedName"].Value.ToString(), guid);
            }

            // 2. Delete GPO entry in LDAP
            Console.WriteLine($@"[*] Step2: Delete the LDAP Entry of the GPO {guid}");
            DirectoryEntry gpo = GetGPOByGuid(guid);
            gpo.DeleteTree();
            gpo.CommitChanges();

            // 3. Delete the GPO directory in the SYSVOL
            string gpoDir = $@"\\{ad.DomainController}\SYSVOL\{ad.DomainName}\Policies\{guid}";
            Console.WriteLine($@"[*] Step3: Delete GPO Dir {gpoDir}");
            DirectoryInfo gpoDirInfo = new DirectoryInfo(gpoDir);
            if (gpoDirInfo.Exists) gpoDirInfo.Delete(true);
        }

        private DirectoryEntry[] GetSites() {
            DirectoryEntry sites = ad.ConnectLdap($@"CN=Sites,CN=Configuration,{ad.DomainDistingushedName}");
            List<DirectoryEntry> sitesList = new List<DirectoryEntry>();
            foreach(DirectoryEntry site in sites.Children)
            {
                sitesList.Add(site);
            }
            return sitesList.ToArray();
        }

        // TODO
        private DirectoryEntry GetSiteByName(string siteName) {
            return null;
        }

        private Dictionary<DirectoryEntry, DirectoryEntry[]> GetGpLinks(string DN)
        {
            // key: OU
            // value: GPO
            Dictionary<DirectoryEntry, DirectoryEntry[]> links = new Dictionary<DirectoryEntry, DirectoryEntry[]>();
            if (DN is null)
            {
                // domain
                DirectoryEntry domain = ad.ConnectLdap();
                links.Add(domain, GetGPOByGpLink((string)domain.Properties["gPLink"].Value));

                // ou
                DirectoryEntry[] ous = new OU(ad).GetOU();
                foreach (DirectoryEntry ou in ous)
                {
                    links.Add(ou, GetGPOByGpLink((string)ou.Properties["gPLink"].Value));
                }

                // site
                DirectoryEntry[] sites = GetSites();
                foreach (DirectoryEntry site in sites)
                {
                    links.Add(site, GetGPOByGpLink((string)site.Properties["gPLink"].Value));
                }
            }
            else
            {
                DirectoryEntry result = ad.ConnectLdap(DN);
                try
                {
                    links.Add(result, GetGPOByGpLink((string)result.Properties["gPLink"].Value));
                }
                catch (DirectoryServicesCOMException)
                {
                    Console.WriteLine("[-] Cannot find DN: {0}", DN);
                    return null;
                }
            }
            return links;
        }

        public DirectoryEntry[] GetGpLinkByGuid(string guid)
        {
            guid = StandardizeGuid(guid);

            Dictionary<DirectoryEntry, DirectoryEntry[]> links = GetGpLinks(null);

            if (links is null) return new DirectoryEntry[0];

            List<DirectoryEntry> results = new List<DirectoryEntry>();

            Console.WriteLine("[*] GPO links to");

            foreach (var link in links)
            {
                if (link.Value.Length != 0)
                {
                    foreach (DirectoryEntry gpo in link.Value)
                    {
                        if (gpo.Properties["cn"].Value.ToString() == guid)
                        {
                            string dn = link.Key.Properties["distinguishedName"].Value.ToString();
                            string name = link.Key.Properties["name"].Value.ToString();
                            Console.WriteLine($@"[*] |-- dn: {dn}, name: {name}");
                            results.Add(link.Key);
                        }
                    }
                }
            }

            Console.WriteLine("[*] --------------------------------------------------------");

            return results.ToArray();

        }

        public void GetGpLinkByDN(string DN)
        {

            Dictionary<DirectoryEntry, DirectoryEntry[]> links = GetGpLinks(DN);

            if (links is null) return;

            foreach (var link in links)
            {
                string dn = link.Key.Properties["distinguishedName"].Value.ToString();
                
                if (link.Value.Length == 0)
                {
                    Console.WriteLine($@"[*] {dn} has no GPLink");
                } 
                else
                {
                    Console.WriteLine($@"[*] {dn} links to");
                    foreach (DirectoryEntry gpo in link.Value)
                    {
                        string GUID = gpo.Properties["cn"].Value.ToString();
                        string name = gpo.Properties["displayName"].Value.ToString();
                        Console.WriteLine($@"[*] |-- GPO GUID: {GUID}, name: {name}");
                    }
                }
                
                Console.WriteLine("[*] --------------------------------------------------------");
            }
        }

        private DirectoryEntry[] GetGPOByGpLink(string gpLink)
        {
            if (string.IsNullOrEmpty(gpLink)) return new DirectoryEntry[0];

            List<DirectoryEntry> results = new List<DirectoryEntry>();
            foreach (Match match in Regex.Matches(gpLink, @"\{.*?\}"))
            {
                DirectoryEntry gpo = GetGPOByGuid(match.Value);
                if(!(gpo is null)) {
                    results.Add(gpo);
                }
            }

            return results.ToArray();
        }

        public bool NewGpLink(string DN, string guid)
        {
            guid = StandardizeGuid(guid);

            DirectoryEntry target = ad.ConnectLdap(DN);

            Console.WriteLine($@"[*] Creating a gPLink: {DN} => GPO {guid}");
            string gPLink = "";
            try
            {
                if (target.Properties.Contains("gPLink"))
                {
                    gPLink = target.Properties["gPLink"].Value.ToString();
                    Console.WriteLine($@"[*] gPLink: {gPLink}");
                }
            } catch (DirectoryServicesCOMException ex)
            {
                Console.WriteLine("[-] OU distingushed name error: {0}", ex.Message);
                return false;
            }
            
            if (gPLink.Contains(guid))
            {
                Console.WriteLine($@"[*] gPLink to {guid} already exists");
                return false;
            }

            string newGPLink = $@"[LDAP://CN={guid},{this.policiesDistingushedName};0]{gPLink}";
            target.Properties["gPLink"].Value = newGPLink;
            target.CommitChanges();
            Console.WriteLine("[*] gPLink was successfully created");
            Console.WriteLine("[*] gPLink after created: {0}", newGPLink);
            return true;
        }

        public bool RemoveGpLink(string DN, string guid)
        {
            guid = StandardizeGuid(guid);
            DirectoryEntry target = ad.ConnectLdap(DN);

            Console.WriteLine($@"[*] Deleting the gPLink: {DN} to GPO {guid}");

            string gPLink = "";
            try
            {
                if (target.Properties.Contains("gPLink"))
                {
                    gPLink = target.Properties["gPLink"].Value.ToString();
                    Console.WriteLine($@"[*] gPLink: {gPLink}");
                }
            }
            catch (DirectoryServicesCOMException ex)
            {
                Console.WriteLine("[-] Distingushed name error: {0}", ex.Message);
                return false;
            }

            if (!gPLink.Contains(guid))
            {
                Console.WriteLine($@"[*] gPLink to {guid} not exists");
                return true;
            }

            string[] links = gPLink.Split(']');
            List<string> result = new List<string>();

            foreach(string link in links)
            {
                if (!link.Contains(guid))
                {
                    result.Add(link);
                }
            }

            string newGPLink = string.Join("]", result.ToArray());

            if(string.IsNullOrEmpty(newGPLink))
            {
                target.Properties["gpLink"].Value = null;
            } 
            else
            {
                target.Properties["gPLink"].Value = newGPLink;
            }

            target.CommitChanges();

            Console.WriteLine("[*] gPLink was successfully deleted");
            Console.WriteLine("[*] gPLink after deleted: {0}", newGPLink);

            return true;
        }

        private void PrintADSecurityDescriptor(ActiveDirectorySecurity nTSecurityDescriptor)
        {
            Console.WriteLine("[*] ========== DACL ==========");
            AuthorizationRuleCollection rules = nTSecurityDescriptor.GetAccessRules(true, false, typeof(NTAccount));
            foreach (AuthorizationRule rule in rules)
            {
                var adRule = rule as ActiveDirectoryAccessRule;
                Console.WriteLine("Access type: {0}", adRule.AccessControlType);
                Console.WriteLine("Rights: {0} {1}", adRule.ActiveDirectoryRights, (int)adRule.ActiveDirectoryRights);
                Console.WriteLine("Identity: {0}", adRule.IdentityReference.Value);
                Console.WriteLine("InheritanceType: {0}", adRule.InheritanceType);
                Console.WriteLine("");
            }
        }

        private void PrintDirectorySecurityDescripter(DirectorySecurity ds)
        {
            Console.WriteLine("[*] ========== Directory DACL ==========");
            AuthorizationRuleCollection rules = ds.GetAccessRules(true, false, typeof(NTAccount));
            foreach (AuthorizationRule rule in rules)
            {
                var fsacl = rule as FileSystemAccessRule;
                Console.WriteLine("Access type: {0}", fsacl.AccessControlType);
                Console.WriteLine("Rights: {0} {1}", fsacl.FileSystemRights, (int)fsacl.FileSystemRights);
                Console.WriteLine("Identity: {0}", fsacl.IdentityReference.Value);
                Console.WriteLine("InheritanceFlags: {0}", fsacl.InheritanceFlags);
                Console.WriteLine("");
            }
        }

        private void RemoveAllFileSystemAccessRules(DirectorySecurity ds)
        {
            AuthorizationRuleCollection rules = ds.GetAccessRules(true, true, typeof(NTAccount));
            foreach (FileSystemAccessRule rule in rules)
                ds.RemoveAccessRuleAll(rule);
        }

        public void GetSecurityFiltering(string guid)
        {
            guid = StandardizeGuid(guid);
            DirectoryEntry gpo = GetGPOByGuid(guid);
            ActiveDirectorySecurity nTSecurityDescriptor = gpo.ObjectSecurity;
            AuthorizationRuleCollection rules = nTSecurityDescriptor.GetAccessRules(true, false, typeof(NTAccount));
            Console.WriteLine($@"[*] Security Filtering:");
            foreach (AuthorizationRule rule in rules)
            {
                var adRule = rule as ActiveDirectoryAccessRule;
                if (((int)adRule.ActiveDirectoryRights & (int)ActiveDirectoryRights.ExtendedRight) ==
                    (int)ActiveDirectoryRights.ExtendedRight)
                {
                    string username = adRule.IdentityReference.Value;
                    if(username.StartsWith("S-"))
                    {
                        username = "Domain Account: " + ad.GetSamAccountName(username);
                    }
                    else
                    {
                        username = "NT Account: " + username;
                    }
                    Console.WriteLine("[*] | -- {0}", username);
                }
            }
            Console.WriteLine("[*] --------------------------------------------------------");
        }

        public void NewSecurityFiltering(string GUID, SecurityIdentifier sid)
        {
            GUID = StandardizeGuid(GUID);

            DirectoryEntry gpoContainer = ad.ConnectLdap($@"CN={GUID},{policiesDistingushedName}");

            Console.WriteLine("[*] Creating Security Filtering");
            Console.WriteLine($@"[*] GPO GUID: {GUID}");
            Console.WriteLine($@"[*] SID: {sid}");

            ActiveDirectorySecurity nTSecurityDescriptor = gpoContainer.ObjectSecurity;
            nTSecurityDescriptor.RemoveAccessRule(
                new ActiveDirectoryAccessRule(
                    new NTAccount("Authenticated Users"),
                    ActiveDirectoryRights.ExtendedRight,
                    AccessControlType.Allow,
                    ActiveDirectorySecurityInheritance.All
                )
            );
            nTSecurityDescriptor.SetAccessRule(
                new ActiveDirectoryAccessRule(
                    sid,
                    ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.GenericExecute | ActiveDirectoryRights.ExtendedRight,
                    AccessControlType.Allow
               )
            );

            gpoContainer.CommitChanges();
            string GPODirectory = $@"\\{ad.DomainController}\SYSVOL\{ad.DomainName}\Policies\{GUID}";
            SetGPOPathACL(GPODirectory, nTSecurityDescriptor);

            Console.WriteLine("[*] Security Filtering created sucessfully");
        }

        public void RemoveSecurityFiltering(string guid, SecurityIdentifier sid)
        {
            guid = StandardizeGuid(guid);
            DirectoryEntry gpo = GetGPOByGuid(guid);

            Console.WriteLine("[*] Deleteing Security Filtering");
            Console.WriteLine($@"[*] GPO GUID: {guid}");
            Console.WriteLine($@"[*] SID: {sid}");

            ActiveDirectorySecurity nTSecurityDescriptor = gpo.ObjectSecurity;

            nTSecurityDescriptor.RemoveAccessRule(
                new ActiveDirectoryAccessRule(
                    sid,
                    ActiveDirectoryRights.ExtendedRight,
                    AccessControlType.Allow
                )
            );

            gpo.CommitChanges();

            string GPODirectory = $@"\\{ad.DomainController}\SYSVOL\{ad.DomainName}\Policies\{guid}";
            SetGPOPathACL(GPODirectory, nTSecurityDescriptor);

            Console.WriteLine("[*] Deleteing Security Filtering sucessfully");

        }

        private void SetGPOPathACL(string gpoPath, ActiveDirectorySecurity nTSecurityDescriptor)
        {
            // create gpoPath if gpoPath is not exists
            DirectoryInfo dirInfo = new DirectoryInfo(gpoPath);
            DirectorySecurity dirSecurity = new DirectorySecurity();

            // disable any inherited access
            dirSecurity.SetAccessRuleProtection(true, false);

            // set owner and group
            dirSecurity.SetOwner(nTSecurityDescriptor.GetOwner(typeof(SecurityIdentifier)));
            dirSecurity.SetGroup(nTSecurityDescriptor.GetGroup(typeof(SecurityIdentifier)));

            // set DACL
            AuthorizationRuleCollection rules = nTSecurityDescriptor.GetAccessRules(true, false, typeof(NTAccount));
            foreach (AuthorizationRule rule in rules)
            {
                var adRule = rule as ActiveDirectoryAccessRule;

                // Full Control
                if ((int)adRule.ActiveDirectoryRights == 983295)
                {
                    // 983295 including the following rights
                    // CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
                    dirSecurity.SetAccessRule(
                        new FileSystemAccessRule(adRule.IdentityReference,
                            FileSystemRights.FullControl,
                            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, // avoid special permission
                            PropagationFlags.None,
                            adRule.AccessControlType
                       )
                    );
                }
                // ReadAndExecute
                else if (((int)adRule.ActiveDirectoryRights &
                    (int)(ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.GenericExecute)) ==
                    (int)(ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.GenericExecute))
                {
                    dirSecurity.SetAccessRule(
                        new FileSystemAccessRule(adRule.IdentityReference,
                            FileSystemRights.ReadAndExecute,
                            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, // avoid special permission
                            PropagationFlags.None,
                            adRule.AccessControlType
                        )
                    );
                }
                else if (adRule.ActiveDirectoryRights != ActiveDirectoryRights.ExtendedRight)
                {
                    Console.WriteLine("[-] Donot known how to map these ActiveDirectoryRights to FileSystemRights");
                    Console.WriteLine("Access type: {0}", adRule.AccessControlType);
                    Console.WriteLine("Rights: {0} {1}", adRule.ActiveDirectoryRights, (int)adRule.ActiveDirectoryRights);
                    Console.WriteLine("Identity: {0}", adRule.IdentityReference.Value);
                }
            }
            
            dirInfo.SetAccessControl(dirSecurity);
        }

        public string CheckAndGetGuid(string GPOName, string GUID)
        {
            if (string.IsNullOrEmpty(GPOName) && string.IsNullOrEmpty(GUID))
            {
                Console.WriteLine("[-] GPOName and GUID are empty.");
                Console.WriteLine("[+] Use --GPOName or --GUID to set them");
                return null;
            }

            if (!string.IsNullOrEmpty(GUID))
            {
                if (GetGPOByGuid(GUID) is null)
                {
                    Console.WriteLine("[-] The GUID {0} is invalid.", GUID);
                    return null;
                }
                return GUID;
            }

            var result = GetGPOByName(GPOName);
            if (result.Length == 0)
            {
                Console.WriteLine("[-] Cannot find GPO {0}", GPOName);
                return null;
            }
            if (result.Length > 1)
            {
                Console.WriteLine("[-] More than one GPO's name is {0}. You should use --GUID to specify a unique GPO.", GPOName);
                return null;
            }

            GUID = (string)result[0].Properties["cn"].Value;
            Console.WriteLine("[*] GUID of the GPO '{0}': {1}", GPOName, GUID);
            return GUID;
        }
    }
}
