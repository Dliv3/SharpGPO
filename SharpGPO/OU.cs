using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace SharpGPO
{
    class OU
    {
        public AD ad;
        public OU(AD ad)
        {
            this.ad = ad;
        }

        public DirectoryEntry[] GetOU(string ouName = null)
        {
            if (string.IsNullOrEmpty(ouName))
            {
                ouName = "*";
            }
            DirectoryEntry domain = ad.ConnectLdap();
            DirectorySearcher searcher = new DirectorySearcher(domain);
            searcher.Filter = $@"(&(objectCategory=organizationalUnit)(name={ouName}))";
            SearchResultCollection results = searcher.FindAll();
            List<DirectoryEntry> ous = new List<DirectoryEntry>();
            foreach (SearchResult result in results)
            {
                ous.Add(result.GetDirectoryEntry());
            }
            return ous.ToArray();
        }

        public void GetOUDetails(string ouName)
        {
            DirectoryEntry[] ous = GetOU(ouName);
            if (ous.Length != 0)
                Console.WriteLine("[*] --------------------------------------------------------");
            foreach (var ou in ous)
            {
                Console.WriteLine($@"[*] OU: {ou.Properties["ou"].Value}");
                Console.WriteLine($@"[*] OU distinguishedName: {ou.Properties["distinguishedName"].Value}");
                Console.WriteLine($@"[*] OU description: {ou.Properties["description"].Value}");
                Console.WriteLine("[*] --------------------------------------------------------");
            }
        }

        public void NewOU(string ouName, string baseDN)
        {
            if (string.IsNullOrEmpty(baseDN)) baseDN = ad.DomainDistingushedName;
            DirectoryEntry target = ad.ConnectLdap(baseDN);
            DirectoryEntries childrenEntries = target.Children;
            Console.WriteLine($@"[*] Creating OU: OU={ouName},{baseDN}");

            try
            {
                DirectoryEntry organizationalUnit = childrenEntries.Add("OU=" + ouName, "organizationalUnit");
                organizationalUnit.Properties["ou"].Value = ouName;
                organizationalUnit.Properties["name"].Value = ouName;
                organizationalUnit.CommitChanges();

                // set GenericAll to current user
                SecurityIdentifier currentUser = ad.GetDomainUserSID(ad.CurrentDomainUser);
                ActiveDirectoryAccessRule newRule = new ActiveDirectoryAccessRule(
                    currentUser,
                    ActiveDirectoryRights.GenericAll,
                    AccessControlType.Allow
                );
                organizationalUnit.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                organizationalUnit.ObjectSecurity.SetAccessRule(newRule);
                organizationalUnit.CommitChanges();

            }
            catch (Exception e)
            {
                Console.WriteLine("Error:   Create failed.");
                Console.WriteLine("         {0}", e.Message);
                return;
            }

            Console.WriteLine("[*] Create OU: Success!");
        }

        public void RemoveOU(string OU, string DN = "")
        {
            if (!string.IsNullOrEmpty(DN))
            {
                DirectoryEntry target = ad.ConnectLdap(DN);
                if (!target.SchemaClassName.ToLower().Contains("organizationalunit"))
                {
                    Console.WriteLine($@"[-] {DN} is not an OU");
                    return;
                }

                Console.WriteLine($@"[*] Remove {DN}");
                target.DeleteTree();
            }
            else
            {
                DirectoryEntry[] ous = new OU(ad).GetOU(OU);
                if (ous.Length == 0) return;
                if (ous.Length > 1)
                {
                    Console.WriteLine();
                    Console.WriteLine($@"[!] More than one OU named {OU}, use --DN to specify one of them");
                    Console.WriteLine();
                    GetOUDetails(OU);
                    return;
                }
                if (ous.Length == 1)
                {
                    Console.WriteLine($@"[*] Remove {ous[0].Properties["distinguishedName"].Value}");
                    ous[0].DeleteTree();
                }
            }
        }

        public void MoveObject(string srcDN, string dstDN)
        {
            DirectoryEntry srcDE = ad.ConnectLdap(srcDN);
            DirectoryEntry dstDE = ad.ConnectLdap(dstDN);
            srcDE.MoveTo(dstDE);
            Console.WriteLine("[*] MoveObject: Success!");
        }

        public bool Exists(string ouName, string baseDN = "")
        {
            if (string.IsNullOrEmpty(baseDN))
            {
                baseDN = ad.DomainDistingushedName;
            }

            return ad.Exists($@"OU={ouName},{baseDN}");
        }
    }
}
