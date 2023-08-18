using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpShareFinder
{
    internal class Program
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct LDAP_TIMEVAL
        {
            public int tv_sec; 
            public int tv_usec; 
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DOMAIN_CONTROLLER_INFO
        {
            public string DomainControllerName;
            public string DomainControllerAddress;
            public int DomainControllerAddressType;
            public Guid DomainGuid;
            public string DomainName;
            public string DnsForestName;
            public int Flags;
            public string DcSiteName;
            public string ClientSiteName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDAP_BERVAL
        {
            public uint bv_len;
            public IntPtr bv_val;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;
            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }
        const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
        const int NERR_Success = 0;
        private enum NetError : uint
        {
            NERR_Success = 0,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23),
        }
        private enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
        }


        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int DsGetDcName(string ComputerName, string DomainName, IntPtr DomainGuid, string SiteName, int Flags, out IntPtr DcInfo);

        [DllImport("Netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Wldap32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr ldap_init(string hostName, int portNumber);

        [DllImport("Wldap32.dll", CharSet = CharSet.Unicode)]
        public static extern int ldap_set_option(IntPtr ldapHandle, int option, ref int inValue);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ldap_connect(IntPtr ld, ref LDAP_TIMEVAL timeout);

        [DllImport("Wldap32.dll")]
        public static extern int ldap_bind_s(IntPtr ld, string dn, string cred, int method);

        [DllImport("Wldap32.dll", CharSet = CharSet.Unicode)]
        public static extern int ldap_search_s(IntPtr ld, string baseDn, int scope, string filter, IntPtr attributes, int attrsonly, ref IntPtr res);

        //[DllImport("wldap32.dll", CharSet = CharSet.Unicode)]
        //public static extern int ldap_search_st(IntPtr ld, string baseDn, int scope, string filter, IntPtr attributes, int attrsonly, ref LDAP_TIMEVAL timeout, ref IntPtr res, int sizelimit);

        [DllImport("wldap32.dll", CharSet = CharSet.Unicode)]
        public static extern int ldap_search_st(IntPtr ld, string baseDn, int scope, string filter, string[] attributes, int attrsonly, IntPtr timeout, ref IntPtr res);

        [DllImport("wldap32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr ldap_get_values_len(IntPtr ld, IntPtr entry, string attr);

        [DllImport("Wldap32.dll")]
        public static extern IntPtr ldap_first_entry(IntPtr ld, IntPtr res);

        [DllImport("Wldap32.dll")]
        public static extern IntPtr ldap_next_entry(IntPtr ld, IntPtr entry);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ldap_first_attribute(IntPtr ld, IntPtr entry, ref IntPtr ptr);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ldap_search_init_page(IntPtr ld, string baseDn, int scope, string filter, IntPtr attributes, int attrsonly, IntPtr servercontrols, IntPtr clientcontrols, int timelimit, int pageSize, ref IntPtr pageHandle);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ldap_get_next_page_s(IntPtr ld, IntPtr search, int timeout, int pageSize, ref IntPtr pageHandle);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern int ldap_get_next_page_s(IntPtr ld, IntPtr search, uint timeout, int pageSize, ref int totalCount, ref IntPtr res);

        [DllImport("wldap32.dll", CharSet = CharSet.Unicode)]
        public static extern int ldap_get_paged_count(IntPtr ld, IntPtr search, ref IntPtr pageHandle, IntPtr res);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ldap_count_entries(IntPtr ld, IntPtr res);


        [DllImport("Wldap32.dll")]
        public static extern void ldap_memfree(IntPtr ptr);

        [DllImport("Wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ldap_msgfree(IntPtr message);

        [DllImport("wldap32.dll")]
        public static extern int ldap_value_free_len(IntPtr pBerVals);


        [DllImport("Wldap32.dll", CharSet = CharSet.Unicode)]
        public static extern int ldap_get_option(IntPtr ld, int option, ref IntPtr outValue);

        const int LDAP_OPT_DIAGNOSTIC_MESSAGE = 0x31;

        [DllImport("Wldap32.dll")]
        public static extern int LdapMapErrorToWin32(int ldapErr);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr FormatMessage(int dwFlags, IntPtr lpSource, int dwMessageId, int dwLanguageId, ref IntPtr lpBuffer, int nSize, IntPtr Arguments);

        const int FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
        const int FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;

        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int LdapGetLastError();

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(StringBuilder ServerName, int level, ref IntPtr bufPtr, uint prefmaxlen, ref int entriesread, ref int totalentries, ref int resume_handle);

        static string ConvertDnsNameToDn(string dnsName)
        {
            if (string.IsNullOrEmpty(dnsName))
            {
                return null;
            }
            string[] parts = dnsName.Split('.');
            string baseDn = "";
            foreach (string part in parts)
            {
                if (baseDn.Length > 0)
                {
                    baseDn += ",";
                }
                baseDn += "DC=" + part;
            }
            return baseDn;
        }

        public static byte[] ToByteArray(LDAP_BERVAL berval)
        {
            byte[] bytes = new byte[berval.bv_len];
            Marshal.Copy(berval.bv_val, bytes, 0, (int)berval.bv_len);
            return bytes;
        }


        // https://www.pinvoke.net/default.aspx/netapi32/netshareenum.html
        public static SHARE_INFO_1[] EnumNetShares(string Server)
        {
            List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            StringBuilder server = new StringBuilder(Server);
            int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == NERR_Success)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                    ShareInfos.Add(shi1);
                    currentPtr += nStructSize;
                }
                NetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }
            else
            {
                ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(), 10, string.Empty));
                return ShareInfos.ToArray();
            }
        }

        static void banner()
        {
            string banner = @"
               _  _   _____ _                   ______ _           _           
             _| || |_/  ___| |                  |  ___(_)         | |          
            |_  __  _\ `--.| |__   __ _ _ __ ___| |_   _ _ __   __| | ___ _ __ 
             _| || |_ `--. \ '_ \ / _` | '__/ _ \  _| | | '_ \ / _` |/ _ \ '__|
            |_  __  _/\__/ / | | | (_| | | |  __/ |   | | | | | (_| |  __/ |   
              |_||_| \____/|_| |_|\__,_|_|  \___\_|   |_|_| |_|\__,_|\___|_|   
                                                                   
            ";
            Console.WriteLine(banner);
            Console.WriteLine("\t\t\tby Mauricio Velazco (@mvelazco)");
            Console.WriteLine("\n\n");

        }

        static List<string> GetDnsHostNames()
        {
            List<string> dnshostnames = new List<string>();
            IntPtr dcInfo;
            int result = DsGetDcName(null, null, IntPtr.Zero, null, 0, out dcInfo);
            if (result != 0)
            {
                Console.WriteLine("[!] Failed to get domain controller.");
                return null;
            }

            DOMAIN_CONTROLLER_INFO dc = (DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(dcInfo, typeof(DOMAIN_CONTROLLER_INFO));
            string domainController = dc.DomainControllerName.TrimStart('\\');

            Console.WriteLine($"[+] Identified domain controller: {domainController}");

            IntPtr ldap = ldap_init(domainController, 389);
            if (ldap == IntPtr.Zero)
            {
                Console.WriteLine("[!]Failed to initialize LDAP.");
                return null;
            }

            int ldapVersion = 3;
            const int LDAP_OPT_PROTOCOL_VERSION = 0x11;

            if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, ref ldapVersion) != 0)
            {
                Console.WriteLine("[!] Failed to set LDAP version.");
                return null;
            }

            LDAP_TIMEVAL timeout;
            timeout.tv_sec = 10; 
            timeout.tv_usec = 0;

            result = ldap_connect(ldap, ref timeout);
            if (result != 0)
            {
                Console.WriteLine("[!] Failed to connect to LDAP server.");
                return null;
            }

            const int LDAP_AUTH_NEGOTIATE = (0x86 | 0x0400);
            result = ldap_bind_s(ldap, null, null, LDAP_AUTH_NEGOTIATE);

            if (result != 0)
            {
                Console.WriteLine("[!] Failed to bind to LDAP.");
                return null;
            }

            IntPtr res = IntPtr.Zero;
            string baseDn = ConvertDnsNameToDn(dc.DomainName);
            NetApiBufferFree(dcInfo);

            string filter = "(objectCategory=computer)";

            //DateTime lastHour = DateTime.UtcNow.AddHours(-1);
            //long lastHourFileTime = lastHour.ToFileTime();
            //string filter = $"(&(objectCategory=computer)(lastLogonTimestamp>={lastHourFileTime}))";
            


            // TODO: implementing paged searching will be needed in large environments.
            // Not working ATM.
            /*
            IntPtr pageHandle = IntPtr.Zero;
            int totalCount = 0;
            int pageSize = 100; 

            do
            {
                IntPtr results = IntPtr.Zero;

                result = ldap_search_init_page(ldap, baseDn, 2, filter, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, 0, pageSize, ref pageHandle);
                Console.WriteLine($"ldap_search_init_page result: {result}");

                if (result != 0)
                {
                    break;
                }

                result = ldap_get_next_page_s(ldap, pageHandle, 0, pageSize, ref totalCount, ref results);
                Console.WriteLine($"ldap_get_next_page_s result: {result}, totalCount: {totalCount}");

                if (result != 0 && result != 4) // more data is available
                {
                    break;
                }
                IntPtr entry = ldap_first_entry(ldap, results);
                while (entry != IntPtr.Zero)
                {
                    IntPtr dnPtr = ldap_get_dn(ldap, entry);
                    if (dnPtr != IntPtr.Zero)
                    {
                        string dn = Marshal.PtrToStringUni(dnPtr);
                        Console.WriteLine($"Distinguished Name: {dn}");

                        ldap_memfree(dnPtr);
                    }
                    entry = ldap_next_entry(ldap, entry);
                }

                ldap_msgfree(results);

            } while (result == 4); 
            */


            
            string[] attrs = new string[] { "dNSHostName", null };
            int maxResults = 100;
            Console.WriteLine($"[+] Running LDAP query to obtain domain computers...");
            res = IntPtr.Zero;
            result = ldap_search_st(ldap, baseDn, 2, filter, attrs, 0, IntPtr.Zero, ref res);
            //result = ldap_search_st(ldap, baseDn, 2, filter, attrs, 0, ref timeout, ref res, maxResults);

            if (result != 0)
            {
                Console.WriteLine("[!] LDAP search failed.");
                //Console.WriteLine($"result code: {result}");
                return null;
            }
            int count = ldap_count_entries(ldap, res);
            Console.WriteLine($"[+] Got {count} entries. Starting enumeration...");

            IntPtr results = ldap_first_entry(ldap, res);
            while (results != IntPtr.Zero)
            {
                IntPtr dnshostnamePtr = ldap_get_values_len(ldap, results, "dNSHostName");
                if (dnshostnamePtr != IntPtr.Zero)
                {
                    IntPtr currentPtr = dnshostnamePtr;
                    while (true)
                    {
                        IntPtr valuePtr = Marshal.ReadIntPtr(currentPtr);
                        if (valuePtr == IntPtr.Zero) break;

                        LDAP_BERVAL valueBerVal = Marshal.PtrToStructure<LDAP_BERVAL>(valuePtr);
                        byte[] valueBytes = new byte[valueBerVal.bv_len]; 
                        Marshal.Copy(valueBerVal.bv_val, valueBytes, 0, valueBytes.Length); 

                        string dnsHostname = Encoding.UTF8.GetString(valueBytes);
                        dnshostnames.Add(dnsHostname);
                        currentPtr += IntPtr.Size; 
                    }
                    ldap_value_free_len(dnshostnamePtr);
                }
                results = ldap_next_entry(ldap, results);
            }
            
            return dnshostnames;
        }

        static void Main(string[] args)
        {
            banner();

            List<string> dnsHostNames = GetDnsHostNames();
            Parallel.ForEach(dnsHostNames, dnsHostName =>
            {
                SHARE_INFO_1[] shares = EnumNetShares(dnsHostName);
                Console.WriteLine($"[+] Identified network shares on: {dnsHostName}");
                foreach (SHARE_INFO_1 share in shares)
                {
                    String sharename = share.ToString();
                    string[] excluded_shares = { "IPC$", "ADMIN$", "C$", "SYSVOL", "NETLOGON" };
                    if (!excluded_shares.Contains(sharename))
                    {
                        Console.WriteLine($"\t\\\\{dnsHostName}\\{sharename}");
                    }

                }
            });
        }
    }
}
