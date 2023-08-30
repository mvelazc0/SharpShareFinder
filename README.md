# SharpShareFinder

SharpShareFinder is a minimalistic network share discovery tool designed to enumerate shares in Windows Active Directory networks leveraging .NET parallelism.

Written in C#, it employs a three-step process to achieve its goals. First, it identifies a domain controller using the DsGetDcName function exported by NetApi32.dll. It then uses this DC to enumerate all domain-joined computers through the Lightweight Directory Access Protocol (LDAP). To perform this task, It leverages functions exported by Wldap32.dll, such as ldap_init and ldap_search_st.

Finally, SharpShareFinder enumerates and prints all available network shares for each identified host. To do this, it relies on the NetShareEnum API function, also exported by Netapi32.dll, the same method utilized by tools like Invoke-ShareFinder.
