#region Imports
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Timers;
using System.Runtime.Caching;
using System.Reflection;
using System.Configuration;
#endregion

namespace F2B.processors
{
    public class AccountProcessor : BoolProcessor
    {
        #region Fields
        private IAccount account;
        private AccountStatus status;
        #endregion

        #region Constructors
        public AccountProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["account"] != null)
            {
                account = AccountManager.Get(config.Options["account"].Value);
            }
            else
            {
                throw new ArgumentNullException("missing required options \"account\"");
            }

            status = AccountStatus.EXISTS;
            if (config.Options["status"] != null)
            {
                string statusstr = config.Options["status"].Value;
                switch (statusstr)
                {
                    case "exists": status = AccountStatus.EXISTS; break;
                    case "locked": status = AccountStatus.LOCKED; break;
                    case "disabled": status = AccountStatus.DISABLED; break;
                    case "deleted": status = AccountStatus.DELETED; break;
                    case "locked|disabled": status = AccountStatus.LOCKED | AccountStatus.DISABLED; break;
                    case "disabled|locked": status = AccountStatus.LOCKED | AccountStatus.DISABLED; break;
                    default: Log.Error("AccountProcessor[" + Name + "] unsupported status: " + statusstr); break;
                }
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (evtlog.Username == null)
            {
                return goto_failure;
            }

            if (account.Exists(evtlog.Username, status))
            {
                return goto_success;
            }
            else
            {
                return goto_failure;
            }
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config account: " + account);
            output.WriteLine("config status: " + status);
        }
#endif
        #endregion
    }



    public class AccountManager
    {
        private static IDictionary<string, IAccount> instances = new Dictionary<string, IAccount>();
        private static object syncRoot = new Object();

        private AccountManager() {}

        private static AccountElement Config(string name)
        {
            F2BSection config = F2B.Config.Instance;

            foreach (AccountElement accountConfig in config.Accounts)
            {
                if (accountConfig.Name != name)
                    continue;

                return accountConfig;
            }

            return null;
        }

        private static IAccount Create(string name)
        {
            AccountElement accoutConfig = Config(name);
            if (accoutConfig == null)
            {
                throw new ArgumentException("unknown account configuration \"" + name + "\"");
            }

            IDictionary<string, string> options = new Dictionary<string, string>();
            foreach (KeyValueConfigurationElement kv in accoutConfig.Options)
            {
                options.Add(kv.Key, kv.Value);
            }

            BaseAccount ret = null;
            string[] types = accoutConfig.Type.Split('+');

            Array.Reverse(types);
            foreach (string t in types)
            {
                ret = AccountManager.Create(name, t, options, ret);
            }

            return ret;
        }

        private static BaseAccount Create(string name, string type, IDictionary<string, string> options, BaseAccount account)
        {
            string clazzName = "F2B.processors." + type + "Account";
            Type clazzType = Type.GetType(clazzName);

            if (clazzType == null)
            {
                Log.Error("AccountManager::Create(" + name + ", " + type
                    + ", ...) unable to resolve account class \"" + clazzName + "\"");
            }
            else
            {
                Log.Info("AccountManager::Create(" + name + ", " + type
                    + ", ...) resolved account class \"" + clazzName + "\"");
            }

            if (typeof(ICacheAccount).IsAssignableFrom(clazzType))
            {
                ConstructorInfo ctor = clazzType.GetConstructor(
                    new[] { typeof(string), typeof(IDictionary<string, string>), typeof(ICachableAccount) });
                return (BaseAccount)ctor.Invoke(new object[] { name, options, account });
            }
            else
            {
                ConstructorInfo ctor = clazzType.GetConstructor(
                    new[] { typeof(string), typeof(IDictionary<string, string>) });
                return (BaseAccount)ctor.Invoke(new object[] { name, options });
            }
        }

        // singleton
        public static IAccount Get(string name)
        {
            if (!instances.ContainsKey(name)) {
                lock (syncRoot)
                {
                    if (!instances.ContainsKey(name))
                    {
                        instances[name] = Create(name);
                    }
                }
            }

            return instances[name];
        }
    }



    public enum AccountStatus
    {
        NULL = 0x0000, // not a real status code
        EXISTS = 0x0001,
        LOCKED = 0x0002,
        DISABLED = 0x0004,
        DELETED = 0x0008,
    }



    public interface IAccount
    {
        bool Exists(string username, AccountStatus status = AccountStatus.EXISTS);
    }

    
    
    public interface ICachableAccount : IAccount
    {
        AccountStatus Status(string username);
    }



    public interface ICachableAccountAll : ICachableAccount
    {
        IDictionary<string, AccountStatus> All();
    }



    public interface ICachableAccountInc : ICachableAccount
    {
        IDictionary<string, AccountStatus> Inc();
    }



    public interface ICacheAccount
    {
    }



    public class BaseAccount : IAccount
    {
        public string Name { get; private set; }
        public bool CaseSensitive { get; private set; }

        public BaseAccount(string name, IDictionary<string, string> options)
        {
            Name = name;

            CaseSensitive = false;
            if (options.ContainsKey("casesensitive"))
            {
                CaseSensitive = Str2Bool(options["casesensitive"]);
            }
        }


        protected bool Str2Bool(string str)
        {
            string val = str.ToLower();
            return (val == "1" || val == "on" || val == "y" || val == "yes" || val == "t" || val == "true");
        }

        
        public virtual AccountStatus Status(string username)
        {
            throw new NotImplementedException();
        }

        
        public virtual bool Exists(string username, AccountStatus status = AccountStatus.EXISTS)
        {
            AccountStatus astatus = Status(username);
            if (astatus == AccountStatus.NULL)
                return false;

            return ((astatus & status) == status);
        }
    }



    public class FileAccount : BaseAccount
    {
        public string Filename { get; private set; }
        public char[] Separator { get; private set; }
        private FileSystemWatcher watcher;
        private IDictionary<string, AccountStatus> data;

        public FileAccount(string name, IDictionary<string, string> options)
            : base(name, options)
        {
            if (!options.ContainsKey("filename"))
            {
                throw new ArgumentNullException("undefined filename option for account " + Name);
            }
            Filename = options["filename"];

            Separator = "\t".ToCharArray();
            if (options.ContainsKey("separator"))
            {
                Separator = options["separator"].ToCharArray();
            }

            watcher = new FileSystemWatcher();
            watcher.Path = Path.GetDirectoryName(Filename);
            watcher.NotifyFilter = NotifyFilters.LastWrite;
            watcher.Filter = Path.GetFileName(Filename);
            watcher.Changed += new FileSystemEventHandler(ConfigChanged);
            watcher.EnableRaisingEvents = true;

            data = new Dictionary<string, AccountStatus>();

            ParseConfig();
        }


        ~FileAccount()
        {
            watcher.EnableRaisingEvents = false;
        }


        private void ConfigChanged(object source, FileSystemEventArgs e)
        {
            Log.Info("FileAccount["+Name+"] ConfigChanged: " + e.FullPath);
            ParseConfig();
        }


        private void ParseConfig()
        {
            if (!File.Exists(Filename))
            {
                Log.Warn("FileAccount[" + Name + "] missing config file: " + Filename);
                data.Clear();
                return;
            }

            try
            {
                // parse IP address ranges from text file
                Dictionary<string, AccountStatus> dataNew = new Dictionary<string, AccountStatus>();
                using (StreamReader reader = new StreamReader(Filename))
                {
                    int pos = 0;
                    string line;

                    while ((line = reader.ReadLine()) != null)
                    {
                        pos++;

                        if (line.StartsWith("#"))
                            continue;

                        if (line.Trim() == string.Empty)
                            continue;

                        string[] cols = line.Split(Separator);
                        if (cols.Length == 0) // this should not happend,
                            continue;         // because we skip empty lines...

                        string username = cols[0];
                        if (!CaseSensitive)
                            username = username.ToLower();

                        if (data.ContainsKey(username))
                        {
                            Log.Info("FileAccount[" + Name + "] username " + username
                                + " already exists, overwriting with definition on line #" + pos);
                        }

                        AccountStatus status = AccountStatus.EXISTS;
                        if (cols.Length > 1)
                        {
                            if (Str2Bool(cols[1]))
                                status |= AccountStatus.LOCKED;
                        }
                        if (cols.Length > 2)
                        {
                            if (Str2Bool(cols[3]))
                                status |= AccountStatus.DISABLED;
                        }
                        if (cols.Length > 3)
                        {
                            if (Str2Bool(cols[1]))
                                status |= AccountStatus.DELETED;
                        }

                        data[username] = status;
                    }
                }

                // update configuration
                data = dataNew;
            }
            catch (Exception ex)
            {
                Log.Error("FileAccount[" + Name + "] unable to parse \""
                    + Filename + "\": " + ex.Message);
            }
        }

        public override AccountStatus Status(string username)
        {
            string user = username;
            if (!CaseSensitive)
                user = user.ToLower();

            if (!data.ContainsKey(user))
                return AccountStatus.NULL;

            return data[user];
        }
    }



    public class ADAccount : BaseAccount, ICachableAccountInc, ICachableAccountAll
    {
        private string[] hosts;
        private int port;
        private bool ssl;
        private bool starttls;
        private AuthType auth;
        private string username;
        private string password;
        private string sbase;
        private string filter;
        //
        private LdapConnection con;
        private string lastHost;
        private Int32 highestCommittedUSN;
        private bool logOnceMissingUAC = true;

        public ADAccount(string name, IDictionary<string, string> options)
            : base(name, options)
        {
            if (options.ContainsKey("hosts"))
            {
                hosts = options["hosts"].Split(',');
            }

            port = 389;
            if (options.ContainsKey("port"))
            {
                port = int.Parse(options["port"]);
            }

            ssl = false;
            if (options.ContainsKey("ssl"))
            {
                ssl = bool.Parse(options["ssl"]);
            }

            starttls = false;
            if (options.ContainsKey("starttls"))
            {
                starttls = bool.Parse(options["starttls"]);
            }

            auth = AuthType.Basic;
            if (options.ContainsKey("auth"))
            {
                switch (options["auth"])
                {
                    case "basic": auth = AuthType.Basic; break;
                    case "kerberos": auth = AuthType.Kerberos; break;
                    default: Log.Error("ADAccount[" + Name + "] unknown auth type: " + options["auth"]); break;
                }
            }

            username = null;
            if (options.ContainsKey("username"))
            {
                username = options["username"];
            }

            password = null;
            if (options.ContainsKey("password"))
            {
                password = options["password"];
            }

            sbase = null;
            if (!options.ContainsKey("base"))
            {
                throw new ArgumentException("ADAccount[" + Name + "] missing search base");
            }
            sbase = options["base"];

            filter = "(objectClass=*)";
            if (options.ContainsKey("filter"))
            {
                filter = options["filter"];
            }

            con = null;
        }


        ~ADAccount()
        {
            if (con != null)
            {
                con.Dispose();
            }
        }


        private bool LdapVerifyServerCertificateCallback(LdapConnection connection, X509Certificate certificate)
        {
            Log.Info("checking server certificate...");
            // make sure certificate was signed by our CA cert
            X509Chain verify = new X509Chain();
            //verify.ChainPolicy.ExtraStore.Add(secureClient.CertificateAuthority); // add CA cert for verification
            //verify.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority; // this accepts too many certificates
            //verify.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // no revocation checking
            //verify.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            if (verify.Build(new X509Certificate2(certificate)))
            {
                return true;
                //return verify.ChainElements[verify.ChainElements.Count - 1]
                //    .Certificate.Thumbprint == cacert.thumbprint; // success?
            }
            return false;
        }


        private LdapConnection GetConnection()
        {
            //con = new LdapConnection(new LdapDirectoryIdentifier(hosts[0], port));
            LdapConnection ret = new LdapConnection(new LdapDirectoryIdentifier(hosts, port, false, false));
            if (ssl)
            {
                ret.SessionOptions.SecureSocketLayer = true;
                //ret.SessionOptions.VerifyServerCertificate =
                //    (connection, certificate) => true;
                //ret.SessionOptions.VerifyServerCertificate =
                //    new VerifyServerCertificateCallback((connection, certificate) => true);
                ret.SessionOptions.VerifyServerCertificate =
                    new VerifyServerCertificateCallback(LdapVerifyServerCertificateCallback);
            }
            if (starttls)
            {
                ret.SessionOptions.StartTransportLayerSecurity(null);
            }
            // paged search doesn't work with All/Subordinate referrals
            ret.SessionOptions.ReferralChasing = ReferralChasingOptions.External;
            ret.SessionOptions.AutoReconnect = true;
            ret.Credential = new NetworkCredential(username, password);
            ret.AuthType = auth;
            ret.Bind();

            return ret;
        }


        public override AccountStatus Status(string username)
        {
            string user = username;
            if (!CaseSensitive)
                user = user.ToLower();

            if (con == null)
                con = GetConnection();

            SearchRequest request = new SearchRequest();
            request.DistinguishedName = sbase;
            request.Filter = String.Format("(&({0})(sAMAccountName={1}))", filter, user);
            request.Scope = System.DirectoryServices.Protocols.SearchScope.Subtree;
            request.Attributes.Add("userAccountControl");

            SearchResponse response = (SearchResponse)con.SendRequest(request);
            if (response.Entries.Count == 0)
            {
                //Log.Info("ADAccount[" + Name + "] user \"" + username + "\" not found");
                return AccountStatus.NULL;
            }
            if (response.Entries.Count > 1)
            {
                Log.Warn("ADAccount[" + Name + "] more users \"" + username + "\" found");
            }

            AccountStatus status = AccountStatus.EXISTS;
            SearchResultEntry entry = response.Entries[0];
            if (entry.Attributes.Contains("userAccountControl"))
            {
                Int32 uac = Int32.Parse((string)entry.Attributes["userAccountControl"][0]);
                if ((uac & 0x00000010) == 0x00000010) status |= AccountStatus.LOCKED;
                if ((uac & 0x00000002) == 0x00000002) status |= AccountStatus.DISABLED;
                // only user with special privileges can search for deleted objects
                //if (entry.Attributes.Contains("isDeleted") && bool.Parse((string)entry.Attributes["isDeleted"][0]))
                //    status |= AccountStatus.DELETED;
            }
            else
            {
                if (logOnceMissingUAC)
                {
                    logOnceMissingUAC = false;
                    Log.Info("ADAccount[" + Name + "] " + entry.DistinguishedName
                        + " doesn't contain userAccountControl attribute"
                        + " or you don't have privileges to read it");
                }
            }

            return status;
        }


        private Tuple<string, Int32> HighestUSN()
        {
            SearchRequest rootRequest = new SearchRequest();
            rootRequest.DistinguishedName = "";
            rootRequest.Scope = System.DirectoryServices.Protocols.SearchScope.Base;
            rootRequest.Attributes.Add("highestCommittedUSN");
            rootRequest.Attributes.Add("dsServiceName");

            SearchResponse rootResponse = (SearchResponse)con.SendRequest(rootRequest);
            if (rootResponse.Entries.Count != 1)
            {
                throw new Exception("unable to obtain LDAP base data");
            }

            SearchResultEntry rootEntry = rootResponse.Entries[0];
            if (!rootEntry.Attributes.Contains("highestCommittedUSN")
                || !rootEntry.Attributes.Contains("dsServiceName"))
            {
                throw new Exception("rootDSE required attributes not available (highestCommittedUSN, dsServiceName)");
            }

            Int32 currentCommitedUSN = Int32.Parse((string)rootEntry.Attributes["highestCommittedUSN"][0]);
            string currentHost = (string)rootEntry.Attributes["dsServiceName"][0];

            return new Tuple<string, Int32>(currentHost, currentCommitedUSN);
        }

        
        private IDictionary<string, AccountStatus> PagedSearch(string afilter)
        {
            // read data from LDAP
            PageResultRequestControl pageRequestControl = new PageResultRequestControl(5);
            // for some reason without setting this search option
            // paged search doesn't work for domain root base name
            // (probably caused by incompatible referral settings
            // so this is no longer necessary with "External" referral
            //SearchOptionsControl searchOptions =
            //    new SearchOptionsControl(System.DirectoryServices.Protocols.SearchOption.DomainScope);
            // with following option we could technically track also deleted
            // objects that are currently updated only by full search in AD,
            // but that requires special persmissions (administrator?) and
            // additional code to deal with history of objects with same name
            //ShowDeletedControl showDeleted = new ShowDeletedControl();

            SearchRequest request = new SearchRequest();
            request.Attributes.Add("cn");
            request.Attributes.Add("userAccountControl");
            //request.Attributes.Add("isDeleted");
            request.Controls.Add(pageRequestControl);
            //request.Controls.Add(searchOptions);
            //request.Controls.Add(showDeleted);
            request.DistinguishedName = sbase;
            request.Filter = afilter;
            request.Scope = System.DirectoryServices.Protocols.SearchScope.Subtree;

            Dictionary<string, AccountStatus> ret = new Dictionary<string, AccountStatus>();
            SearchResponse response;
            while (true)
            {
                response = (SearchResponse)con.SendRequest(request);

                foreach (SearchResultEntry entry in response.Entries)
                {
                    string user = (string)entry.Attributes["cn"][0];
                    Int32 uac = Int32.Parse((string)entry.Attributes["userAccountControl"][0]);

                    if (!CaseSensitive)
                        user = user.ToLower();

                    AccountStatus status = AccountStatus.EXISTS;
                    if ((uac & 0x00000010) == 0x00000010)
                    {
                        status |= AccountStatus.LOCKED;
                    }
                    if ((uac & 0x00000002) == 0x00000002)
                    {
                        status |= AccountStatus.DISABLED;
                    }
                    //if (entry.Attributes.Contains("isDeleted") && bool.Parse((string)entry.Attributes["isDeleted"][0]))
                    //{
                    //    status |= Account.DELETED;
                    //}

                    ret[user] = status;
                }

                //find the returned page response control
                foreach (DirectoryControl control in response.Controls)
                {
                    if (control is PageResultResponseControl)
                    {
                        //update the cookie for next set
                        pageRequestControl.Cookie = ((PageResultResponseControl)control).Cookie;
                        break;
                    }
                }

                if (pageRequestControl.Cookie.Length == 0)
                    break;
            }
            //con.SessionOptions.StopTransportLayerSecurity();

            return ret;
        }

        
        public IDictionary<string, AccountStatus> All()
        {
            return PagedSearch(filter);
        }

                
        public IDictionary<string, AccountStatus> Inc()
        {
            IDictionary<string, AccountStatus> ret;
            Tuple<string, Int32> tmp = HighestUSN();
            string currentHost = tmp.Item1;
            Int32 currentCommitedUSN = tmp.Item2;

            // connection to different server (USN valid only for given server)
            if (lastHost == currentHost)
            {
                // no changes in LDAP data source
                if (highestCommittedUSN == currentCommitedUSN)
                {
                    return new Dictionary<string, AccountStatus>();
                }

                ret = PagedSearch("(&" + filter + "(uSNChanged>=" + highestCommittedUSN + "))");
            }
            else
            {
                ret = PagedSearch(filter);
            }

            // update last user query info
            lastHost = currentHost;
            highestCommittedUSN = currentCommitedUSN;

            return ret;
        }
    }



    public class CachedAccount : BaseAccount, ICacheAccount
    {

        // NOTE: this class is not thread-safe, because processors using this
        // class are executed serially.
        class ExpirableCache
        {
            private double expire;
            private int max_size;
            private IDictionary<string, ExpirableItem> data;
            private int expire_intervals; // number of time slices
            private ISet<string>[] expire_sets;
            private DateTime expire_first_timestamp, expire_last_timestamp;
            private int expire_last_index;

            public ExpirableCache(double expire, int max_size)
            {
                this.expire = expire;
                this.max_size = max_size;
                expire_intervals = 100;
                expire_first_timestamp = DateTime.UtcNow;
                expire_last_timestamp = expire_first_timestamp;
                expire_last_index = 0;

                data = new Dictionary<string, ExpirableItem>();
                expire_sets = new ISet<string>[expire_intervals];
                for (int i = 0; i < expire_intervals; i++)
                {
                    expire_sets[i] = new HashSet<string>();
                }
            }

            public bool TryGet(string username, out AccountStatus status)
            {
                status = AccountStatus.NULL;

                ExpirableItem item;
                if (data.TryGetValue(username, out item))
                {
                    if (!item.IsExpired())
                    {
                        status = item.Status;
                        return true;
                    }
                }

                return false;
            }

            public void Insert(string username, AccountStatus status)
            {
                double seconds;
                DateTime expire_curr_timestamp;

                // purge all invalid/expired records
                // check if we came from future(?!) or all data exceeds "expire" time
                while (true)
                {
                    expire_curr_timestamp = DateTime.UtcNow;
                    seconds = (expire_last_timestamp - expire_curr_timestamp).TotalSeconds;

                    if (seconds >= 0 && seconds < expire)
                        break;

                    Clear();
                }

                int index = (int) (expire_intervals * (seconds / expire));

                // purge selected expired records
                if (expire_last_index != index)
                {
                    for (int i = expire_last_index + 1; i < expire_last_index + expire_intervals; i++)
                    {
                        int curr_index = i % expire_intervals;

                        foreach (string ausername in expire_sets[i])
                        {
                            data.Remove(ausername);
                        }
                        expire_sets[i].Clear();

                        if (curr_index == index)
                            break;
                    }
                }

                // remove oldest cached data when we reach max_size quota
                if (data.Count > max_size)
                {
                    for (int i = expire_intervals + index - 1; i > index; i--)
                    {
                        int curr_index = i % expire_intervals;

                        foreach (string ausername in expire_sets[i])
                        {
                            data.Remove(ausername);
                        }
                        expire_sets[i].Clear();
                    }

                    // NOTE: now we should check if all data doesn't sit in expire_sets[index]
                    // and remove oldest record (or some fraction of oldest records)
                }

                // remove old record for username
                ExpirableItem last;
                if (data.TryGetValue(username, out last))
                {
                    expire_sets[last.Index].Remove(username);
                    data.Remove(username);
                }

                data[username] = new ExpirableItem(status, expire, index);
                expire_sets[index].Add(username);
            }

            public void Clear()
            {
                data.Clear();
                for (int i = 0; i < expire_intervals; i++)
                {
                    expire_sets[i].Clear();
                }

                expire_first_timestamp = DateTime.UtcNow;
                expire_last_timestamp = expire_first_timestamp;
                expire_last_index = 0;
            }
        }

        struct ExpirableItem
        {
            private AccountStatus status;
            private DateTime timestamp;
            private TimeSpan timetolive;
            private int index;

            public ExpirableItem(AccountStatus status, double expire, int index)
            {
                this.status = status;
                this.timestamp = DateTime.UtcNow;
                this.timetolive = TimeSpan.FromSeconds(expire);
                this.index = index;
            }

            public AccountStatus Status
            {
                get { return status; }
            }

            public int Index
            {
                get { return index; }
            }

            public bool IsExpired()
            {
                return DateTime.UtcNow > timestamp + timetolive;
            }
        }

        private ICachableAccount Account;
        //private MemoryCache cache; // can't be used on primitive data types?!
        //private IDictionary<string, Tuple<AccountStatus, DateTime, TimeSpan, int>> cache;
        //private IDictionary<string, ExpirableItem> cache;
        //private ISet<string>[] expire_cache;
        //private DateTime expire_start;
        ExpirableCache cache_positive;
        ExpirableCache cache_negative;

        public CachedAccount(string name, IDictionary<string, string> options, ICachableAccount account)
            : base(name, options)
        {
            Account = account;

            int cache_positive_time = 600;
            if (options.ContainsKey("cache_positive_time"))
            {
                cache_positive_time = int.Parse(options["cache_positive_time"]);
            }

            int cache_negative_time = 60;
            if (options.ContainsKey("cache_negative_time"))
            {
                cache_negative_time = int.Parse(options["cache_negative_time"]);
            }

            int cache_positive_max_size = 10000;
            if (options.ContainsKey("cache_positive_max_size"))
            {
                cache_positive_time = int.Parse(options["cache_positive_max_size"]);
            }

            int cache_negative_max_size = 1000;
            if (options.ContainsKey("cache_negative_max_size"))
            {
                cache_negative_time = int.Parse(options["cache_negative_max_size"]);
            }

            cache_positive = null;
            cache_negative = null;
            if (cache_positive_time > 0)
            {
                cache_positive = new ExpirableCache(cache_positive_time, cache_positive_max_size);
            }
            if (cache_negative_time > 0)
            {
                cache_negative = new ExpirableCache(cache_negative_time, cache_negative_max_size);
            }

            //cache = new MemoryCache("CachedAccount[" + name + "]");
            //cache = new Dictionary<string, Tuple<AccountStatus, DateTime, TimeSpan, int>>();
        }


        public override AccountStatus Status(string username)
        {
            string user = username;
            if (!CaseSensitive)
                user = user.ToLower();

            AccountStatus status;

            if (cache_positive != null)
            {
                if (cache_positive.TryGet(user, out status))
                {
                    return status;
                }
            }

            if (cache_negative != null)
            {
                if (cache_negative.TryGet(user, out status))
                {
                    return status;
                }
            }

            status = Account.Status(username);

            // cache AccountStatus data for this user
            if (status == AccountStatus.NULL)
            {
                cache_negative.Insert(user, status);
            }
            else
            {
                cache_positive.Insert(user, status);
            }

            return status;
        }
    }



    public class CachedAllAccount : BaseAccount, ICacheAccount
    {
        private int refresh_inc;
        private int refresh_full;
        //
        private ICachableAccount Account;
        private Timer refresh_inc_timer = null;
        private Timer refresh_full_timer = null;
        private IDictionary<string, AccountStatus> cache;

        public CachedAllAccount(string name, IDictionary<string, string> options, ICachableAccount account)
            : base(name, options)
        {
            if (!(account is ICachableAccountAll) && !(account is ICachableAccountInc))
            {
                throw new ArgumentException("can't cache account class that "
                    + "doesn't implement IAccountAll or IAccountInc interface");
            }
            Account = account;

            refresh_inc = -1;
            if (options.ContainsKey("refresh_inc"))
            {
                refresh_inc = int.Parse(options["refresh_inc"]);
            }
            else if (Account is ICachableAccountInc)
            {
                refresh_inc = 300;
            }

            refresh_full = -1;
            if (options.ContainsKey("refresh_full"))
            {
                refresh_full = int.Parse(options["refresh_full"]);
            }
            else if (Account is ICachableAccountAll)
            {
                refresh_full = 3600;
            }

            // initialize cached data
            try
            {
                RefreshFull();
            }
            catch (Exception ex)
            {
                Log.Error("ADAccount[" + Name + "] unable to fill cache: " + ex.Message);
            }

            // create timers to periodically update cached data
            if (refresh_inc > 0 && refresh_inc != refresh_full) // && Account is IAccountInc)
            {
                refresh_inc_timer = new Timer(refresh_inc);
                refresh_inc_timer.Elapsed += RefreshIncElapsed;
                refresh_inc_timer.Enabled = true;
            }

            if (refresh_full > 0) // && Account is IAccountAll)
            {
                refresh_full_timer = new Timer(refresh_full);
                refresh_full_timer.Elapsed += RefreshFullElapsed;
                refresh_full_timer.Enabled = true;
            }
        }


        ~CachedAllAccount()
        {
            if (refresh_inc_timer != null && refresh_inc_timer.Enabled)
            {
                refresh_inc_timer.Enabled = false;
                refresh_inc_timer.Dispose();
            }

            if (refresh_full_timer != null && refresh_full_timer.Enabled)
            {
                refresh_full_timer.Enabled = false;
                refresh_full_timer.Dispose();
            }
        }


        public override AccountStatus Status(string username)
        {
            string user = username;
            if (!CaseSensitive)
                user = user.ToLower();

            // try to get cached data
            AccountStatus status = AccountStatus.NULL;
            cache.TryGetValue(user, out status);

            return status;
        }


        private void RefreshIncElapsed(object sender, ElapsedEventArgs e)
        {
            if (!refresh_inc_timer.Enabled)
            {
                // this should prevent race condition, because elapsed
                // event is queued for execution on a thread poole thread
                return;
            }

            try
            {
                RefreshInc();
            }
            catch (Exception ex)
            {
                Log.Error("ADAccount[" + Name + "] unable to refresh inc: " + ex.Message);
            }
        }


        private void RefreshInc()
        {
            IDictionary<string, AccountStatus> tmp;

            if (Account is ICachableAccountInc)
            {
                tmp = (Account as ICachableAccountInc).Inc();
                foreach (KeyValuePair<string, AccountStatus> item in tmp)
                {
                    cache[item.Key] = item.Value;
                }
            }
            else
            {
                tmp = (Account as ICachableAccountAll).All();
                cache = tmp;
            }
        }


        private void RefreshFullElapsed(object sender, ElapsedEventArgs e)
        {
            if (!refresh_full_timer.Enabled)
            {
                // this should prevent race condition, because elapsed
                // event is queued for execution on a thread poole thread
                return;
            }

            try
            {
                RefreshFull();
            }
            catch (Exception ex)
            {
                Log.Error("ADAccount[" + Name + "] unable to refresh full: " + ex.Message);
            }
        }


        private void RefreshFull()
        {
            IDictionary<string, AccountStatus> tmp;

            if (Account is ICachableAccountAll)
            {
                tmp = (Account as ICachableAccountAll).All();
                cache = tmp;
            }
            else
            {
                tmp = (Account as ICachableAccountInc).Inc();
                foreach (KeyValuePair<string, AccountStatus> item in tmp)
                {
                    cache[item.Key] = item.Value;
                }
            }
        }
    }
}
