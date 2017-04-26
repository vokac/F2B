using System;
using System.Configuration;
using System.Diagnostics;
using System.Net;
using System.Reflection;

namespace F2B
{
    static class Program
    {
        #region Properties
        public static string ConfigFile { get; private set; }
        public static Configuration Config { get; private set; }
        #endregion

        /// <summary>
        /// Help message for command line arguments.
        /// </summary>
        public static void Usage()
        {
            Version v = Assembly.GetExecutingAssembly().GetName().Version;
            string pname = Process.GetCurrentProcess().ProcessName;
            string vcinfo = string.Format("{0}[{1}] {2} ({3})", VCS.type, VCS.branch, VCS.commit, VCS.status);
            Console.WriteLine("{0} version {1}.{2}.{3} (r{4}), {5}", pname, v.Major, v.Minor, v.Build, v.Revision, vcinfo);
            Console.WriteLine("Command line arguments:");
            Console.WriteLine("  help                show this help");
            Console.WriteLine("  examples            show command line examples");
            Console.WriteLine("  list-filters        list all F2BFW filters");
            Console.WriteLine("  add-filter          add F2BFW filte rule");
            Console.WriteLine("  remove-filter       remove F2BFW filter rule with filterId");
            Console.WriteLine("  remove-filters      remove all F2BFW filters");
            Console.WriteLine("  remove-expired-filters remove expired F2BFW filters");
            Console.WriteLine("  remove-unknown-filters remove F2BFW filters with invalid name");
            Console.WriteLine("  list-wfp            show F2B WFP structures");
            Console.WriteLine("  add-wfp             add F2B WFP structures");
            Console.WriteLine("  remove-wfp          remove F2B WFP structures");
            Console.WriteLine("  list-privileges     show WFP security descriptors");
            Console.WriteLine("  add-privileges      add user to WFP security descriptors");
            Console.WriteLine("  remove-privileges   remove user from WFP security descriptors");
            Console.WriteLine("Options:");
            Console.WriteLine("  -h          show this help");
            Console.WriteLine("  -l          log severity level (INFO, WARN, ERROR)");
            Console.WriteLine("  -g, --log-file file log filename (disables event log or console logging)");
            Console.WriteLine("  --log-size size     maximum log file size");
            Console.WriteLine("  --log-history cnt   number of rotated log files");
            Console.WriteLine("  -u user     use given user to run this service");
            Console.WriteLine("  -x size     configure hard limit for memory in MB (Job Object)");
            Console.WriteLine("  -a	IPAddr/p IPv4 or IPv6 address and optional prefix length");
            Console.WriteLine("  -e	expir    expiration time in windows UTC time ticks");
            Console.WriteLine("  -w weight   filter rule priority");
            Console.WriteLine("  -t          permit filter rule");
            Console.WriteLine("  -s          persistent filter rule (survive machine reboot)");
            Console.WriteLine("  -f	filterId filter identifier");
        }

        public static void Examples()
        {
            string pname = Process.GetCurrentProcess().ProcessName;
            Console.WriteLine("Examples:");
            Console.WriteLine("  # add privileges F2B firewall rules to \"DOMAIN\\username\"");
            Console.WriteLine("  {0} add-privileges [-u DOMAIN\\username]", pname);
            Console.WriteLine("  # remove privileges F2B firewall rules from \"DOMAIN\\username\"");
            Console.WriteLine("  {0} remove-privileges [-u DOMAIN\\username]", pname);
            Console.WriteLine("  # list all F2B filter rules");
            Console.WriteLine("  {0} list-filters", pname);
            Console.WriteLine("  # add F2B firewall filter for 192.0.2.123/24 with 5 minute expiration");
            Console.WriteLine("  {0} add-filter --address 192.0.2.123/24 --expiration {0}", pname, DateTime.UtcNow.Ticks + 5 * 60 * TimeSpan.TicksPerSecond);
            Console.WriteLine("  # add pernament F2B firewall filter with hight priority which permits access from 192.0.2.234");
            Console.WriteLine("  {0} add-filter --address 192.0.2.234 --weight 18446744073709551615 --permit --persistent", pname);
            Console.WriteLine("  # remove filter with ID 12345678 (only F2B rules can be removed)");
            Console.WriteLine("  {0} remove-filter --filter-id 12345678", pname);
            Console.WriteLine("  # show debug info using DbgView from SysInternals");
            Console.WriteLine("  DbgView.exe");
            Console.WriteLine("Manage service manually:");
            Console.WriteLine("  # register WPF provider with GUID " + F2B.Firewall.PROVIDER_KEY);
            Console.WriteLine("  # register WPF subLayer with GUID " + F2B.Firewall.SUBLAYER_KEY);
            Console.WriteLine("  # add user ACL to WPF provider, subLayer and filter if you want run this service with unprivileged account");
        }

        /// <summary>
        /// Main entry point of the application.
        /// </summary>
        public static void Main(string[] args)
        {
            ConfigFile = AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;
            Log.Dest = Log.Destinations.EventLog;
            Log.Level = EventLogEntryType.Information;

            int i = 0;
            string command = null;
            string user = null;
            ulong maxmem = 0;
            string address = null;
            long expiration = 0;
            UInt64 weight = 0;
            bool permit = false;
            bool persistent = false;
            UInt64 filterId = 0;

            while (i < args.Length)
            {
                string param = args[i];
                if (args[i][0] == '/')
                {
                    param = "-" + param.Substring(1);
                }

                if (param == "-h" || param == "-help" || param == "--help")
                {
                    Usage();
                    return;
                }
                else if (param == "-l" || param == "-log-level" || param == "--log-level")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        switch (args[i].ToUpper())
                        {
                            case "INFORMATION":
                            case "INFO":
                                Log.Level = EventLogEntryType.Information;
                                break;
                            case "WARNING":
                            case "WARN":
                                Log.Level = EventLogEntryType.Warning;
                                break;
                            case "ERROR":
                                Log.Level = EventLogEntryType.Error;
                                break;
                        }
                    }
                }
                else if (param == "-g" || param == "-log-file" || param == "--log-file")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        Log.File = args[i];
                        Log.Dest = Log.Destinations.File;
                    }
                }
                else if (param == "-log-size" || param == "--log-size")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        Log.FileSize = long.Parse(args[i]);
                    }
                }
                else if (param == "-log-history" || param == "--log-history")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        Log.FileRotate = int.Parse(args[i]);
                    }
                }
                else if (param == "-c" || param == "-config" || param == "--config")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        ConfigFile = args[i];
                    }
                }
                else if (param == "-u" || param == "-user" || param == "--user")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        user = args[i];
                    }
                }
                else if (param == "-x" || param == "-max-mem" || param == "--max-mem")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        maxmem = ulong.Parse(args[i]);
                    }
                }
                else if (param == "-a" || param == "-address" || param == "--address")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        address = args[i];
                    }
                }
                else if (param == "-e" || param == "-expiration" || param == "--expiration")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        expiration = long.Parse(args[i]);
                    }
                }
                else if (param == "-w" || param == "-weight" || param == "--weight")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        weight = UInt64.Parse(args[i]);
                    }
                }
                else if (param == "-t" || param == "-permit" || param == "--permit")
                {
                    permit = true;
                }
                else if (param == "-s" || param == "-persistent" || param == "--persistent")
                {
                    persistent = true;
                }
                else if (param == "-f" || param == "-filter-id" || param == "--filter-id")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        filterId = UInt64.Parse(args[i]);
                    }
                }
                else if (param.Length > 0 && param[0] == '-')
                {
                    Log.Error("Unknown argument #" + i + " (" + args[i] + ")");
                    if (Environment.UserInteractive)
                    {
                        Usage();
                    }
                    return;
                }
                else
                {
                    command = args[i];
                }
                i++;
            }

            // Set memory limit for this process
            if (maxmem > 0)
            {
                Limit limitMemory = new Limit(maxmem * 1024 * 1024, maxmem * 1024 * 1024);
                limitMemory.AddProcess(Process.GetCurrentProcess().Handle);
                limitMemory.Dispose();
            }

            if (Environment.UserInteractive)
            {
                if (command == null)
                {
                    command = "help";
                }

                if ((Log.Dest & Log.Destinations.File) == 0)
                {
                    Log.Dest = Log.Destinations.Console;
                }
                Log.Info("F2BFwCmd in interactive mode executing command: " + command);
            }

            if (true)
            {
                if (command.ToLower() == "help")
                {
                    Usage();
                }
                else if (command.ToLower() == "examples")
                {
                    Examples();
                }
                else if (command.ToLower() == "list-wfp")
                {
                    Log.Info("Dump F2B WFP provider and sublyer");
                    try
                    {
                        F2B.Firewall.Instance.DumpWFP();
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error(ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "add-wfp")
                {
                    Log.Info("Adding F2B WFP provider and sublyer");
                    try
                    {
                        F2B.Firewall.Instance.Install();
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error(ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "remove-wfp")
                {
                    Log.Info("Removing F2B WFP provider and sublyer");
                    try
                    {
                        F2B.Firewall.Instance.Uninstall();
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error(ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "list-privileges")
                {
                    Log.Info("List F2B WFP privileges");
                    try
                    {
                        F2B.Firewall.Instance.DumpPrivileges();
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error(ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "add-privileges")
                {
                    if (user != null)
                    {
                        Log.Info("Adding privileges to modify F2B firewall rules to account " + user);
                        try
                        {
                            F2B.Firewall.Instance.AddPrivileges(F2B.Sid.Get(user));
                        }
                        catch (FirewallException ex)
                        {
                            Log.Error(ex.Message);
                            Environment.Exit(1);
                        }
                    }
                    else
                    {
                        Console.WriteLine("ERROR: missing user argument");
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "remove-privileges")
                {
                    if (user != null)
                    {
                        Log.Info("Removing privileges to modify F2B firewall rules from account " + user);
                        try
                        {
                            F2B.Firewall.Instance.RemovePrivileges(F2B.Sid.Get(user));
                        }
                        catch (FirewallException ex)
                        {
                            Log.Error(ex.Message);
                            Environment.Exit(1);
                        }
                    }
                    else
                    {
                        Console.WriteLine("ERROR: missing user argument");
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "list-filters")
                {
                    try
                    {
                        var details = F2B.Firewall.Instance.List(true);
                        foreach (var item in F2B.Firewall.Instance.List())
                        {
                            try
                            {
                                Tuple<long, byte[]> fwname = FwData.DecodeName(item.Value);
                                string tmp = Convert.ToString(fwname.Item1);
                                try
                                {
                                    DateTime tmpExp = new DateTime(fwname.Item1, DateTimeKind.Utc);
                                    tmp = tmpExp.ToLocalTime().ToString();
                                }
                                catch (Exception)
                                {
                                }
                                Console.WriteLine("{0}: {1} (expiration={2}, md5={3}) ... {4}",
                                    item.Key, item.Value, tmp,
                                    BitConverter.ToString(fwname.Item2).Replace("-", ":"),
                                    details.ContainsKey(item.Key) ? details[item.Key] : "");
                            }
                            catch (ArgumentException)
                            {
                                // can't parse filter rule name to F2B structured data
                                Console.WriteLine("{0}: {1}", item.Key, item.Value);
                            }
                        }
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error("Unable to list firewall filters: " + ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "remove-filters")
                {
                    try
                    {
                        F2B.Firewall.Instance.Cleanup();
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error("Unable to remove all firewall filters: " + ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "remove-expired-filters")
                {
                    long currTime = DateTime.UtcNow.Ticks;

                    try
                    {
                        foreach (var item in F2B.Firewall.Instance.List())
                        {
                            try
                            {
                                Tuple<long, byte[]> fwname = FwData.DecodeName(item.Value);
                                if (currTime > fwname.Item1)
                                {
                                    Log.Info("Remove expired filter #" + item.Key
                                        + " (expiration=" + fwname.Item1 + ", md5="
                                        + BitConverter.ToString(fwname.Item2).Replace("-", ":")
                                        + ")");
                                    F2B.Firewall.Instance.Remove(item.Key);
                                }
                            }
                            catch (ArgumentException)
                            {
                                // can't parse filter rule name to F2B structured data
                                Log.Info("Unable to parse expiration time from filter #" + item.Key);
                            }
                        }
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error("Unable to remove expired firewall filters: " + ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "remove-unknown-filters")
                {
                    try
                    {
                        foreach (var item in F2B.Firewall.Instance.List())
                        {
                            try
                            {
                                Tuple<long, byte[]> fwname = FwData.DecodeName(item.Value);
                            }
                            catch (ArgumentException)
                            {
                                // can't parse filter rule name to F2B structured data
                                Log.Info("Remove filter #" + item.Key + " with unparsable filter name: " + item.Value);
                                F2B.Firewall.Instance.Remove(item.Key);
                            }
                        }
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error("Unable to remove unknown firewall filters: " + ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "add-filter")
                {
                    if (address == null)
                    {
                        Console.WriteLine("ERROR: missing address argument");
                        Environment.Exit(1);
                    }

                    IPAddress addr;
                    int prefix = 128;
                    if (address.IndexOf('/') > 0)
                    {
                        if (!IPAddress.TryParse(address.Substring(0, address.IndexOf('/')), out addr) || !int.TryParse(address.Substring(address.IndexOf('/') + 1), out prefix))
                        {
                            Console.WriteLine("ERROR: unable to parse address " + address);
                            Environment.Exit(1);
                        }
                    }
                    else
                    {
                        if (!IPAddress.TryParse(address, out addr))
                        {
                            Console.WriteLine("ERROR: unable to parse address " + address);
                            Environment.Exit(1);
                        }
                    }

                    try
                    {
                        if (expiration == 0)
                        {
                            string filterName = "F2B " + (permit ? "permit " : "block ") + address + " with no expiration" + (persistent ? " (persistent rule)" : "");
                            UInt64 filterIdNew = F2B.Firewall.Instance.Add(filterName, addr, prefix, weight, permit, persistent);
                            Log.Info("Added new filter #" + filterIdNew + " with name: " + filterName);
                        }
                        else
                        {
                            FwData fwdata = new FwData(expiration, addr, prefix);

                            // This code doesn't enumerate and check existing F2B firewall rules,
                            // but it must be updated together with changes in FwManager ... so
                            // to get consistent behavior in future it is better to use directly
                            // less optimal function from FwManager
                            // 
                            //byte[] hash = fwdata.Hash;
                            //FirewallConditions conds = fwdata.Conditions();
                            //
                            //// IPv4 filter layer
                            //if (conds.HasIPv4() || (!conds.HasIPv4() && !conds.HasIPv6()))
                            //{
                            //    byte[] hash4 = new byte[hash.Length];
                            //    hash.CopyTo(hash4, 0);
                            //    hash4[hash4.Length - 1] &= 0xfe;
                            //    string filterName = FwData.EncodeName(expiration, hash4);
                            //    UInt64 filterIdNew = F2B.Firewall.Instance.AddIPv4(filterName, conds);
                            //    Log.Info("Added new IPv4 filter #" + filterIdNew + " for " + addr + "/" + prefix + " with encoded name: " + filterName);
                            //}
                            //
                            //// IPv6 filter layer
                            //if (conds.HasIPv6() || (!conds.HasIPv4() && !conds.HasIPv6()))
                            //{
                            //    byte[] hash6 = new byte[hash.Length];
                            //    hash.CopyTo(hash6, 0);
                            //    hash6[hash6.Length - 1] |= 0x01;
                            //    string filterName = FwData.EncodeName(expiration, hash6);
                            //    UInt64 filterIdNew = F2B.Firewall.Instance.AddIPv4(filterName, conds);
                            //    Log.Info("Added new IPv6 filter #" + filterIdNew + " for " + addr + "/" + prefix + " with encoded name: " + filterName);
                            //}

                            FwManager.Instance.Add(fwdata, weight, permit, persistent);
                        }
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error("Unable to add firewall filter: " + ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "remove-filter")
                {
                    if (filterId == 0)
                    {
                        Console.WriteLine("ERROR: missing filterId argument");
                        Environment.Exit(1);
                    }
                    try
                    {
                        F2B.Firewall.Instance.Remove(filterId);
                    }
                    catch (FirewallException ex)
                    {
                        Log.Error("Unable to remove firewall filter: " + ex.Message);
                        Environment.Exit(1);
                    }
                }
                else
                {
                    Log.Error("Unknown F2BFwCmd command: " + command);
                    return;
                }

                // Waiting a key press to not return to VS directly
                if (System.Diagnostics.Debugger.IsAttached)
                {
                    Console.WriteLine();
                    Console.Write("=== Press a key to quit ===");
                    Console.ReadKey();
                    Console.WriteLine();
                }
            }

            Log.Info("F2BFwCmd main finished");
        }
    }
}
