using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Configuration.Install;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

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
            Console.WriteLine("{0} command line arguments:", Process.GetCurrentProcess().ProcessName);
            Console.WriteLine("  help                show this help");
            Console.WriteLine("  run                 execute service interactively");
            Console.WriteLine("  install             apply required WPF modifications and register F2BFW service");
            Console.WriteLine("                      (use \"user\" to specify unprivileged account for F2BFW service)");
            Console.WriteLine("  uninstall           remove WPF modifications and unregister F2BFW service");
            Console.WriteLine("  start               start installed service");
            Console.WriteLine("  stop                stop installed service");
            Console.WriteLine("  list-filters        list all F2BFW filters");
            Console.WriteLine("  add-filter          add F2BFW filte rule");
            Console.WriteLine("  remove-filter       remove F2BFW filter rule with filterId");
            Console.WriteLine("  remove-all-filters  remove all F2BFW filters");
            Console.WriteLine("  remove-expired-filters remove expired F2BFW filters");
            Console.WriteLine("  remove-unknown-filters remove F2BFW filters with invalid name");
            Console.WriteLine("  list-privileges     show WFP security descriptors");
            Console.WriteLine("  add-privileges      add user to WFP security descriptors");
            Console.WriteLine("  remove-privileges   remove user from WFP security descriptors");
#if DEBUG
            Console.WriteLine("Additional command line arguments in debug build:");
            Console.WriteLine("  hash                test hash function");
            Console.WriteLine("  wfp                 test Firewall module");
            Console.WriteLine("  wfpperf             test Firewall module performance (add/remove 100k rules)");
            Console.WriteLine("  wfpperfraw          test raw wfp performance (add/remove 100k rules)");
            Console.WriteLine("  wfpdump             dump all providers, layers, sublayers, filters");
            Console.WriteLine("  mq                  test MsmqComm module");
            Console.WriteLine("  mqrule              send/receive FWDATA rule");
#endif
            Console.WriteLine("Options:");
            Console.WriteLine("  -h          show this help");
            Console.WriteLine("  -l          log severity level (INFO, WARN, ERROR)");
            Console.WriteLine("  -g file     log file");
            Console.WriteLine("  -u user     use given user to run this service");
            Console.WriteLine("  -H host     hostname with running F2BQueue (or F2BLogAnalyzer) service");
            Console.WriteLine("  -p queue    producer queue provided by F2BQueue (or F2BLogAnalyzer) service");
            Console.WriteLine("  -r queue    subscription queue for F2BQueue service");
            Console.WriteLine("  -i interv   subscribe interval in seconds (default 60, disable 0)");
            Console.WriteLine("  -n interv   cleanup interval for expired filter rules in seconds (default 30, disable 0)");
            Console.WriteLine("  -m size     maximum number of filter rules in WFP (default 0 - no limit)");
            Console.WriteLine("  -a	IPAddr/p IPv4 or IPv6 address and optional prefix length");
            Console.WriteLine("  -e	expir    expiration time in windows UTC time ticks");
            Console.WriteLine("  -w weight   filter rule priority");
            Console.WriteLine("  -t          permit filter rule");
            Console.WriteLine("  -s          persistent filter rule (survive machine reboot)");
            Console.WriteLine("  -f	filterId filter identifier");
            Console.WriteLine("Examples:");
            Console.WriteLine("  # service startup command for F2BQueue running on HOST with f2buser privileges");
            Console.WriteLine("  F2BFirewall.exe run -h HOST -r F2BFWRegistration -i 60 -u f2buser");
            Console.WriteLine("  # service startup command for direct communication with F2BLogAnalyzer with f2buser privileges");
            Console.WriteLine("  F2BFirewall.exe run -h . -p F2BFWProvider -u f2buser");
            Console.WriteLine("  # register F2BFirewall service and allow \"DOMAIN\\username\" to modify firewall filters");
            Console.WriteLine("  F2BFirewall.exe install [-u DOMAIN\\username] [-h HOST] [-r F2BFWRegistration] [-i 60] [-n 30]");
            Console.WriteLine("  # unregister F2BFirewall service and remove \"DOMAIN\\username\" privileges for firewall filters");
            Console.WriteLine("  F2BFirewall.exe uninstall [-u DOMAIN\\username]");
            Console.WriteLine("  # add privileges F2B firewall rules to \"DOMAIN\\username\"");
            Console.WriteLine("  F2BFirewall.exe add-privileges [-u DOMAIN\\username]");
            Console.WriteLine("  # remove privileges F2B firewall rules from \"DOMAIN\\username\"");
            Console.WriteLine("  F2BFirewall.exe remove-privileges [-u DOMAIN\\username]");
            Console.WriteLine("  # list all F2B filter rules");
            Console.WriteLine("  F2BFirewall.exe list-filters");
            Console.WriteLine("  # add F2B firewall filter for 192.0.2.123/24 with 5 minute expiration");
            Console.WriteLine("  F2BFirewall.exe add-filter --address 192.0.2.123/24 --expiration " + (DateTime.UtcNow.Ticks + 5 * 60 * TimeSpan.TicksPerSecond));
            Console.WriteLine("  # add pernament F2B firewall filter with hight priority which permits access from 192.0.2.234");
            Console.WriteLine("  F2BFirewall.exe add-filter --address 192.0.2.234 --weight 16 --permit --persistent");
            Console.WriteLine("  # remove filter with ID 12345678 (only F2B rules can be removed)");
            Console.WriteLine("  F2BFirewall.exe remove-filter --filter-id 12345678");
            Console.WriteLine("  # show debug info using DbgView from SysInternals");
            Console.WriteLine("  DbgView.exe");
            Console.WriteLine("Manage service manually:");
            Console.WriteLine("  # register WPF provider with GUID " + F2B.Firewall.PROVIDER_KEY);
            Console.WriteLine("  # register WPF subLayer with GUID " + F2B.Firewall.SUBLAYER_KEY);
            Console.WriteLine("  # add user ACL to WPF provider, subLayer and filter if you want run this service with unprivileged account");
            Console.WriteLine("  # create " + Service.NAME + " service");
            Console.WriteLine("  sc create " + Service.NAME + " binPath= \"C:\\path\\to\\executable\\F2BFirewall.exe\" DisplayName= \"" + Service.DISPLAY + "\" type= own start= auto depend= eventlog/BFE/MSMQ");
            Console.WriteLine("  sc description " + Service.NAME + " \"" + Service.DESCR + "\"");
            Console.WriteLine("  sc queryex " + Service.NAME);
            Console.WriteLine("  sc start " + Service.NAME);
            Console.WriteLine("  sc stop " + Service.NAME);
            Console.WriteLine("  sc delete " + Service.NAME);
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
            string host = null;
            string producerQueue = null;
            string registrationQueue = null;
            int registrationInterval = 60;
            int cleanupExpiredInterval = 30;
            int maxFilterRules = 0;
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
                else if (param == "-H" || param == "-host" || param == "--host")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        host = args[i];
                    }
                }
                else if (param == "-p" || param == "-producer-queue" || param == "--producer-queue")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        producerQueue = args[i];
                    }
                }
                else if (param == "-r" || param == "-registration-queue" || param == "--registration-queue")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        registrationQueue = args[i];
                    }
                }
                else if (param == "-i" || param == "-registration-interval" || param == "--registration-interval")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        registrationInterval = int.Parse(args[i]);
                    }
                }
                else if (param == "-n" || param == "-cleanup-interval" || param == "--cleanup-interval")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        cleanupExpiredInterval = int.Parse(args[i]);
                    }
                }
                else if (param == "-m" || param == "-max-size" || param == "--max-size")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        maxFilterRules = int.Parse(args[i]);
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

            string[] serviceNamesToRun = new string[]
            {
                Service.NAME,
            };

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
                Log.Info("F2BFirewall in interactive mode executing command: " + command);
            }

            if (Environment.UserInteractive && command.ToLower() != "run")
            {
                if (command.ToLower() == "help")
                {
                    Usage();
                }
                else if (command.ToLower() == "install" || command.ToLower() == "uninstall")
                {
                    List<string> l = new List<string>();
                    if ((Log.Dest & Log.Destinations.EventLog) != 0)
                    {
                        l.Add(string.Format("f2bLogLevel={0}", Log.Level));
                    }
                    if ((Log.Dest & Log.Destinations.File) != 0 && !string.IsNullOrEmpty(Log.File))
                    {
                        l.Add(string.Format("f2bLogLevel={0}", Log.Level));
                        l.Add(string.Format("f2bLogFile={0}", Log.File));
                    }
                    if (user != null)
                    {
                        l.Add(string.Format("f2bUser={0}", user));
                    }
                    if (host != null)
                    {
                        l.Add(string.Format("f2bHost={0}", host));
                    }
                    if (producerQueue != null)
                    {
                        l.Add(string.Format("f2bProducerQueue={0}", producerQueue));
                    }
                    if (registrationQueue != null)
                    {
                        l.Add(string.Format("f2bRegistrationQueue={0}", registrationQueue));
                    }
                    if (registrationInterval != 0)
                    {
                        l.Add(string.Format("f2bRegistrationInterval={0}", registrationInterval));
                    }
                    if (cleanupExpiredInterval != 0)
                    {
                        l.Add(string.Format("f2bCleanupExpiredInterval={0}", cleanupExpiredInterval));
                    }

                    if (command.ToLower() == "install") // Install
                    {
                        Log.Info("Installing " + Service.NAME + " (" + Service.DISPLAY + ")");

                        //ManagedInstallerClass.InstallHelper(new String[] { typeof(Program).Assembly.Location });
                        Install(false, l.ToArray());

                        Log.Info("Adding F2B WFP provider and sublyer");
                        try
                        {
                            F2B.Firewall.Instance.Install();
                        }
                        catch (Exception ex)
                        {
                            Log.Error(ex.Message);
                            throw;
                        }

                        if (user != null)
                        {
                            Log.Info("Adding privileges to modify F2B firewall rules to account " + user);
                            F2B.Firewall.Instance.AddPrivileges(F2B.Sid.Get(user));
                        }
                    }
                    else // Uninstall
                    {
                        if (user != null)
                        {
                            Log.Info("Removing privileges to modify F2B firewall rules from account " + user);
                            F2B.Firewall.Instance.RemovePrivileges(F2B.Sid.Get(user));
                        }

                        Log.Info("Removing F2B WFP provider, sublyer and all filter rules");
                        try
                        {
                            F2B.Firewall.Instance.Uninstall();
                        }
                        catch (Exception ex)
                        {
                            Log.Error(ex.Message);
                            throw;
                        }

                        Log.Info("Uninstalling " + Service.NAME + " (" + Service.DISPLAY + ")");

                        //ManagedInstallerClass.InstallHelper(new String[] { "/u", typeof(Program).Assembly.Location });
                        Install(true, l.ToArray());
                    }
                }
                else if (command.ToLower() == "start")
                {
                    try
                    {
                        foreach (var serviceName in serviceNamesToRun)
                        {
                            ServiceController sc = new ServiceController(serviceName);
                            if (sc.Status == ServiceControllerStatus.Stopped)
                            {
                                sc.Start();
                                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(10));
                                Log.Info("Service " + sc.ServiceName + " (" + sc.DisplayName + ") is now in " + sc.Status + " state");
                            }
                            else
                            {
                                Log.Info("Service " + sc.ServiceName + " (" + sc.DisplayName + ") is not stopped, state = " + sc.Status);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "stop")
                {
                    try
                    {
                        foreach (var serviceName in serviceNamesToRun)
                        {
                            ServiceController sc = new ServiceController(serviceName);
                            if (sc.Status == ServiceControllerStatus.Running)
                            {
                                sc.Stop();
                                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                                Log.Info("Service " + sc.ServiceName + " (" + sc.DisplayName + ") is now in " + sc.Status + " state");
                            }
                            else
                            {
                                Log.Info("Service " + sc.ServiceName + " (" + sc.DisplayName + ") is not running, state = " + sc.Status);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex.Message);
                        Environment.Exit(1);
                    }
                }
                else if (command.ToLower() == "list-privileges")
                {
                    F2B.Firewall.Instance.DumpPrivileges();
                }
                else if (command.ToLower() == "add-privileges")
                {
                    if (user != null)
                    {
                        Log.Info("Adding privileges to modify F2B firewall rules to account " + user);
                        F2B.Firewall.Instance.AddPrivileges(F2B.Sid.Get(user));
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
                        F2B.Firewall.Instance.RemovePrivileges(F2B.Sid.Get(user));
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
                        foreach (var item in F2B.Firewall.Instance.List())
                        {
                            try
                            {
                                Tuple<long, byte[]> fwname = FwData.DecodeName(item.Value);
                                string tmp = Convert.ToString(fwname.Item1);
                                try
                                {
                                    DateTime tmpExp = new DateTime(fwname.Item1);
                                    tmp = tmpExp.ToLocalTime().ToString();
                                }
                                catch (Exception)
                                {
                                }
                                Console.WriteLine("{0}: {1} (expiration={2}, md5={3})",
                                    item.Key, item.Value, tmp,
                                    BitConverter.ToString(fwname.Item2).Replace("-", ":"));
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
                else if (command.ToLower() == "remove-all-filters")
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
                        if (!IPAddress.TryParse(address.Substring(0, address.IndexOf('/')), out addr) || !int.TryParse(address.Substring(address.IndexOf('/')+1), out prefix))
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
                    Log.Error("Unknown F2BFirewall command: " + command);
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
            else
            {
                if (string.IsNullOrEmpty(host))
                {
                    Log.Error("Missing host command line argument");
                    //Usage();
                    Environment.Exit(1);
                }

                if (string.IsNullOrEmpty(producerQueue) && string.IsNullOrEmpty(registrationQueue))
                {
                    Log.Error("Can't start without production or registration queue name");
                    //Usage();
                    Environment.Exit(1);
                }

                if (!string.IsNullOrEmpty(producerQueue) && !string.IsNullOrEmpty(registrationQueue))
                {
                    Log.Error("Specify only one queue (producer of registration)");
                    //Usage();
                    Environment.Exit(1);
                }

                if (!string.IsNullOrEmpty(registrationQueue) && !(registrationInterval > 0))
                {
                    Log.Warn("Using registration queue without specifying registration interval doesn't make too much sense");
                }

                if (!(cleanupExpiredInterval > 0))
                {
                    Log.Warn("Running without specifying cleanup interval doesn't make too much sense");
                }

                // Initialize the service to start
                ServiceBase[] servicesToRun = new ServiceBase[]
                {
                    new Service(host, producerQueue, registrationQueue, registrationInterval, cleanupExpiredInterval, maxFilterRules),
                };

                if (!Environment.UserInteractive)
                {
                    // Start windows service
                    ServiceBase.Run(servicesToRun);
                }
                else // command.ToLower() == "run"
                {
                    // Get the method to invoke on each service to start it
                    MethodInfo onStartMethod = typeof(ServiceBase).GetMethod("OnStart", BindingFlags.Instance | BindingFlags.NonPublic);

                    // Start services loop
                    foreach (ServiceBase service in servicesToRun)
                    {
                        Log.Info("Starting " + service.ServiceName + " ...");
                        onStartMethod.Invoke(service, new object[] { new string[] { } });
                    }

                    // Waiting the end
                    string help = "Interactive help\n"
                        + "  press 'h' key for this help\n"
                        + "  press 'q' key to quit\n"
                        + "  press 'f' key to reread WFP F2B filter rules\n"
#if DEBUG
                        + "  press 'd' key to write debug info\n"
#endif
                        ;
                    Console.Write(help);
                    while (true)
                    {
                        ConsoleKeyInfo key = Console.ReadKey();
                        if (key.KeyChar == 'q')
                        {
                            Log.Info("Quit key pressed");
                            break;
                        }
                        else if (key.KeyChar == 'h')
                        {
                            Log.Info("Interactive help");
                            Console.Write(help);
                        }
                        else if (key.KeyChar == 'f')
                        {
                            Log.Info("Reread F2B filter rules from WFP");
                            F2B.FwManager.Instance.Refresh();
                        }
#if DEBUG
                        else if (key.KeyChar == 'd')
                        {
                            Log.Info("Debug key pressed");
                            ((Service)servicesToRun[0]).Dump();
                        }
#endif
                        else
                        {
                            Console.WriteLine("Unsupported key " + key.KeyChar);
                        }
                    }

                    // Get the method to invoke on each service to stop it
                    MethodInfo onStopMethod = typeof(ServiceBase).GetMethod("OnStop", BindingFlags.Instance | BindingFlags.NonPublic);

                    // Stop loop
                    foreach (ServiceBase service in servicesToRun)
                    {
                        Log.Info("Stopping " + service.ServiceName + " ...");
                        onStopMethod.Invoke(service, null);
                    }

                    Log.Info("Debug F2B service finished");
                }
            }

            Log.Info("F2BFirewall main finished");
        }


        static void Install(bool undo, string[] args)
        {
            try
            {
                using (AssemblyInstaller inst = new AssemblyInstaller(typeof(Program).Assembly, args))
                {
                    IDictionary state = new Hashtable();
                    inst.UseNewContext = true;
                    try
                    {
                        if (undo)
                        {
                            inst.Uninstall(state);
                        }
                        else
                        {
                            inst.Install(state);
                            inst.Commit(state);
                        }
                    }
                    catch
                    {
                        try
                        {
                            inst.Rollback(state);
                        }
                        catch { }
                        throw;
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex.Message);
            }
        }
    }
}
