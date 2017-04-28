using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Configuration.Install;
using System.Diagnostics;
using System.Linq;
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
            Version v = Assembly.GetExecutingAssembly().GetName().Version;
            string pname = Process.GetCurrentProcess().ProcessName;
            string vcinfo = string.Format("{0}[{1}] {2} ({3})", VCS.type, VCS.branch, VCS.commit, VCS.status);
            Console.WriteLine("{0} version {1}.{2}.{3} (r{4}), {5}", pname, v.Major, v.Minor, v.Build, v.Revision, vcinfo);
            Console.WriteLine("Command line arguments:");
            Console.WriteLine("  help                show this help");
            Console.WriteLine("  examples            show command line examples");
            Console.WriteLine("  run                 execute service interactively");
            Console.WriteLine("  install             install as windows service");
            Console.WriteLine("  uninstall           uninstall windows service");
            Console.WriteLine("  start               start installed service");
            Console.WriteLine("  stop                stop installed service");
            Console.WriteLine("Options");
            Console.WriteLine("  -h, --help          show this help");
            Console.WriteLine("  -l, --log-level     log severity level (INFO, WARN, ERROR)");
            Console.WriteLine("  -g, --log-file file log filename (disables event log or console logging)");
            Console.WriteLine("  --log-size size     maximum log file size");
            Console.WriteLine("  --log-history cnt   number of rotated log files");
            Console.WriteLine("  -c, --config file   use this configuration (default: F2BQueue.exe.config)");
            Console.WriteLine("  -s, --state file    read/write queue state to file");
            Console.WriteLine("  -u, --user user     use given user to run this service");
            Console.WriteLine("  -x, --mex-mem size  configure hard limit for memory in MB (Job Object)");
            Console.WriteLine("  -H, --host host     hostname with running F2BQueue (or F2BLogAnalyzer) service");
            Console.WriteLine("  -p queue            producer queue provided by F2BQueue (or F2BLogAnalyzer) service");
            Console.WriteLine("  -r queue            subscription queue for F2BQueue service");
            Console.WriteLine("  -i interv           unsubscribe interval in seconds (default 150, disable 0)");
            Console.WriteLine("  -n interv           cleanup interval for expired filter rules in seconds (default 300, disable 0)");
            Console.WriteLine("  -m, --max-size size maximum size of non-expired records in queue (default 0 - no limit)");
        }

        public static void Examples()
        {
            string pname = Process.GetCurrentProcess().ProcessName;
            Console.WriteLine("Examples:");
            Console.WriteLine("  rem Interactive run for debuging");
            Console.WriteLine("  {0} run -H . -p F2BProducer -r F2BSubscription -s c:\\F2B\\queue.dat -i 300 -n 150", pname);
            Console.WriteLine("  rem Manage F2BQueue service");
            Console.WriteLine("  {0} install [-u DOMAIN\\username] [-h HOST] [-p F2BFWProduction] [-r F2BFWRegistration] [-i 150] [-n 300] [-s c:\\F2B\\queue.dat] [-l INFO] [-g c:\\F2B\\F2BQueue.log]", pname);
            Console.WriteLine("  {0} start", pname);
            Console.WriteLine("  {0} stop", pname);
            Console.WriteLine("  {0} uninstall", pname);
            Console.WriteLine("Manual F2BQueue service installation:");
            Console.WriteLine("  sc create " + Service.NAME + " binPath = \"C:\\path\\to\\executabla\\F2BQueue.exe\" DisplayName= \"" + Service.DISPLAY + "\" type= own start= auto depend= eventlog/MSMQ");
            Console.WriteLine("  sc description " + Service.NAME + " \"" + Service.DESCR + "\"");
            Console.WriteLine("  sc queryex " + Service.NAME);
            Console.WriteLine("  sc qc " + Service.NAME);
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
            string StateFile = null;
            string user = null;
            ulong maxmem = 0;
            string host = null;
            string producerQueue = null;
            string registrationQueue = null;
            int unsubscribeInterval = 150;
            int cleanupExpiredInterval = 300;
            int maxQueueSize = 0;

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
                else if (param == "-s" || param == "-state" || param == "--state")
                {
                    if (i + 1 < args.Length)
                    {
                        i++;
                        StateFile = args[i];
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
                        unsubscribeInterval = int.Parse(args[i]);
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
                        maxQueueSize = int.Parse(args[i]);
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
                else if (command.ToLower() == "examples")
                {
                    Examples();
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
                    if (StateFile != null)
                    {
                        l.Add(string.Format("f2bState={0}", StateFile));
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
                    if (unsubscribeInterval != 0)
                    {
                        l.Add(string.Format("f2bRegistrationInterval={0}", unsubscribeInterval));
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
                    }
                    else // Uninstall
                    {
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
                else
                {
                    Log.Error("Unknown F2BQueue command: " + command);
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

                if (string.IsNullOrEmpty(producerQueue) || string.IsNullOrEmpty(registrationQueue))
                {
                    Log.Error("Both production and registration queue must be defined");
                    //Usage();
                    Environment.Exit(1);
                }

                if (!(unsubscribeInterval > 0))
                {
                    Log.Warn("Using application without unregistration interval is not optimal");
                }

                if (!(cleanupExpiredInterval > 0))
                {
                    Log.Warn("Running without specifying cleanup interval doesn't make too much sense");
                }

                // Initialize the service to start
                ServiceBase[] servicesToRun = new ServiceBase[]
                {
                    new Service(host, producerQueue, registrationQueue, unsubscribeInterval, cleanupExpiredInterval, maxQueueSize, StateFile),
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

            Log.Info("F2BQueue main finished");
        }


        static void Install(bool undo, string[] args)
        {
            try
            {
                Log.Info(undo ? "uninstalling" : "installing");
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
