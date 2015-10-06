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
    public static class Program
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
            Console.WriteLine("  help                  show this help");
            Console.WriteLine("  examples              show command line examples");
            Console.WriteLine("  run                   execute service interactively");
            Console.WriteLine("  install               install as windows service");
            Console.WriteLine("  uninstall             uninstall windows service");
            Console.WriteLine("  start                 start installed service");
            Console.WriteLine("  stop                  stop installed service");
            Console.WriteLine("Options");
            Console.WriteLine("  -h, --help            show this help");
            Console.WriteLine("  -l, --log-level       log severity level (INFO, WARN, ERROR)");
            Console.WriteLine("  -g, --log-file file   log file");
            Console.WriteLine("  -c, --config file     use this configuration (default: F2BLogAnalyzer.exe.config)");
            Console.WriteLine("  -u, --user user       use given user to run this service");
        }

        public static void Examples()
        {
            Console.WriteLine("Examples:");
            Console.WriteLine("  # Interactive run for debuging");
            Console.WriteLine("  F2BLogAnalyzer.exe run -c F2BLogAnalyzer.config");
            Console.WriteLine("  # Manage F2BLogAnalyzer service");
            Console.WriteLine("  F2BLogAnalyzer.exe install -c c:\\F2B\\F2BLogAnalyzer.config [-u DOMAIN\\username] [-l INFO] [-g c:\\F2B\\F2BLogAnalyzer.log]");
            Console.WriteLine("  F2BLogAnalyzer.exe start");
            Console.WriteLine("  F2BLogAnalyzer.exe stop");
            Console.WriteLine("  F2BLogAnalyzer.exe uninstall");
            Console.WriteLine("Manual F2BLogAnalyzer service installation:");
            Console.WriteLine("  # create " + Service.NAME + " service");
            Console.WriteLine("  sc create " + Service.NAME + " binPath= \"C:\\path\\to\\executable\\F2BLogAnalyzer.exe\" DisplayName= \"" + Service.DISPLAY + "\" type= own start= auto depend= eventlog/MSMQ");
            Console.WriteLine("  sc description " + Service.NAME + " \"" + Service.DESCR + "\"");
            Console.WriteLine("  sc queryex " + Service.NAME);
            Console.WriteLine("  sc qc " + Service.NAME);
            Console.WriteLine("  sc start " + Service.NAME);
            Console.WriteLine("  sc stop " + Service.NAME);
            Console.WriteLine("  sc delete " + Service.NAME);
            Console.WriteLine("User access to windows event log");
            Console.WriteLine("  # Add user to \"Event Log Readers\" group or change directly log SDDL, e.g.");
            Console.WriteLine("  wevtutil gl Application");
            Console.WriteLine("  wevtutil sl Application /ca:...(A;;0x3;;;\"SID\")");
        }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        public static void Main(string[] args)
        {
            string user = null;
            ConfigFile = AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;
            Log.Dest = Log.Destinations.EventLog;
            Log.Level = EventLogEntryType.Information;

            int i = 0;
            String command = null;
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
                        switch (args[i].ToUpper()) {
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

            // Initialize the service to start
            ServiceBase[] servicesToRun;
            servicesToRun = new ServiceBase[]
            {
                new Service()
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
                Log.Info("F2BLogAnalyzer in interactive mode executing command: " + command);

                if (command.ToLower() == "help")
                {
                    Usage();
                }
                else if (command.ToLower() == "examples")
                {
                    Examples();
                }
                else if (command.ToLower() == "run")
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
                    if (ConfigFile != null)
                    {
                        l.Add(string.Format("f2bConfig={0}", ConfigFile));
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
                        foreach (var service in servicesToRun)
                        {
                            ServiceController sc = new ServiceController(service.ServiceName);
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
                        foreach (var service in servicesToRun)
                        {
                            ServiceController sc = new ServiceController(service.ServiceName);
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
                    Log.Error("Unknown F2BLogAnalyzer command: " + command);
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
                ServiceBase.Run(servicesToRun);
            }

            Log.Info("F2BLogAnalyzer main finished");
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
