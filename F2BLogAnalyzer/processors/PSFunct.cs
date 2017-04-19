#region Imports
using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
#endregion

namespace F2B.processors
{
    public class PSFunctProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string script;
        private string code = null;
        private string funct;
        private IList<Tuple<string, string>> pars;
        // NOTE: we could create multiple powershell instances
        //       to deal with long running powershell function
        // https://msdn.microsoft.com/en-us/library/ff458671(v=vs.110).aspx
        private PowerShell powershell = null;
        FileSystemWatcher watcher = null;
        #endregion

        #region Constructors
        public PSFunctProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["code"] != null && !string.IsNullOrWhiteSpace(config.Options["code"].Value))
            {
                code = config.Options["code"].Value;
            }

            if (code == null)
            {
                if (config.Options["script"] != null && !string.IsNullOrWhiteSpace(config.Options["script"].Value))
                {
                    script = config.Options["script"].Value;
                    if (File.Exists(script))
                    {
                        string dirname = Path.GetDirectoryName(script);
                        if (dirname == string.Empty)
                        {
                            dirname = Directory.GetCurrentDirectory();
                        }

                        // Create a new FileSystemWatcher and set its properties.
                        watcher = new FileSystemWatcher();
                        watcher.Path = dirname;
                        watcher.Filter = Path.GetFileName(script);
                        watcher.NotifyFilter = NotifyFilters.CreationTime | NotifyFilters.LastWrite;
                        watcher.Created += new FileSystemEventHandler((s, e) => FileWatcherChanged(s, e));
                        watcher.Changed += new FileSystemEventHandler((s, e) => FileWatcherChanged(s, e));
                    }
                    else
                    {
                        throw new InvalidDataException("script file \"" + script + "\" doesn't exists");
                    }
                }
                else
                {
                    throw new InvalidDataException("missing powershell code - code or script configuration option");
                }
            }

            if (config.Options["function"] != null && !string.IsNullOrWhiteSpace(config.Options["function"].Value))
            {
                funct = config.Options["function"].Value;
            }
            else
            {
                throw new InvalidDataException("required configuration option \"function\" missing or empty");
            }

            pars = new List<Tuple<string, string>>();
            if (config.Options["params"] != null && !string.IsNullOrWhiteSpace(config.Options["params"].Value))
            {
                foreach (string param in config.Options["params"].Value.Split(','))
                {
                    string template = "";

                    if (config.Options["param." + param] != null)
                    {
                        template = config.Options["param." + param].Value;
                    }
                    else
                    {
                        Log.Warn("missing required column template for param." + param);
                    }

                    pars.Add(new Tuple<string, string>(param, template));
                }
            }
            else
            {
                throw new InvalidDataException("required configuration option params missing or empty");
            }
        }

        ~PSFunctProcessor()
        {
            if (powershell != null)
            {
                powershell.Dispose();
            }
        }
        #endregion

        #region Methods
        private void InitializePowershell()
        {
            string newcode = code;

            if (watcher != null)
            {
                try
                {
                    using (StreamReader sr = new StreamReader(script))
                    {
                        newcode = sr.ReadToEnd();
                    }
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException("unable to read script file \"" + script + "\" doesn't exists: " + ex.Message);
                }
            }

            Log.Info(GetType() + "[" + Name + "]: powershell initialization started");

            PowerShell newps = PowerShell.Create();
            newps.AddScript(newcode, false);
            newps.Invoke();

            lock (this)
            {
                if (powershell != null)
                {
                    powershell.Dispose();
                }
                powershell = newps;
                code = newcode;
            }

            Log.Info(GetType() + "[" + Name + "]: powershell initialization finished");
        }

        private void FileWatcherChanged(object source, FileSystemEventArgs e)
        {
            WatcherChangeTypes wct = e.ChangeType;
            Log.Info(GetType() + "[" + Name + "]: FileWatcherChanged for \""
                + script + "\": " + wct.ToString() + ", " + e.FullPath);

            try
            {
                InitializePowershell();
            }
            catch (Exception ex)
            {
                Log.Error(GetType() + "[" + Name + "]: script \"" + script
                    + "\" updated, but powershell init failed (" + ex.Message
                    + "), using old instance with old script code");
            }
        }
        #endregion

        #region Override
        public override void Start()
        {
            InitializePowershell();

            if (watcher != null)
            {
                watcher.EnableRaisingEvents = true;
            }
        }

        public override void Stop()
        {
            if (watcher != null)
            {
                watcher.EnableRaisingEvents = false;
            }
        }

        public override string Execute(EventEntry evtlog)
        {
            lock (this)
            {
                ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);

                powershell.Commands.Clear();
                powershell.AddCommand(tpl.Apply(funct));
                foreach (Tuple<string, string> item in pars)
                {
                    powershell.AddParameter(item.Item1, tpl.Apply(item.Item2));
                }
                // we keep just last result from invoke call
                foreach (PSObject result in powershell.Invoke())
                {
                    evtlog.SetProcData(Name + ".Result", result.BaseObject);
                }
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            output.WriteLine("config script: " + script);
            output.WriteLine("config function: " + funct);
            foreach (Tuple<string, string> item in pars)
            {
                output.WriteLine("config param." + item.Item1 + ": " + item.Item2);
            }
            base.Debug(output);
        }
#endif
        #endregion
    }
}
