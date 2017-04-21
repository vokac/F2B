#region Imports
using System;
using System.IO;
using System.Management.Automation;
#endregion

namespace F2B.processors
{
    public class PSProcProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string script;
        private string funct_start = "PSProcStart";
        private string funct_stop = "PSProcStop";
        private string funct_execute = "PSProcExecute";
        private bool threadsafe = true;
        private PowerShell powershell = null;
        #endregion

        #region Constructors
        public PSProcProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["script"] != null && !string.IsNullOrWhiteSpace(config.Options["script"].Value))
            {
                script = config.Options["script"].Value;
                if (!File.Exists(script))
                {
                    throw new InvalidDataException("script file \"" + script + "\" doesn't exists");
                }
            }
            else
            {
                throw new InvalidDataException("missing powershell code - code or script configuration option");
            }

            if (config.Options["funct_start"] != null)
            {
                funct_start = config.Options["funct_start"].Value;
            }
            if (config.Options["funct_stop"] != null)
            {
                funct_stop = config.Options["funct_stop"].Value;
            }
            if (config.Options["funct_execute"] != null)
            {
                funct_execute = config.Options["funct_execute"].Value;
            }

            if (config.Options["threadsafe"] != null)
            {
                threadsafe = bool.Parse(config.Options["threadsafe"].Value);
            }

            string code;
            try
            {
                using (StreamReader sr = new StreamReader(script))
                {
                    code = sr.ReadToEnd();
                }
            }
            catch (Exception ex)
            {
                throw new InvalidDataException("unable to read script file \"" + script + "\" doesn't exists: " + ex.Message);
            }

            Log.Info(GetType() + "[" + Name + "]: powershell initialization started");
            powershell = PowerShell.Create();
            powershell.AddScript(code, false);
            powershell.AddParameter("proc", this);
            powershell.Invoke();
            Log.Info(GetType() + "[" + Name + "]: powershell initialization finished");
        }

        ~PSProcProcessor()
        {
            if (powershell != null)
            {
                powershell.Dispose();
            }
        }
        #endregion

        #region Override
        public override void Start()
        {
            if (!string.IsNullOrEmpty(funct_start))
            {
                powershell.Commands.Clear();
                powershell.AddCommand(funct_start);
                powershell.Invoke();
            }
        }

        public override void Stop()
        {
            if (!string.IsNullOrEmpty(funct_stop))
            {
                powershell.Commands.Clear();
                powershell.AddCommand(funct_stop);
                powershell.Invoke();
            }
        }

        public override string Execute(EventEntry evtlog)
        {
            string ret = goto_next;
            if (string.IsNullOrEmpty(funct_execute))
            {
                return ret;
            }

            lock (this)
            {
                powershell.Commands.Clear();
                powershell.AddCommand(funct_execute);
                powershell.AddParameter("evtlog", evtlog);
                foreach (PSObject result in powershell.Invoke())
                {
                    string res = result.BaseObject.ToString();
                    if (res == "NEXT")
                    {
                        ret = goto_next;
                    }
                    else if (res == "ERROR")
                    {
                        ret = goto_error;
                    }
                    else if (res.StartsWith("GOTO "))
                    {
                        ret = res.Substring(5);
                    }
                    else
                    {
                        Log.Warn(GetType() + "[" + Name + "]: unexpected return value: " + res);
                    }
                }
            }

            return ret;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            output.WriteLine("config script: " + script);
            output.WriteLine("config funct_start: " + funct_start);
            output.WriteLine("config funct_stop: " + funct_stop);
            output.WriteLine("config funct_execute: " + funct_execute);
            output.WriteLine("config threadsafe: " + threadsafe);
            base.Debug(output);
        }
#endif
        #endregion
    }
}
