#region Imports
using System;
using System.IO;
using System.Net;
#endregion

namespace F2B.processors
{
    public class CmdProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string path = null;
        private string args = "";
        private bool waitForExit = true;
        #endregion

        #region Constructors
        public CmdProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["path"] != null)
            {
                path = Environment.ExpandEnvironmentVariables(config.Options["path"].Value);
            }

            if (config.Options["args"] != null)
            {
                args = Environment.ExpandEnvironmentVariables(config.Options["args"].Value);
            }

            if (config.Options["wait_for_exit"] != null)
            {
                waitForExit = bool.Parse(config.Options["wait_for_exit"].Value);
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (path == null)
            {
                return goto_next;
            }

            ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);

            // run process without creating window
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = tpl.Apply(path);
            startInfo.Arguments = tpl.Apply(args);
            startInfo.UseShellExecute = false;
            Log.Info("CmdProcessor: executing command: " + startInfo.FileName + " " + startInfo.Arguments);
            System.Diagnostics.Process process = System.Diagnostics.Process.Start(startInfo);
            if (process != null && waitForExit)
            {
                process.WaitForExit();
                evtlog.SetProcData(Name + ".ExitCode", process.ExitCode);
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            output.WriteLine("config path: " + path);
            output.WriteLine("config args: " + args);
            output.WriteLine("config wait_for_exit: " + waitForExit);
            base.Debug(output);
        }
#endif
        #endregion
    }
}
