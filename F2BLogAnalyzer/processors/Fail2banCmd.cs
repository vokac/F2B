#region Imports
using System;
using System.IO;
using System.Messaging;
using System.Net;
using System.Runtime.Caching;
#endregion

namespace F2B.processors
{
    public class Fail2banCmdProcessor : Fail2banActionProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string path;
        private string args;
        #endregion

        #region Constructors
        public Fail2banCmdProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            path = "F2BFirewall.exe";
            if (config.Options["path"] != null)
            {
                path = Environment.ExpandEnvironmentVariables(config.Options["path"].Value);
            }

            args = "add-filter /address ${Fail2ban.address} /expiration ${Fail2ban.expiration}/${Fail2ban.prefix}";
            if (config.Options["args"] != null)
            {
                args = Environment.ExpandEnvironmentVariables(config.Options["args"].Value);
            }
        }
        #endregion

        #region Override
        protected override void ExecuteFail2banAction(EventEntry evtlog, IPAddress addr, int prefix, long expiration)
        {
            ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);

            // run process without creating window
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = path;
            startInfo.Arguments = tpl.ExpandTemplateVariables(args);
            startInfo.UseShellExecute = false;
            //startInfo.EnvironmentVariables.Add("F2B_ADDRESS", address);
            //startInfo.EnvironmentVariables.Add("F2B_EXPIRATION", expiration.ToString());
            process.StartInfo = startInfo;
            Log.Info("Fail2banCmdProcessor: executing command: " + startInfo.FileName + " " + startInfo.Arguments);
            process.Start();
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            output.WriteLine("config path: " + path);
            output.WriteLine("config args: " + args);
            base.Debug(output);
        }
#endif
        #endregion
    }
}
