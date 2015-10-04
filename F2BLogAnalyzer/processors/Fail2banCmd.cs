#region Imports
using System;
using System.IO;
using System.Messaging;
using System.Net;
using System.Runtime.Caching;
#endregion

namespace F2B.processors
{
    public class Fail2banCmdProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string path;
        private string args;
        private int max_ignore;
        private int bantime;

        private MemoryCache recent;
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

            args = "add-filter /a %F2B_ADDRESS% /e %F2B_EXPIRATION%";
            if (config.Options["args"] != null)
            {
                args = Environment.ExpandEnvironmentVariables(config.Options["args"].Value);
            }

            max_ignore = 60;
            if (config.Options["max_ignore"] != null)
            {
                max_ignore = int.Parse(config.Options["max_ignore"].Value);
            }

            bantime = 60;
            if (config.Options["bantime"] != null)
            {
                bantime = int.Parse(config.Options["bantime"].Value);
            }

            //recent = new MemoryCache("F2B." + Name + ".recent");
            recent = new MemoryCache(GetType() + ".recent");
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (!evtlog.HasProcData("Fail2ban.address"))
            {
                throw new ArgumentException("Missing Fail2ban.address, invalid/misspelled configuration?!");
            }
            if (!evtlog.HasProcData("Fail2ban.prefix"))
            {
                throw new ArgumentException("Missing Fail2ban.prefix, invalid/misspelled configuration?!");
            }

            IPAddress addr = evtlog.GetProcData<IPAddress>("Fail2ban.address");
            int prefix = evtlog.GetProcData<int>("Fail2ban.prefix");
            int btime = evtlog.GetProcData("Fail2ban.bantime", bantime);

            // check in memory cache with recently send F2B messages
            string recentKey = null;
            long now = DateTimeOffset.Now.Ticks;
            if (max_ignore > 0)
            {
                recentKey = Name + "[" + addr + "/" + prefix + "]";
                object cacheEntry = recent[recentKey];

                if (cacheEntry != null)
                {
                    Tuple<long, int> item = (Tuple<long, int>)cacheEntry;
                    long ticksDiff = Math.Abs(item.Item1 - now);

                    if (ticksDiff < TimeSpan.FromSeconds(btime).Ticks / 100)
                    {
                        Log.Info("Skipping F2B firewall for recent address ("
                            + TimeSpan.FromTicks(ticksDiff).TotalSeconds + "s ago)");

                        return goto_next;
                    }
                }
            }

            string address;
            long expiration = DateTime.UtcNow.Ticks + btime * 100L * 1000L * 1000L;

            if (addr.IsIPv4MappedToIPv6)
            {
                address = addr.MapToIPv4().ToString() + "/" + (prefix - 96);
            }
            else
            {
                address = addr.ToString() + "/" + prefix;
            }

            // run process without creating window
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = path;
            startInfo.Arguments = args.Replace("%F2B_ADDRESS%", address).Replace("%F2B_EXPIRATION%", expiration.ToString());
            startInfo.UseShellExecute = false;
            //startInfo.EnvironmentVariables.Add("F2B_ADDRESS", address);
            //startInfo.EnvironmentVariables.Add("F2B_EXPIRATION", expiration.ToString());
            process.StartInfo = startInfo;
            Log.Info("Fail2banCmdProcessor: executing command: " + startInfo.FileName + " " + startInfo.Arguments);
            process.Start();

            // add this message to in memory cache of recently send F2B messages
            if (max_ignore > 0)
            {
                long bantimeTicks = TimeSpan.FromSeconds(btime).Ticks / 100;
                long expirationTicks = Math.Min(bantimeTicks, TimeSpan.FromSeconds(max_ignore).Ticks);
                TimeSpan expirationOffset = TimeSpan.FromTicks(expirationTicks);
                DateTimeOffset absoluteExpiration = DateTimeOffset.Now + expirationOffset;
                recent.Add(recentKey, new Tuple<long, int>(now, btime), absoluteExpiration);
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config path: " + path);
            output.WriteLine("config args: " + args);
            output.WriteLine("config max_ignore: " + max_ignore);
            output.WriteLine("config bantime: " + bantime);
            output.WriteLine("status cache size: " + recent.GetCount());
        }
#endif
        #endregion
    }
}
