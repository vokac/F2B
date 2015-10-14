#region Imports
using System;
using System.Collections.Generic;
using System.IO;
using System.Messaging;
using System.Net;
using System.Runtime.Caching;
using System.Timers;
#endregion

namespace F2B.processors
{
    public class Fail2banWFPProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private int max_ignore;
        private int bantime;
        private int cleanup;
        private int max_filter_rules;

        //private System.Timers.Timer tCleanupExpired;
        private MemoryCache recent;
        #endregion

        #region Constructors
        public Fail2banWFPProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            max_ignore = 60;
            if (config.Options["max_ignore"] != null)
            {
                max_ignore = int.Parse(config.Options["max_ignore"].Value);
            }

            bantime = 600;
            if (config.Options["bantime"] != null)
            {
                bantime = int.Parse(config.Options["bantime"].Value);
            }

            cleanup = bantime / 10;
            if (config.Options["cleanup"] != null)
            {
                int tmp = int.Parse(config.Options["cleanup"].Value);
                if (tmp > 0)
                {
                    cleanup = tmp;
                }
                else
                {
                    Log.Error("Ignoring invalid cleanup interval " + tmp);
                }
            }

            max_filter_rules = 0;
            if (config.Options["max_filter_rules"] != null)
            {
                max_filter_rules = int.Parse(config.Options["max_filter_rules"].Value);
            }

            if (FwManager.Instance.Interval > 1000 * cleanup)
            {
                FwManager.Instance.Interval = 1000 * cleanup;
            }
            FwManager.Instance.MaxSize = max_filter_rules;

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

            long expiration = DateTime.UtcNow.Ticks + btime * TimeSpan.TicksPerSecond;

            F2B.FwData fwData = new F2B.FwData(expiration, addr);
            F2B.FwManager.Instance.Add(fwData);

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

            output.WriteLine("config max_ignore: " + max_ignore);
            output.WriteLine("config bantime: " + bantime);
            output.WriteLine("config cleanup: " + cleanup);
            output.WriteLine("config max_filter_rules: " + max_filter_rules);
            output.WriteLine("status cache size: " + recent.GetCount());
            output.WriteLine("FwManager:");
            F2B.FwManager.Instance.Debug(output);
        }
#endif
        #endregion
    }
}
