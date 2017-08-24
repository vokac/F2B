#region Imports
using System;
using System.IO;
using System.Net;
using System.Runtime.Caching;
#endregion

namespace F2B.processors
{
    public class Fail2banActionProcessor : BaseProcessor
    {
        #region Fields
        protected int max_ignore;
        protected int bantime;
        private MemoryCache recent;
        #endregion

        #region Constructors
        public Fail2banActionProcessor(ProcessorElement config, Service service)
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

            //recent = new MemoryCache("F2B." + Name + ".recent");
            recent = new MemoryCache(GetType() + ".recent");
        }
        #endregion

        #region Override
        protected virtual void ExecuteFail2banAction(EventEntry evtlog, IPAddress addr, int prefix, long expiration)
        {
            throw new NotImplementedException();
        }

        public override string Execute(EventEntry evtlog)
        {
            if (!evtlog.HasProcData("Fail2ban.Last"))
            {
                throw new ArgumentException("Missing Fail2ban.Last, no Fail2ban processor reached fail treshold");
            }
            string fail2banName = evtlog.GetProcData<string>("Fail2ban.Last");

            if (!evtlog.HasProcData(fail2banName + ".Address"))
            {
                throw new ArgumentException("Missing " + fail2banName + ".Address!?");
            }
            if (!evtlog.HasProcData(fail2banName + ".Prefix"))
            {
                throw new ArgumentException("Missing " + fail2banName + ".Prefix!?");
            }

            IPAddress addr = evtlog.GetProcData<IPAddress>(fail2banName + ".Address");
            int prefix = evtlog.GetProcData<int>(fail2banName + ".Prefix");
            int btime = evtlog.GetProcData(fail2banName + ".Bantime", bantime);

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
            Log.Info("Ban IP address " + addr + "/" + prefix + " with expiration time " + expiration);
            ExecuteFail2banAction(evtlog, addr, prefix, expiration);

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
            output.WriteLine("status cache size: " + recent.GetCount());
        }
#endif
        #endregion
    }
}
