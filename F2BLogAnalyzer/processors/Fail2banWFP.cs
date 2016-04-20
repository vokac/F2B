#region Imports
using System;
using System.IO;
using System.Net;
#endregion

namespace F2B.processors
{
    public class Fail2banWFPProcessor : Fail2banActionProcessor, IThreadSafeProcessor
    {
        #region Fields
        private int cleanup;
        private int max_filter_rules;
        private ulong weight;
        private bool permit;
        private bool persistent;
        #endregion

        #region Constructors
        public Fail2banWFPProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
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

            weight = 0;
            if (config.Options["weight"] != null)
            {
                weight = ulong.Parse(config.Options["weight"].Value);
            }

            permit = false;
            if (config.Options["permit"] != null)
            {
                permit = bool.Parse(config.Options["permit"].Value);
            }

            persistent = false;
            if (config.Options["persistent"] != null)
            {
                persistent = bool.Parse(config.Options["persistent"].Value);
            }
        }
        #endregion

        #region Override
        protected override void ExecuteFail2banAction(EventEntry evtlog, IPAddress addr, int prefix, long expiration)
        {
            F2B.FwData fwData = new F2B.FwData(expiration, addr, prefix);
            F2B.FwManager.Instance.Add(fwData, weight, permit, persistent);
        }


#if DEBUG
        public override void Debug(StreamWriter output)
        {
            output.WriteLine("config cleanup: " + cleanup);
            output.WriteLine("config max_filter_rules: " + max_filter_rules);
            output.WriteLine("config weight: " + weight);
            output.WriteLine("config permit: " + permit);
            output.WriteLine("config persistent: " + persistent);
            base.Debug(output);
            output.WriteLine("FwManager:");
            F2B.FwManager.Instance.Debug(output);
            output.WriteLine("  WFP Rules:");
            try
            {
                var details = F2B.Firewall.Instance.List(true);
                foreach (var item in F2B.Firewall.Instance.List())
                {
                    try
                    {
                        Tuple<long, byte[]> fwname = FwData.DecodeName(item.Value);
                        string tmp = Convert.ToString(fwname.Item1);
                        try
                        {
                            DateTime tmpExp = new DateTime(fwname.Item1, DateTimeKind.Utc);
                            tmp = tmpExp.ToLocalTime().ToString();
                        }
                        catch (Exception)
                        {
                        }
                        output.WriteLine("    filterId[{0}]/{4}/expiration[{2}]/md5[{3}]",
                            item.Key, item.Value, tmp,
                            BitConverter.ToString(fwname.Item2).Replace("-", ":"),
                            details.ContainsKey(item.Key) ? details[item.Key] : "");
                    }
                    catch (ArgumentException)
                    {
                        // can't parse filter rule name to F2B structured data
                        output.WriteLine("    filterId[{0}]/name=[{1}]", item.Key, item.Value);
                    }
                }
            }
            catch (FirewallException ex)
            {
                Log.Error("Unable to list firewall filters: " + ex.Message);
            }
        }
#endif
        #endregion
    }
}
