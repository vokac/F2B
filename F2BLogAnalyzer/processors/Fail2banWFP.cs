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
    public class Fail2banWFPProcessor : Fail2banActionProcessor, IThreadSafeProcessor
    {
        #region Fields
        private int cleanup;
        private int max_filter_rules;
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
        }
        #endregion

        #region Override
        protected override void ExecuteFail2banAction(EventEntry evtlog, IPAddress addr, int prefix, long expiration)
        {
            F2B.FwData fwData = new F2B.FwData(expiration, addr, prefix);
            F2B.FwManager.Instance.Add(fwData);
        }


#if DEBUG
        public override void Debug(StreamWriter output)
        {
            output.WriteLine("config cleanup: " + cleanup);
            output.WriteLine("config max_filter_rules: " + max_filter_rules);
            base.Debug(output);
            output.WriteLine("FwManager:");
            F2B.FwManager.Instance.Debug(output);
        }
#endif
        #endregion
    }
}
