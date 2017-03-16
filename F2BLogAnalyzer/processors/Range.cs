#region Imports
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

#endregion

namespace F2B.processors
{
    public class RangeProcessor : BoolProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string address;
        private Dictionary<IPAddress, int> ranges;
        private string mail;
        #endregion

        #region Constructors
        public RangeProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            address = "Event.Address";
            if (config.Options["address"] != null)
            {
                address = config.Options["address"].Value;
            }

            ranges = new Dictionary<IPAddress, int>();

            foreach (RangeElement range in config.Ranges)
            {
                IPAddress network = Utils.GetNetwork(range.Network.Item1, range.Network.Item2);
                if (ranges.ContainsKey(network) && ranges[network] >= range.Network.Item2)
                    continue;
                ranges[network] = range.Network.Item2;
            }
            // Optimization: remove overlapping IP subranges

            mail = null;
            if (config.Options["mail"] != null)
            {
                mail = config.Options["mail"].Value;
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (ranges.Count == 0)
            {
                return goto_failure;
            }

            string strAddress = evtlog.GetProcData<string>(address);
            if (string.IsNullOrEmpty(strAddress))
            {
                Log.Info(GetType() + "[" + Name
                    + "]: empty address attribute: " + address);

                return goto_error;
            }

            IPAddress addr = null;
            try
            {
                addr = IPAddress.Parse(strAddress.Trim()).MapToIPv6();
            }
            catch (FormatException ex)
            {
                Log.Info(GetType() + "[" + Name
                    + "]: invalid address " + address
                    + "[" + strAddress + "]: " + ex.Message);

                return goto_error;
            }

            string firstRange = null;

            foreach (KeyValuePair<IPAddress, int> range in ranges)
            {
                IPAddress network = Utils.GetNetwork(addr, range.Value);

                Log.Info(GetType() + "[" + Name
                    + "]: " + addr + "/" + range.Value + " -> " + network
                    + (range.Key.Equals(network) ? "" : " not")
                    + " in " + range.Key + "/" + range.Value);

                if (range.Key.Equals(network))
                {
                    firstRange = range.Key + "/" + range.Value;
                    break;
                }
            }

            if (firstRange == null)
            {
                return goto_failure;
            }

            if (evtlog.HasProcData("Range.All"))
            {
                string all = evtlog.GetProcData<string>("Range.All");
                evtlog.SetProcData("Range.All", all + "," + Name);
            }
            else
            {
                evtlog.SetProcData("Range.All", Name);
            }
            evtlog.SetProcData("Range.Last", Name);

            evtlog.SetProcData(Name + ".Range", firstRange);
            evtlog.SetProcData(Name + ".Mail", mail);

            return goto_success;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config address: {0}", address);
            foreach (KeyValuePair<IPAddress, int> range in ranges)
            {
                output.WriteLine("config range: {0}/{1}", range.Key, range.Value);
            }

            output.WriteLine("config email: {0}", mail);
        }
#endif
        #endregion
    }
}
