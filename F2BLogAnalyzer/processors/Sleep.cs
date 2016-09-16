using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace F2B.processors
{
    public class SleepProcessor : BaseProcessor, IThreadSafeProcessor
    {
        public enum SleepMode { Normal, Random }

        private SleepMode mode;
        private string interval;
        private Random rnd;

        #region Constructors
        public SleepProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            mode = SleepMode.Normal;
            if (config.Options["mode"] != null && !string.IsNullOrEmpty(config.Options["mode"].Value))
            {
                foreach (SleepMode item in Enum.GetValues(typeof(SleepMode)))
                {
                    if (item.ToString().ToLower().Equals(config.Options["mode"].Value.ToLower()))
                        mode = item;
                }
            }

            interval = null;
            if (config.Options["interval"] != null && !string.IsNullOrEmpty(config.Options["interval"].Value))
            {
                interval = config.Options["interval"].Value;
            }
            else
            {
                Log.Warn("sleep interval not defined");
            }

            if (mode == SleepMode.Random)
            {
                rnd = new Random();
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (string.IsNullOrEmpty(this.interval))
                return goto_next;

            ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);
            string value = tpl.Apply(this.interval);

            int intvl;
            if (!int.TryParse(value, out intvl))
            {
                Log.Info("unable to parse \"" + value + "\" as integer");
                return goto_next;
            }

            switch (mode)
            {
                case SleepMode.Normal:
                    Thread.Sleep(1000 * intvl);
                    break;
                case SleepMode.Random:
                    Thread.Sleep(rnd.Next(1000 * intvl));
                    break;
                default:
                    Log.Warn("unsupported sleep mode " + mode);
                    break;
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config mode: {0}", mode);
            output.WriteLine("config interval: {0}", interval);
        }
#endif
        #endregion
    }
}
