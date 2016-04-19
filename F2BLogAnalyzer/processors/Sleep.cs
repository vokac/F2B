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
        private string pattern;
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
                    if (item.ToString().ToLower().Equals(config.Options["mode"]))
                        mode = item;
                }
            }

            pattern = null;
            if (config.Options["pattern"] != null && !string.IsNullOrEmpty(config.Options["pattern"].Value))
            {
                pattern = config.Options["pattern"].Value;
            }
            else
            {
                Log.Warn("sleep pattern not defined");
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
            if (string.IsNullOrEmpty(pattern))
                return goto_next;

            ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);
            string value = tpl.Apply(pattern);

            int interval;
            if (!int.TryParse(value, out interval))
            {
                Log.Info("unable to parse \"" + value + "\" as integer");
                return goto_next;
            }

            switch (mode)
            {
                case SleepMode.Normal:
                    Thread.Sleep(1000 * interval);
                    break;
                case SleepMode.Random:
                    Thread.Sleep(rnd.Next(1000 * interval));
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
            output.WriteLine("config pattern: {0}", pattern);
        }
#endif
        #endregion
    }
}
