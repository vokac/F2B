using System;
using System.Collections.Generic;

namespace F2B.processors
{
    public class Inputname : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string pattern;
        #endregion

        #region Constructors
        public Inputname(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["pattern"] != null)
            {
                pattern = config.Options["pattern"].Value;
            }

            if (pattern == null || pattern == string.Empty)
            {
                pattern = "label_for_events_with_input_{INPUT_NAME}_selector_{SELECTOR}";
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            string tmp0 = pattern;
            string tmp1 = tmp0.Replace("{INPUT_NAME}", evtlog.Input.InputName);
            string tmp2 = tmp1.Replace("{INPUT_TYPE}", evtlog.Input.InputType);
            string tmp3 = tmp2.Replace("{SELECTOR}", evtlog.Input.SelectorName);

            return tmp3;
        }
        #endregion
    }
}
