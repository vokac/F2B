#region Imports
using System;
#endregion

namespace F2B.processors
{
    public class LabelProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Constructors
        public LabelProcessor(ProcessorElement config, Service service)
            : base(config, service)
        { }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            return goto_next;
        }
        #endregion
    }
}
