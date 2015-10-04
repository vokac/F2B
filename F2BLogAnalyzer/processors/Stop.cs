#region Imports
using System;
#endregion

namespace F2B.processors
{
    public class StopProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Constructors
        public StopProcessor(ProcessorElement config, Service service)
            : base(config, service)
        { }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            return null;
        }
        #endregion
    }
}
