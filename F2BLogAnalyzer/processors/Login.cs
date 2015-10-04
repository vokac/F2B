#region Imports
using System;
#endregion

namespace F2B.processors
{
    public class LoginProcessor : BoolProcessor, IThreadSafeProcessor
    {
        #region Fields
        #endregion

        #region Constructors
        public LoginProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (evtlog.Status == LoginStatus.SUCCESS)
            {
                return goto_success;
            }
            else if (evtlog.Status == LoginStatus.FAILURE)
            {
                return goto_failure;
            }
            else
            {
                return goto_next;
            }
        }
        #endregion
    }
}
