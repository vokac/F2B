#region Imports
#endregion

namespace F2B.processors
{
    public abstract class BoolProcessor : BaseProcessor
    {
        #region Fields
        protected string goto_success = null;
        protected string goto_failure = null;
        #endregion

        #region Constructors
        public BoolProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            goto_success = config.Goto.Success;
            goto_failure = config.Goto.Failure;
        }
        #endregion
    }
}
