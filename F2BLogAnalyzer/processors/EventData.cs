using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace F2B.processors
{
    public class EventDataProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Constructors
        public EventDataProcessor(ProcessorElement config, Service service)
            : base(config, service)
        { }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (!(evtlog.LogData.GetType() == typeof(EventRecordWrittenEventArgs)
                || evtlog.LogData.GetType().IsSubclassOf(typeof(EventRecordWrittenEventArgs))))
            {
                return goto_next;
            }

            EventRecordWrittenEventArgs evtarg = evtlog.LogData as EventRecordWrittenEventArgs;
            EventRecord evtrec = evtarg.EventRecord;
            string xmlString = evtrec.ToXml();

            evtlog.SetProcData("EventData.XML", xmlString);
            evtlog.SetProcData("EventData.Description", evtrec.FormatDescription());

            // process event XML data
            var doc = XDocument.Parse(xmlString);
            var namespaces = new XmlNamespaceManager(new NameTable());
            var ns = doc.Root.GetDefaultNamespace();
            namespaces.AddNamespace("ns", ns.NamespaceName);

            //foreach (var element in doc.XPathSelectElements("/ns:Event/ns:System/*", namespaces))
            //{
            //    evtlog.SetProcData("Event.System." + element.Name.LocalName, element.Value);
            //}

            int dataCnt = 0;
            foreach (var element in doc.XPathSelectElements("/ns:Event/ns:EventData/ns:Data", namespaces))
            {
                var path = element.AncestorsAndSelf().Select(e => e.Name.LocalName).Reverse();
                var xPath = string.Join("/", path);
                var name = element.Attribute("Name");
                if (name != null)
                {
                    evtlog.SetProcData("EventData." + name.Value, element.Value);
                }
                else
                {
                    evtlog.SetProcData("EventData[" + dataCnt + "]", element.Value);
                    dataCnt++;
                }
            }

            if (dataCnt > 0)
            {
                evtlog.SetProcData("EventData", dataCnt);
            }

            return goto_next;
        }
        #endregion
    }
}
