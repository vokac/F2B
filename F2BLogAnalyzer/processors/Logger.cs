#region Imports
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;

#endregion

namespace F2B.processors
{
    public class LoggerProcessor : BaseProcessor
    {
        #region Fields
        private long nexceptions;
        private long size_curr;
        private StreamWriter sw;

        private string filename;
        private long size;
        private int rotate;
        private string template;
        private bool synchronized;
        #endregion

        #region Constructors
        public LoggerProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            // set default values
            nexceptions = 0;
            size_curr = -1;
            sw = null;

            filename = null;
            size = -1;
            rotate = -1;
            template = @"${Event.Timestamp}	${Event.TimeCreated}	${Event.Hostname}	${Event.Id}	${Event.Input}	${Event.Selector}	${Event.Status}	${Event.MachineName}	${Event.EventId}	${Event.RecordId}	${Event.Address}	${Event.Port}	${Event.Username}	${Event.Domain}
";
            synchronized = true;

            if (config.Options["file"] != null && !string.IsNullOrWhiteSpace(config.Options["file"].Value))
            {
                filename = config.Options["file"].Value;
            }
            else
            {
                throw new InvalidDataException("required configuration option file missing or empty");
            }

            if (config.Options["size"] != null)
            {
                size = long.Parse(config.Options["size"].Value);
            }
            if (config.Options["rotate"] != null)
            {
                rotate = int.Parse(config.Options["rotate"].Value);
            }
            if (config.Options["template"] != null)
            {
                template = config.Options["template"].Value;
            }
            if (config.Options["synchronized"] != null)
            {
                synchronized = bool.Parse(config.Options["synchronized"].Value);
            }
        }
        #endregion

        #region Override
        public override void Stop()
        {
             //base.Stop();
            if (sw != null)
            {
                sw.Close();
                sw = null;
            }
        }


        public override string Execute(EventEntry evtlog)
        {
            try
            {
                if (size > 0)
                {
                    // get current log file size
                    if (size_curr < 0)
                    {
                        if (File.Exists(filename))
                        {
                            FileInfo f = new FileInfo(filename);
                            size_curr = f.Length;
                        }
                        else
                        {
                            size_curr = 0;
                        }
                    }

                    if (size_curr > size)
                    {
                        if (sw != null)
                        {
                            sw.Close();
                            sw = null;
                        }

                        if (rotate > 0)
                        {
                            if (File.Exists(filename + "." + rotate))
                            {
                                File.Delete(filename + "." + rotate);
                            }
                            for (int i = rotate; i > 1; i++)
                            {
                                if (File.Exists(filename + "." + (i - 1)))
                                {
                                    File.Move(filename + "." + (i - 1), filename + "." + i);
                                }
                            }
                            if (File.Exists(filename))
                            {
                                File.Move(filename, filename + ".1");
                            }
                        }
                        else
                        {
                            if (File.Exists(filename))
                            {
                                File.Move(filename, filename + ".bak");
                            }
                        }
                    }
                }

                if (sw == null)
                {
                    sw = File.AppendText(filename);
                    nexceptions = 0;
                }

                ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);
                string data = tpl.ExpandTemplateVariables(template);
                sw.Write(data);
                
                if (synchronized)
                {
                    sw.Flush();
                }

                size_curr += data.Length;
            }
            catch (Exception ex)
            {
                if (nexceptions == 0)
                {
                    Log.Error("LoggerProcessor::Execute exception: " + ex.ToString());
                }

                nexceptions++;
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config file: " + filename);
            output.WriteLine("config size: " + size);
            output.WriteLine("config rotate: " + rotate);
            output.WriteLine("status size_curr: " + size_curr);
            output.WriteLine("status nexceptions: " + nexceptions);
            output.WriteLine("status sw: " + sw);
        }
#endif
        #endregion
    }
}
