using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace F2B
{
    public class Utils
    {
        public static Tuple<IPAddress, int> ParseNetwork(string network)
        {
            IPAddress addr;
            int prefix;

            int pos = network.LastIndexOf('/');
            if (pos == -1)
            {
                addr = IPAddress.Parse(network).MapToIPv6();
                prefix = 128;
            }
            else
            {
                addr = IPAddress.Parse(network.Substring(0, pos));
                prefix = int.Parse(network.Substring(pos + 1));
                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    prefix += 96;
                }
                addr = addr.MapToIPv6();
            }

            return new Tuple<IPAddress, int>(addr, prefix);
        }

        public static IPAddress GetNetwork(IPAddress addr, int prefix)
        {
            byte[] addrBytes = addr.GetAddressBytes();

            if (addrBytes.Length != 16)
                throw new ArgumentException("Only IPv6 (or IPv6 mapped IPv4 addresses) supported.");

            for (int i = (prefix + 7) / 8; i < 16; i++)
            {
                addrBytes[i] = 0;
            }

            if (prefix % 8 != 0)
            {
                addrBytes[prefix / 8] &= (byte)(0xff << (8 - (prefix % 8)));
            }

            return new IPAddress(addrBytes);
        }
    }


    class ProcessorEventStringTemplate
    {
        private IDictionary<string, string> repl;

        private static Dictionary<string, string> escapeMapping = new Dictionary<string, string>()
        {
            {Regex.Escape(@""""), "\""},
            {Regex.Escape(@"\\"), "\\\\"},
            {Regex.Escape(@"\a"), "\a"},
            {Regex.Escape(@"\b"), "\b"},
            {Regex.Escape(@"\f"), "\f"},
            {Regex.Escape(@"\n"), "\n"},
            {Regex.Escape(@"\r"), "\r"},
            {Regex.Escape(@"\t"), "\t"},
            {Regex.Escape(@"\v"), "\v"},
            {Regex.Escape(@"\0"), "\0"},
            {Regex.Escape(@"\${"), "${"},
        };
        private static Regex escapeRegex = new Regex(string.Join("|", escapeMapping.Keys));

        public ProcessorEventStringTemplate(EventEntry evtlog)
        {
            repl = new Dictionary<string, string>(20 + evtlog.ProcData.Count);

            // Environment
            repl["Environment.Now"] = DateTime.Now.Ticks.ToString();
            repl["Environment.DateTime"] = DateTime.Now.ToString();
            repl["Environment.MachineName"] = System.Environment.MachineName;

            // F2B Event
            repl["Event.Id"] = evtlog.Id.ToString();
            repl["Event.Timestamp"] = evtlog.Created.Ticks.ToString();
            repl["Event.Hostname"] = (evtlog.Hostname != null ? evtlog.Hostname : "");
            repl["Event.Type"] = evtlog.Input.InputType;
            repl["Event.Input"] = evtlog.Input.InputName;
            repl["Event.Selector"] = evtlog.Input.SelectorName;
            repl["Event.Address"] = evtlog.Address.ToString();
            repl["Event.Port"] = evtlog.Port.ToString();
            repl["Event.Username"] = (evtlog.Username != null ? evtlog.Username : "");
            repl["Event.Domain"] = (evtlog.Domain != null ? evtlog.Domain : "");
            repl["Event.Status"] = evtlog.Status.ToString();
            // Event
            if (evtlog.LogData.GetType() == typeof(EventRecordWrittenEventArgs)
                || evtlog.LogData.GetType().IsSubclassOf(typeof(EventRecordWrittenEventArgs)))
            {
                EventRecordWrittenEventArgs evtarg = evtlog.LogData as EventRecordWrittenEventArgs;
                EventRecord evtrec = evtarg.EventRecord;
                repl["Event.EventId"] = evtrec.Id.ToString();
                repl["Event.RecordId"] = evtrec.RecordId.ToString();
                repl["Event.MachineName"] = evtrec.MachineName;
                repl["Event.TimeCreated"] = evtrec.TimeCreated.Value.ToString();
                repl["Event.ProviderName"] = evtrec.ProviderName;
                repl["Event.ProcessId"] = evtrec.ProcessId.ToString();
            }
            else
            {
                repl["Event.EventId"] = "0";
                repl["Event.RecordId"] = "0";
                repl["Event.MachineName"] = "";
                repl["Event.TimeCreated"] = "0";
                repl["Event.ProviderName"] = "";
                repl["Event.ProcessId"] = "";
            }

            // Processor
            foreach (var item in evtlog.ProcData)
            {
                if (item.Value == null) repl[item.Key] = "";
                else repl[item.Key] = item.Value.ToString();
            }
        }

        public string ExpandTemplateVariables(string str, string empty = null)
        {
            StringBuilder output = new StringBuilder();

            // parse template line by line (report syntax error
            // in case of unmatched variable parenthesis)
            int pos;
            int start, end, par;
            bool subvar;
            string key;
            foreach (string line in str.Replace(Environment.NewLine, "\n").Split('\n'))
            {
                pos = 0;
                while (true)
                {
                    // try to find beginning of variable definition "${"
                    start = pos;
                    while (start < line.Length - 1 && (!(line[start] == '$' && line[start + 1] == '{') || (start > 0 && line[start - 1] == '\\'))) start++;
                    if (!(start < line.Length - 1))
                    {
                        output.Append(line.Substring(pos));
                        break;
                    }
                    output.Append(line.Substring(pos, start - pos));
                    pos = start;
                    start += 2;

                    // try to find end of variable definiton "}"
                    par = 0;
                    subvar = false;
                    end = start;
                    while (end < line.Length && (par > 0 || line[end] != '}'))
                    {
                        if (end < line.Length - 1 && line[end - 1] != '\\' && line[end] == '$' && line[end + 1] == '{')
                        {
                            par++;
                            subvar = true;
                        }
                        if (line[end] == '}')
                        {
                            par--;
                        }
                        end++;
                    }
                    if (!(end < line.Length))
                    {
                        Log.Warn("Unable to parse all variables in template line: " + line);
                        output.Append(line.Substring(pos));
                        break;
                    }
                    pos = end + 1;

                    // expand variable
                    if (subvar)
                    {
                        key = ExpandTemplateVariables(line.Substring(start, end - start), empty);
                    }
                    else
                    {
                        key = line.Substring(start, end - start);
                    }

                    // parse default value from key
                    string defval = null;
                    if (key.Contains(":="))
                    {
                        int seppos = key.IndexOf(":=");
                        defval = key.Substring(seppos + 2);
                        key = key.Substring(0, seppos);
                    }

                    // replace variable
                    if (repl.ContainsKey(key))
                    {
                        output.Append(repl[key]);
                    }
                    else if (defval != null)
                    {
                        output.Append(defval);
                    }
                    else if (empty != null)
                    {
                        output.Append(empty);
                    }
                    else
                    {
                        output.Append("${");
                        output.Append(key);
                        output.Append("}");
                    }
                }

                output.Append(Environment.NewLine);
            }

            return Escape(output.ToString(0, output.Length - Environment.NewLine.Length));
        }

        public static string Escape(string s)
        {
            return escapeRegex.Replace(s, EscapeMatchEval);
        }

        private static string EscapeMatchEval(Match m)
        {
            if (escapeMapping.ContainsKey(m.Value))
            {
                return escapeMapping[m.Value];
            }
            return escapeMapping[Regex.Escape(m.Value)];
        }
    }
}
