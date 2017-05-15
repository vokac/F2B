using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

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

        public static void DumpProcessInfo(EventLogEntryType type = EventLogEntryType.Information)
        {
            Process currentProcess = Process.GetCurrentProcess();
            Log.Logger("Process[" + currentProcess.Id + "]: NonpagedSystemMemorySize64 = " + currentProcess.NonpagedSystemMemorySize64, type);
            Log.Logger("Process[" + currentProcess.Id + "]: PagedMemorySize64 = " + currentProcess.PagedMemorySize64, type);
            Log.Logger("Process[" + currentProcess.Id + "]: PagedSystemMemorySize64 = " + currentProcess.PagedSystemMemorySize64, type);
            Log.Logger("Process[" + currentProcess.Id + "]: PeakPagedMemorySize64 = " + currentProcess.PeakPagedMemorySize64, type);
            Log.Logger("Process[" + currentProcess.Id + "]: PeakVirtualMemorySize64 = " + currentProcess.PeakVirtualMemorySize64, type);
            Log.Logger("Process[" + currentProcess.Id + "]: PeadWorkingSet64 = " + currentProcess.PeakWorkingSet64, type);
            Log.Logger("Process[" + currentProcess.Id + "]: PrivateMemorySize64 = " + currentProcess.PrivateMemorySize64, type);
            Log.Logger("Process[" + currentProcess.Id + "]: VirtualMemorySize64 = " + currentProcess.VirtualMemorySize64, type);
            Log.Logger("Process[" + currentProcess.Id + "]: WorkingSet64 = " + currentProcess.WorkingSet64, type);
            Log.Logger("Process[" + currentProcess.Id + "]: PrivilegedProcessorTime = " + currentProcess.PrivilegedProcessorTime, type);
            Log.Logger("Process[" + currentProcess.Id + "]: StartTime = " + currentProcess.StartTime, type);
            //Log.Logger("Process[" + currentProcess.Id + "]: ExitTime = " + currentProcess.ExitTime, type);
            Log.Logger("Process[" + currentProcess.Id + "]: TotalProcessorTime = " + currentProcess.TotalProcessorTime, type);
            Log.Logger("Process[" + currentProcess.Id + "]: UserProcessorTime = " + currentProcess.UserProcessorTime, type);
        }
    }



    public class SimpleExpression
    {
        public enum EvaluateTokenType
        {
            Number = 0x01,
            Unary = 0x02,
            Binary = 0x04,
            End = 0x08,
        }

        public static double Evaluate(string expr)
        {
            List<string> ops = new List<string>();
            List<double> vals = new List<double>();
            EvaluateTokenType allowed = EvaluateTokenType.Number | EvaluateTokenType.Unary;

            // normalize input expression
            expr = expr.ToLower();
            expr = expr.Replace(" ", "");
            expr = expr.Replace("true", "1"); // NOTE: truetrue -> 11 ?!
            expr = expr.Replace("false", "0"); // NOTE: falsefalse -> 00 ?!

            for (int pos = 0; pos < expr.Length;)
            {
                string s1 = expr.Substring(pos, 1);
                string s2 = "\0\0";
                string s3 = "\0\0\0";
                string s4 = "\0\0\0\0";
                string s5 = "\0\0\0\0\0";

                if (pos < expr.Length - 1) s2 = expr.Substring(pos, 2);
                if (pos < expr.Length - 2) s3 = expr.Substring(pos, 3);
                if (pos < expr.Length - 3) s4 = expr.Substring(pos, 4);
                if (pos < expr.Length - 4) s5 = expr.Substring(pos, 5);

                if (s1.Equals("(") || s4.Equals("abs(") || s4.Equals("int(") || s5.Equals("bool("))
                {
                    if (!allowed.HasFlag(EvaluateTokenType.Number))
                    {
                        throw new ArgumentException("Invalid token type \"" + expr + "\"[" + pos + "]");
                    }

                    if (s1.Equals("(")) pos += 1;
                    else if (s4.Equals("abs(")) pos += 4;
                    else if (s4.Equals("int(")) pos += 4;
                    else if (s5.Equals("bool(")) pos += 5;

                    // recursively call Evaluate
                    int start = pos;
                    int bracketCount = 0;
                    for (; pos < expr.Length; pos++)
                    {
                        string s = expr.Substring(pos, 1);

                        if (s.Equals("("))
                        {
                            bracketCount++;
                        }
                        else if (s.Equals(")"))
                        {
                            if (bracketCount == 0)
                                break;

                            bracketCount--;
                        }
                    }

                    if (!(pos < expr.Length))
                    {
                        throw new ArgumentException("Invalid expression \"" + expr + "\"");
                    }

                    double val = Evaluate(expr.Substring(start, pos - start));

                    if (s1.Equals("(")) vals.Add(val);
                    else if (s4.Equals("abs(")) vals.Add(Math.Abs(val));
                    else if (s4.Equals("int(")) vals.Add(((long)val));
                    else if (s5.Equals("bool(")) vals.Add(val == 0 ? 0 : 1);

                    if (expr[pos] != ')')
                    {
                        throw new ArgumentException("Invalid token type \"" + expr + "\"[" + pos + "], expected ')'");
                    }

                    pos += 1; // ")"

                    allowed = EvaluateTokenType.Binary | EvaluateTokenType.End;
                }
                else if (s2.Equals("==") || s2.Equals("!=")
                    || s2.Equals("<=") || s2.Equals(">=")
                    || s2.Equals("&&") || s2.Equals("||"))
                {
                    if (!allowed.HasFlag(EvaluateTokenType.Binary))
                    {
                        throw new ArgumentException("Invalid token type \"" + expr + "\"[" + pos + "]");
                    }

                    ops.Add(s2);
                    pos += 2;

                    allowed = EvaluateTokenType.Number | EvaluateTokenType.Unary;
                }
                else if (allowed.HasFlag(EvaluateTokenType.Unary) && s1.Equals("+"))
                {
                    ops.Add("p");
                    pos += 1;

                    allowed = EvaluateTokenType.Number;
                }
                else if (allowed.HasFlag(EvaluateTokenType.Unary) && s1.Equals("-"))
                {
                    ops.Add("m");
                    pos += 1;

                    allowed = EvaluateTokenType.Number;
                }
                else if (s1.Equals("+") || s1.Equals("-") || s1.Equals("*") || s1.Equals("/")
                    || s1.Equals("%") || s1.Equals(">") || s1.Equals("<")
                    || s1.Equals("&") || s1.Equals("^") || s1.Equals("|"))
                {
                    if (!allowed.HasFlag(EvaluateTokenType.Binary))
                    {
                        throw new ArgumentException("Invalid token type \"" + expr + "\"[" + pos + "]");
                    }

                    ops.Add(s1);
                    pos += 1;

                    allowed = EvaluateTokenType.Number | EvaluateTokenType.Unary;
                }
                else if (s1.Equals("!"))
                {
                    if (!allowed.HasFlag(EvaluateTokenType.Unary))
                    {
                        throw new ArgumentException("Invalid token type \"" + expr + "\"[" + pos + "]");
                    }

                    ops.Add(s1);
                    pos += 1;

                    allowed = EvaluateTokenType.Number;
                }
                else if (char.IsDigit(expr[pos]))
                {
                    if (!allowed.HasFlag(EvaluateTokenType.Number))
                    {
                        throw new ArgumentException("Invalid token type \"" + expr + "\"[" + pos + "]");
                    }

                    // parse number from string, supported formats:
                    int start = pos;
                    // hexadecimal numbers (e.g. 0xFFFF)
                    if (expr.Length >= 3 && expr.StartsWith("0x") && "0123456789abcdefABCDEF".IndexOf(expr[pos+2]) != -1)
                    {
                        pos += 2;
                        while (pos < expr.Length && "0123456789abcdefABCDEF".IndexOf(expr[pos]) != -1) pos++;
                        vals.Add(Convert.ToInt64(expr.Substring(start+2, pos - (start+2)), 16));
                    }
                    // binary numbers (e.g. 0b1111)
                    else if (expr.Length >= 3 && expr.StartsWith("0b") && (expr[pos+2] == '0' || expr[pos+2] == '1'))
                    {
                        pos += 2;
                        while (pos < expr.Length && (expr[pos] == '0' || expr[pos] == '1')) pos++;
                        vals.Add(Convert.ToInt64(expr.Substring(start+2, pos - (start+2)), 2));
                    }
                    // decimal and floating point numbers (e.g. 123456, 1.2345)
                    else
                    {
                        while (pos < expr.Length && (char.IsDigit(expr, pos) || expr.Substring(pos, 1).Equals("."))) pos++;
                        vals.Add(double.Parse(expr.Substring(start, pos - start)));
                    }

                    allowed = EvaluateTokenType.Binary | EvaluateTokenType.End;
                }
                else
                {
                    throw new ArgumentException("Invalid character \"" + expr + "\"[" + pos + "]: s1=" + s1 + "s2=" + s2);
                }
            }

            if (!allowed.HasFlag(EvaluateTokenType.End))
            {
                throw new ArgumentException("Invalid token type \"" + expr + "\": non-terminating token at the end");
            }

            // debug
            //Log.Info("Eval[" + expr + "].ops: " + string.Join(",", ops));
            //Log.Info("Eval[" + expr + "].vals: " + string.Join(",", vals));

            string[] operation_precedence = new string[] {
                "!", "p", "m", "*", "/", "%", "+", "-",
                "<", ">", "<=", ">=", "==", "!=",
                "&", "^", "|", "&&", "||"
            };

            foreach (string cop in operation_precedence)
            {
                int vpos = 0;
                foreach (string op in ops)
                {
                    if (!cop.Equals(op))
                    {
                        vpos++;
                        continue;
                    }

                    if (op.Equals("!"))
                        vals[vpos] = vals[vpos] == 0 ? 1 : 0;
                    else if (op.Equals("p"))
                        vals[vpos] = vals[vpos];
                    else if (op.Equals("m"))
                        vals[vpos] = -vals[vpos];
                    else if (op.Equals("*"))
                        vals[vpos] *= vals[vpos + 1];
                    else if (op.Equals("/"))
                        vals[vpos] /= vals[vpos + 1];
                    else if (op.Equals("%"))
                        vals[vpos] = ((long)vals[vpos]) % ((long)vals[vpos + 1]);
                    else if (op.Equals("+"))
                        vals[vpos] += vals[vpos + 1];
                    else if (op.Equals("-"))
                        vals[vpos] -= vals[vpos + 1];
                    else if (op.Equals("<"))
                        vals[vpos] = vals[vpos] < vals[vpos + 1] ? 1 : 0;
                    else if (op.Equals(">"))
                        vals[vpos] = vals[vpos] > vals[vpos + 1] ? 1 : 0;
                    else if (op.Equals("<="))
                        vals[vpos] = vals[vpos] <= vals[vpos + 1] ? 1 : 0;
                    else if (op.Equals(">="))
                        vals[vpos] = vals[vpos] >= vals[vpos + 1] ? 1 : 0;
                    else if (op.Equals("=="))
                        vals[vpos] = vals[vpos] == vals[vpos + 1] ? 1 : 0;
                    else if (op.Equals("!="))
                        vals[vpos] = vals[vpos] != vals[vpos + 1] ? 1 : 0;
                    else if (op.Equals("&"))
                        vals[vpos] = ((long)vals[vpos]) & ((long)vals[vpos + 1]);
                    else if (op.Equals("^"))
                        vals[vpos] = ((long)vals[vpos]) ^ ((long)vals[vpos + 1]);
                    else if (op.Equals("|"))
                        vals[vpos] = ((long)vals[vpos]) | ((long)vals[vpos + 1]);
                    else if (op.Equals("&&"))
                        vals[vpos] = vals[vpos] != 0 && vals[vpos + 1] != 0 ? 1 : 0;
                    else if (op.Equals("||"))
                        vals[vpos] = vals[vpos] != 0 || vals[vpos + 1] != 0 ? 1 : 0;

                    // binary operators
                    if (!(op.Equals("!") || op.Equals("p") || op.Equals("m")))
                        vals.RemoveAt(vpos + 1);
                }
                ops.RemoveAll(op => op.Equals(cop));
            }

            if (vals.Count != 1)
            {
                throw new ArgumentException("Invalid expression \"" + expr + "\": extra arguments");
            }

            return vals[0];
        }
    }



    class ProcessorEventStringTemplate
    {
        private IReadOnlyDictionary<string, object> repl;

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
            {Regex.Escape(@"\$("), "$("},
        };
        private static Regex escapeRegex = new Regex(string.Join("|", escapeMapping.Keys));

        public ProcessorEventStringTemplate(EventEntry evtent)
        {
            repl = evtent.ProcData;
        }

        public string ExpandTemplateVariables(string str)
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
                        key = ExpandTemplateVariables(line.Substring(start, end - start));
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

                    // final string start position and length
                    int vpos = 0;
                    int vlen = -1;
                    if (key.Contains(":"))
                    {
                        int seppos = key.IndexOf(":");
                        string keysfx = key.Substring(seppos + 1);
                        key = key.Substring(0, seppos);
                        if (keysfx.Contains(":"))
                        {
                            seppos = keysfx.IndexOf(":");
                            vpos = int.Parse(keysfx.Substring(0, seppos));
                            vlen = int.Parse(keysfx.Substring(seppos + 1));
                        }
                        else
                        {
                            vpos = int.Parse(keysfx);
                        }
                    }

                    // replace variable
                    if (repl.ContainsKey(key))
                    {
                        object value = repl[key];
                        if (value != null)
                        {
                            string val = value.ToString();
                            if (vpos == 0 && vlen == -1)
                            {
                                output.Append(val);
                            }
                            else
                            {
                                if (vpos < val.Length)
                                {
                                    vlen = (vlen == -1 ? val.Length-vpos : Math.Min(val.Length-vpos, vlen));
                                    output.Append(val.Substring(vpos, vlen));
                                }
                                else
                                {
                                    output.Append("");
                                }
                            }
                        }
                        else
                        {
                            output.Append("");
                        }
                    }
                    else if (defval != null)
                    {
                        output.Append(defval);
                    }
                    else
                    {
                        // NOTE: append unexpanded variable just to make clear
                        // to the user that default value is necessary
                        output.Append("${");
                        output.Append(key);
                        output.Append("}");
                    }
                }

                output.Append(Environment.NewLine);
            }

            return output.ToString(0, output.Length - Environment.NewLine.Length);
        }

        public string EvalTemplateExpressions(string str)
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
                    // try to find beginning of variable definition "$("
                    start = pos;
                    while (start < line.Length - 1 && (!(line[start] == '$' && line[start + 1] == '(') || (start > 0 && line[start - 1] == '\\'))) start++;
                    if (!(start < line.Length - 1))
                    {
                        output.Append(line.Substring(pos));
                        break;
                    }
                    output.Append(line.Substring(pos, start - pos));
                    pos = start;
                    start += 2;

                    // try to find end of variable definiton ")"
                    par = 0;
                    subvar = false;
                    end = start;
                    while (end < line.Length && (par > 0 || line[end] != ')'))
                    {
                        if (end < line.Length - 1 && line[end - 1] != '\\' && line[end] == '$' && line[end + 1] == '(')
                        {
                            subvar = true;
                        }

                        if (line[end] == '(') par++;
                        else if (line[end] == ')') par--;

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
                        key = EvalTemplateExpressions(line.Substring(start, end - start));
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
                    try
                    {
                        output.Append(SimpleExpression.Evaluate(key));
                    }
                    catch (Exception ex)
                    {
                        Log.Warn("Unable to evaluate expression \"" + key + "\": " + ex.Message);

                        if (defval != null)
                        {
                            output.Append(defval);
                        }
                        else
                        {
                            // NOTE: append unevaluated string just to make clear
                            // to the user that thare was an error in expression
                            // and default value should be used to deal with such
                            // the expression that could lead to eval errors
                            output.Append("$(");
                            output.Append(key);
                            output.Append(")");
                        }
                    }
                }

                output.Append(Environment.NewLine);
            }

            return output.ToString(0, output.Length - Environment.NewLine.Length);
        }

        public static string UnEscape(string s)
        {
            return escapeRegex.Replace(s, UnEscapeMatchEval);
        }

        public string Apply(string str)
        {
            string tmp = ExpandTemplateVariables(str);
            tmp = EvalTemplateExpressions(tmp);
            return UnEscape(tmp);
        }

        private static string UnEscapeMatchEval(Match m)
        {
            if (escapeMapping.ContainsKey(m.Value))
            {
                return escapeMapping[m.Value];
            }
            return escapeMapping[Regex.Escape(m.Value)];
        }
    }
}
