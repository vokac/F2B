#region Imports
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
#endregion

namespace F2B.processors
{
    public class MailProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string sender;
        private string recipient;
        private string subject;
        private string body;
        private NetworkCredential smtpAuth = null;
#if DEBUG
        private int nmsgs;
#endif
        #endregion

        #region Constructors
        public MailProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            foreach (string item in new string[] { "sender", "recipient", "subject", "body" })
            {
                string value = null;

                if (config.Options[item] != null)
                {
                    value = config.Options[item].Value;
                }

                if (string.IsNullOrEmpty(value))
                {
                    throw new Exception(GetType() + "[" + Name + "]: Undefined or empty " + item);
                }
            }

            if (config.Options["sender"] != null)
            {
                sender = config.Options["sender"].Value;
            }

            if (config.Options["recipient"] != null)
            {
                recipient = config.Options["recipient"].Value;
            }

            if (config.Options["subject"] != null)
            {
                subject = config.Options["subject"].Value;
            }

            if (config.Options["body"] != null)
            {
                body = config.Options["body"].Value;
            }

            SmtpElement smtpConfig = F2B.Config.Instance.Smtp;
            if (!string.IsNullOrEmpty(smtpConfig.Username.Value) && !string.IsNullOrEmpty(smtpConfig.Password.Value))
            {
                if (!smtpConfig.Ssl.Value)
                {
                    throw new InvalidDataException("Can't send SMTP AUTH email without SSL encryption");
                }
                smtpAuth = new System.Net.NetworkCredential(smtpConfig.Username.Value, smtpConfig.Password.Value);
            }

#if DEBUG
            nmsgs = 0;
#endif
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            F2BSection config = F2B.Config.Instance;

            Dictionary<string, string> repl = new Dictionary<string, string>(10 + evtlog.ProcData.Count);
            repl["$Event.Id$"] = evtlog.Id.ToString();
            if (evtlog.LogData.GetType().IsSubclassOf(typeof(EventRecordWrittenEventArgs)))
            {
                EventRecordWrittenEventArgs evtarg = evtlog.LogData as EventRecordWrittenEventArgs;
                repl["$Event.RecordId$"] = evtarg.EventRecord.Id.ToString();
            }
            else
            {
                repl["$Event.RecordId$"] = "0";
            }
            repl["$Event.Timestamp$"] = evtlog.Timestamp.ToString();
            repl["$Event.Hostname$"] = (evtlog.Hostname != null ? evtlog.Hostname : "''");
            repl["$Event.InputName$"] = evtlog.Input.InputName;
            repl["$Event.SelectorName$"] = evtlog.Input.SelectorName;
            repl["$Event.Address$"] = evtlog.Address.ToString();
            repl["$Event.Port$"] = evtlog.Port.ToString();
            repl["$Event.Username$"] = (evtlog.Username != null ? evtlog.Username : "''");
            repl["$Event.Domain$"] = (evtlog.Domain != null ? evtlog.Domain : "''");
            repl["$Event.Status$"] = evtlog.Status.ToString();
            foreach (var item in evtlog.ProcData)
            {
                if (item.Value == null) repl["$" + item.Key + "$"] = "";
                else repl["$" + item.Key + "$"] = item.Value.ToString();
            }

            string senderEx = ExpandTemplateVariables(sender, repl, "");
            string recipientEx = Regex.Replace(ExpandTemplateVariables(recipient, repl, ""), @"^,*(.*?),*$", "$1");
            string subjectEx = ExpandTemplateVariables(subject, repl);
            Log.Info("Sending mail notification (from=" + senderEx + ",to=" + recipientEx + ",subject=" + subjectEx + ")");

            MailMessage mail = new MailMessage(senderEx, recipientEx);
            mail.Subject = subjectEx;
            mail.Body = ExpandTemplateVariables(body, repl);

            SmtpClient client = new SmtpClient();
            client.Port = config.Smtp.Port.Value;
            client.DeliveryMethod = SmtpDeliveryMethod.Network;
            client.UseDefaultCredentials = false;
            client.Host = config.Smtp.Host.Value;
            client.EnableSsl = config.Smtp.Ssl.Value;
            client.Credentials = smtpAuth;
            client.Send(mail);

#if DEBUG
            Interlocked.Increment(ref nmsgs);
#endif

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config sender: " + sender);
            output.WriteLine("config recipient: " + recipient);
            output.WriteLine("status sent messages: " + nmsgs);
        }
#endif
        #endregion

        #region Methods
        private string ExpandTemplateVariables(string str, IReadOnlyDictionary<string, string> repl, string empty = null)
        {
            //Regex re = new Regex(@"\$(\w+)\$", RegexOptions.Compiled);
            //return re.Replace(str, match => repl[match.Groups[1].Value].ToString());
            StringBuilder output = new StringBuilder(str);

            foreach (var kvp in repl)
            {
                output.Replace(kvp.Key, kvp.Value);
            }

            if (empty != null)
            {
                return Regex.Replace(output.ToString(), @"\$.*?\$", "");
            }

            return output.ToString();
        }
        #endregion
    }
}
