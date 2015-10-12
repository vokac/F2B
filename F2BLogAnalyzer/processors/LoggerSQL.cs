#region Imports
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Odbc;
using System.IO;
using System.Linq;
using System.Text;

#endregion

namespace F2B.processors
{
    public class LoggerSQLProcessor : BaseProcessor
    {
        #region Fields
        private string odbc;
        private string table;
        private IList<Tuple<string, string>> columns;
        private string insert;
        OdbcConnection conn;
        #endregion

        #region Constructors
        public LoggerSQLProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["odbc"] != null && !string.IsNullOrWhiteSpace(config.Options["odbc"].Value))
            {
                odbc = config.Options["odbc"].Value;
            }
            else
            {
                throw new InvalidDataException("required configuration option odbc missing or empty");
            }

            if (config.Options["table"] != null && !string.IsNullOrWhiteSpace(config.Options["table"].Value))
            {
                table = config.Options["table"].Value;
            }
            else
            {
                throw new InvalidDataException("required configuration option table missing or empty");
            }

            columns = new List<Tuple<string, string>>();
            if (config.Options["columns"] != null && !string.IsNullOrWhiteSpace(config.Options["columns"].Value))
            {
                foreach (string column in config.Options["columns"].Value.Split(','))
                {
                    string template = "";

                    if (config.Options["column." + column] != null)
                    {
                        template = config.Options["column." + column].Value;
                    }
                    else
                    {
                        Log.Warn("missing required column template for column." + column);
                    }

                    columns.Add(new Tuple<string, string>(column, template));
                }

                char[] vars = Enumerable.Repeat('?', columns.Count).ToArray();
                insert = "INSERT INTO " + table + " (" + config.Options["columns"].Value
                    + ") VALUES (" + string.Join(",", vars) + ")";
            }
            else
            {
                throw new InvalidDataException("required configuration option columns missing or empty");
            }

            conn = null;
        }
        #endregion

        #region Override
        public override void Start()
        {
            conn = new OdbcConnection(odbc);

            try
            {
                conn.Open();
            }
            catch (OdbcException ex)
            {
                Log.Error("unable to connect to database: " + ex.Message);
            }
        }

        public override void Stop()
        {
            if (conn == null)
            {
                conn.Close();
            }
        }


        public override string Execute(EventEntry evtlog)
        {
            ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);
            using (OdbcCommand cmd = new OdbcCommand(insert, conn))
            {
                foreach (var item in columns)
                {
                    cmd.Parameters.Add(new OdbcParameter(item.Item1, tpl.ExpandTemplateVariables(item.Item2)));
                }

                cmd.ExecuteNonQuery();
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config connection: " + odbc);
            output.WriteLine("config table: " + table);
            foreach (var item in columns)
            {
                output.WriteLine("config column " + item.Item1 + ": " + item.Item2);
            }
        }
#endif
        #endregion
    }
}
