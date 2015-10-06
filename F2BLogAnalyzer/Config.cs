#region Imports
using System;
using System.ComponentModel;
using System.Configuration;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Xml;
#endregion

namespace F2B
{
    public class Config
    {
        private static volatile F2BSection instance;
        private static object syncRoot = new Object();

        private Config() { }

        public static F2BSection Instance
        {
            get
            {
                if (instance == null)
                {
                    lock (syncRoot)
                    {
                        if (instance == null)
                        {
                            //ConfigurationManager.RefreshSection("f2bSection");
                            //ExeConfigurationFileMap configMap = new ExeConfigurationFileMap();
                            //configMap.ExeConfigFilename = @"d:\test\justAConfigFile.config.whateverYouLikeExtension";
                            ExeConfigurationFileMap map = new ExeConfigurationFileMap { ExeConfigFilename = Program.ConfigFile };
                            Configuration cfg = ConfigurationManager.OpenMappedExeConfiguration(map, ConfigurationUserLevel.None);

                            F2BSection config;
                            try
                            {
                                config = cfg.GetSection("f2bSection") as F2BSection;
                            }
                            catch (ConfigurationErrorsException ex)
                            {
                                Log.Error("Unable to process config file \""
                                    + cfg.FilePath + "\": " + ex.Message);
                                throw;
                            }

                            if (config == null)
                            {
                                // TODO: add more details in case we include additional config files
                                throw new Exception("Invalid/missing configuration file \""
                                    + cfg.FilePath + "\": no f2bSection");
                            }

                            // save configuration (just a test)
                            //cfg.SaveAs(@"C:\test.xml", ConfigurationSaveMode.Full, true);

                            instance = config;
                        }
                    }
                }

                return instance;
            }
        }
    }

    //
    // Classes that supports F2B configuration
    //
    public class F2BSection : ConfigurationSection
    {
        #region Constructors
        // Create a configuration section.
        public F2BSection()
        { }
        #endregion

        #region Properties
        // Get or set the queue options.
        [ConfigurationProperty("queue")]
        public QueueElement Queue
        {
            get
            {
                return (QueueElement)this["queue"];
            }
        }

        // Get or set the smtp options.
        [ConfigurationProperty("smtp")]
        public SmtpElement Smtp
        {
            get
            {
                return (SmtpElement)this["smtp"];
            }
        }

        [ConfigurationProperty("inputs", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(InputCollection),
            AddItemName = "input",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public InputCollection Inputs
        {
            get
            {
                return (InputCollection)base["inputs"];
            }
        }

        [ConfigurationProperty("selectors", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(SelectorCollection),
            AddItemName = "selector",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public SelectorCollection Selectors
        {
            get
            {
                return (SelectorCollection)base["selectors"];
            }
        }

        [ConfigurationProperty("processors", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(ProcessorCollection),
            AddItemName = "processor",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public ProcessorCollection Processors
        {
            get
            {
                return (ProcessorCollection)base["processors"];
            }
        }

        //[ConfigurationProperty("actions", IsDefaultCollection = false)]
        //[ConfigurationCollection(typeof(ActionCollection),
        //    AddItemName = "action",
        //    ClearItemsName = "clear",
        //    RemoveItemName = "remove")]
        //public ActionCollection Actions
        //{
        //    get
        //    {
        //        return (ActionCollection)base["action"];
        //    }
        //}

        [ConfigurationProperty("accounts", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(AccountCollection),
            AddItemName = "account",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public AccountCollection Accounts
        {
            get
            {
                return (AccountCollection)base["accounts"];
            }
        }
        #endregion
    }


    // helper class to access XML elements data
    public class ConfigurationTextElement<T> : ConfigurationElement
    {
        private T _value;
        protected override void DeserializeElement(XmlReader reader,
                                bool serializeCollectionKey)
        {
            // First get the attributes
            for (int i = 0; i < reader.AttributeCount; i++)
            {
                reader.MoveToAttribute(i);
                this[reader.Name] = reader.Value;
            }
            // then get the text content
            reader.MoveToElement();
            _value = (T)reader.ReadElementContentAs(typeof(T), null);
        }
        public T Value
        {
            get { return _value; }
            // ??? set { _value = (string)value; }
        }
    }
    
    
    //
    // Classes that supports INPUT section
    //

    // collection of log event producers that we want to subscribe
    //
    public class InputCollection : ConfigurationElementCollection
    {
        #region Overrides
        protected override ConfigurationElement CreateNewElement()
        {
            return new InputElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            InputElement ie = element as InputElement;
            return ie.Server + ie.Domain;
        }

        public InputElement this[int index]
        {
            get { return base.BaseGet(index) as InputElement; }
        }

        public new InputElement this[string key]
        {
            get { return base.BaseGet(key) as InputElement; }
        }
        #endregion
    }


    // configuration of log event producers that we want to subscribe
    //
    public class InputElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public InputElement()
        { }

        // Create the element.
        public InputElement(string name, string type, string server, string domain, string username, string password)
        {
            Name = name;
            Type = type;
            Server = server;
            Domain = domain;
            Username = username;
            Password = password;
        }

        // Create the element.
        public InputElement(string name, string type, string logpath, int interval)
        {
            Name = name;
            Type = type;
            LogPath = logpath;
            Interval = interval;
        }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the log name.
        [ConfigurationProperty("name",
          DefaultValue = null,
          IsRequired = true)]
        public string Name
        {
            get
            {
                return (string)this["name"];
            }
            set
            {
                this["name"] = value;
            }
        }

        // Get or set the log type.
        [ConfigurationProperty("type",
          DefaultValue = null,
          IsRequired = true)]
        public string Type
        {
            get
            {
                return (string)this["type"];
            }
            set
            {
                this["type"] = value;
            }
        }

        // Get or set the log server name.
        [ConfigurationProperty("server",
          DefaultValue = null,
          IsRequired = false)]
        public string Server
        {
            get
            {
                return (string)this["server"];
            }
            set
            {
                this["server"] = value;
            }
        }

        // Get or set the log server domain.
        [ConfigurationProperty("domain",
          DefaultValue = null,
          IsRequired = false)]
        public string Domain
        {
            get
            {
                return (string)this["domain"];
            }
            set
            {
                this["domain"] = value;
            }
        }

        // Get or set the log server username.
        [ConfigurationProperty("username",
          DefaultValue = null,
          IsRequired = false)]
        public string Username
        {
            get
            {
                return (string)this["username"];
            }
            set
            {
                this["username"] = value;
            }
        }

        // Get or set the log server password.
        [ConfigurationProperty("password",
          DefaultValue = null,
          IsRequired = false)]
        public string Password
        {
            get
            {
                return (string)this["password"];
            }
            set
            {
                this["password"] = value;
            }
        }

        // Get or set the log file path.
        [ConfigurationProperty("logpath",
          DefaultValue = null,
          IsRequired = false)]
        public string LogPath
        {
            get
            {
                return (string)this["logpath"];
            }
            set
            {
                this["logpath"] = value;
            }
        }

        // Get or set the log file read interval.
        [ConfigurationProperty("interval",
          DefaultValue = 1000,
          IsRequired = false)]
        public int Interval
        {
            get
            {
                return int.Parse((string)this["interval"]);
            }
            set
            {
                this["interval"] = value;
            }
        }
        #endregion
    }



    //
    // Classes that supports SELECTOR section
    //

    // collection of log event selectors
    //
    public class SelectorCollection : ConfigurationElementCollection
    {
        #region Overrides
        protected override ConfigurationElement CreateNewElement()
        {
            return new SelectorElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            SelectorElement fe = element as SelectorElement;
            return fe.Name;
        }

        public ConfigurationElement this[int index]
        {
            get { return base.BaseGet(index) as ConfigurationElement; }
        }

        public new ConfigurationElement this[string key]
        {
            get { return base.BaseGet(key) as ConfigurationElement; }
        }
        #endregion
    }


    // configuration of log event producers that we want to subscribe
    //
    public class SelectorElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public SelectorElement()
        { }

        // Create the element.
        public SelectorElement(string name, string inputName, string inputType, string query, string address, string port, string username, string domain)
        {
            Name = name;
            InputName = inputName;
            InputType = inputType;
            //Query = ??? query ???
            // regexp to extract required log event data
            //Address = address;
            //Port = port;
            //Username = username;
            //Domain = domain;
        }

        // Create the element.
        public SelectorElement(string name, string inputName, string inputType, string[] match, string[] ignore)
        {
            Name = name;
            InputName = inputName;
            InputType = inputType;
            // regexp to extract required log event data
            //LineRegexp = "match + ignore"
        }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the selector name.
        [ConfigurationProperty("name",
          DefaultValue = null,
          IsRequired = true)]
        public string Name
        {
            get
            {
                return (string)this["name"];
            }
            set
            {
                this["name"] = value;
            }
        }

        // Get or set the log input name.
        [ConfigurationProperty("input_name",
          DefaultValue = null,
          IsRequired = false)]
        public string InputName
        {
            get
            {
                return (string)this["input_name"];
            }
            set
            {
                this["input_name"] = value;
            }
        }

        // Get or set the log input type.
        [ConfigurationProperty("input_type",
          DefaultValue = null,
          IsRequired = false)]
        public string InputType
        {
            get
            {
                return (string)this["input_type"];
            }
            set
            {
                this["input_type"] = value;
            }
        }

        // Get or set the login status.
        [ConfigurationProperty("login",
          DefaultValue = "failure",
          IsRequired = false)]
        public string Login
        {
            get
            {
                return (string)this["login"];
            }
            set
            {
                this["login"] = value;
            }
        }

        // Get or set the first processor name.
        [ConfigurationProperty("processor",
          DefaultValue = "",
          IsRequired = false)]
        public string Processor
        {
            get
            {
                return (string)this["processor"];
            }
            set
            {
                this["processor"] = value;
            }
        }

        // Get or set the selector query.
        [ConfigurationProperty("query")]
        public QueryElement Query
        {
            get
            {
                return (QueryElement)this["query"];
            }
        }

        // Get or set the selector regex to extract client IP address.
        [ConfigurationProperty("address")]
        public EventDataElement Address
        {
            get
            {
                return (EventDataElement)this["address"];
            }
        }

        // Get or set the selector regex to extract client port.
        [ConfigurationProperty("port")]
        public EventDataElement Port
        {
            get
            {
                return (EventDataElement)this["port"];
            }
        }

        // Get or set the selector regex to extract required username.
        [ConfigurationProperty("username")]
        public EventDataElement Username
        {
            get
            {
                return (EventDataElement)this["username"];
            }
        }

        // Get or set the selector regex to extract required domain.
        [ConfigurationProperty("domain")]
        public EventDataElement Domain
        {
            get
            {
                return (EventDataElement)this["domain"];
            }
        }


        // collection of regexps
        //
        public class RegexpCollection : ConfigurationElementCollection
        {
            #region Overrides
            protected override ConfigurationElement CreateNewElement()
            {
                return new RegexpElement();
            }

            protected override object GetElementKey(ConfigurationElement element)
            {
                RegexpElement re = element as RegexpElement;
                return re.Value;
            }

            public RegexpElement this[int index]
            {
                get { return base.BaseGet(index) as RegexpElement; }
            }

            //public new RegexpElement this[string key]
            //{
            //    get { return base.BaseGet(key) as RegexpElement; }
            //}
            #endregion
        }

        [ConfigurationProperty("regexps", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(RegexpCollection),
            AddItemName = "regexp",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public RegexpCollection Regexps
        {
            get
            {
                return (RegexpCollection)base["regexps"];
            }
        }
        #endregion
    }


    // configuration of log event producers that we want to subscribe
    //
    public class QueryElement : ConfigurationTextElement<string>
    {
        #region Constructors
        // Create the element.
        public QueryElement()
        { }
        #endregion
    }


    // configuration to extract IP address from event log message
    //
    public class EventDataElement : ConfigurationTextElement<string>
    {
        #region Constructors
        // Create the element.
        public EventDataElement()
        { }
        #endregion

        #region Properties
        // Get or set the selector regex to extract client IP address.
        [ConfigurationProperty("xpath",
          DefaultValue = null,
          IsRequired = true)]
        public string XPath
        {
            get
            {
                return (string)this["xpath"];
            }
            set
            {
                this["xpath"] = value;
            }
        }
        #endregion
    }


    // configuration filter reference
    //
    public class RegexpElement : ConfigurationTextElement<string>
    {
        #region Constructors
        // Create the element.
        public RegexpElement()
        { }

        // Create the element.
        public RegexpElement(string rtype, string regexp)
        {
            Type = rtype;
            // Value = regexp
        }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the regex type.
        [ConfigurationProperty("type",
          DefaultValue = "default",
          IsRequired = true)]
        public string Type
        {
            get
            {
                return (string)this["type"];
            }
            set
            {
                this["type"] = value;
            }
        }
        #endregion
    }




    //
    // Classes that supports QUEUE parameters
    //
    public class QueueElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public QueueElement()
        { }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the selector query.
        [ConfigurationProperty("maxsize")]
        public ConfigurationTextElement<int> MaxSize
        {
            get
            {
                return (ConfigurationTextElement<int>)this["maxsize"];
            }
        }

        // Get or set the selector query.
        [ConfigurationProperty("consumers")]
        public ConfigurationTextElement<int> Consumers
        {
            get
            {
                return (ConfigurationTextElement<int>)this["consumers"];
            }
        }
        #endregion
    }




    //
    // Classes that supports SMTP parameters
    //
    public class SmtpElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public SmtpElement()
        { }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get SMTP host.
        [ConfigurationProperty("host")]
        public ConfigurationTextElement<string> Host
        {
            get
            {
                return (ConfigurationTextElement<string>)this["host"];
            }
        }

        // Get SMTP port.
        [ConfigurationProperty("port")]
        public ConfigurationTextElement<int> Port
        {
            get
            {
                return (ConfigurationTextElement<int>)this["port"];
            }
        }

        // Get SMTP ssl.
        [ConfigurationProperty("ssl")]
        public ConfigurationTextElement<bool> Ssl
        {
            get
            {
                return (ConfigurationTextElement<bool>)this["ssl"];
            }
        }

        // Get SMTP AUTH username.
        [ConfigurationProperty("username")]
        public ConfigurationTextElement<string> Username
        {
            get
            {
                return (ConfigurationTextElement<string>)this["username"];
            }
        }

        // Get SMTP AUTH password.
        [ConfigurationProperty("password")]
        public ConfigurationTextElement<string> Password
        {
            get
            {
                return (ConfigurationTextElement<string>)this["password"];
            }
        }
        #endregion
    }



    //
    // Classes that supports PROCESSOR section
    //

    // collection of processors
    //
    public class ProcessorCollection : ConfigurationElementCollection
    {
        #region Overrides
        protected override ConfigurationElement CreateNewElement()
        {
            return new ProcessorElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            ProcessorElement pe = element as ProcessorElement;
            return pe.Name;
        }

        public ProcessorElement this[int index]
        {
            get { return base.BaseGet(index) as ProcessorElement; }
        }

        public new ProcessorElement this[string key]
        {
            get { return base.BaseGet(key) as ProcessorElement; }
        }
        #endregion
    }


    // configuration of log event producers that we want to subscribe
    //
    public class ProcessorElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public ProcessorElement()
        { }

        // Create the element.
        public ProcessorElement(string name, string type, string description)
        {
            Name = name;
            Type = type;
            //Description = description;
        }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the processor name.
        [ConfigurationProperty("name",
          DefaultValue = null,
          IsRequired = true)]
        public string Name
        {
            get
            {
                return (string)this["name"];
            }
            set
            {
                this["name"] = value;
            }
        }

        // Get or set the processor type.
        [ConfigurationProperty("type",
          DefaultValue = null,
          IsRequired = true)]
        public string Type
        {
            get
            {
                return (string)this["type"];
            }
            set
            {
                this["type"] = value;
            }
        }

        // Get or set the selector query.
        [ConfigurationProperty("description")]
        public DescriptionElement Description
        {
            get
            {
                return (DescriptionElement)this["description"];
            }
        }

        [ConfigurationProperty("filters", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(FilterRefCollection),
            AddItemName = "filter",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public FilterRefCollection Filters
        {
            get
            {
                return (FilterRefCollection)base["filters"];
            }
        }

        [ConfigurationProperty("ranges", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(RangeCollection),
            AddItemName = "range",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public RangeCollection Ranges
        {
            get
            {
                return (RangeCollection)base["ranges"];
            }
        }

        // Get or set the return value for success/failure.
        [ConfigurationProperty("goto")]
        public GotoElement Goto
        {
            get
            {
                return (GotoElement)this["goto"];
            }
        }

        [ConfigurationProperty("options", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(KeyValueConfigurationCollection),
            AddItemName = "option",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public KeyValueConfigurationCollection Options
        {
            get
            {
                return (KeyValueConfigurationCollection)base["options"];
            }
        }
        #endregion
    }



    //
    // Classes that supports ACTION section
    //

    // collection of actions
    //
    public class ActionCollection : ConfigurationElementCollection
    {
        #region Overrides
        protected override ConfigurationElement CreateNewElement()
        {
            return new ActionElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            ActionElement pe = element as ActionElement;
            return pe.Name;
        }

        public ActionElement this[int index]
        {
            get { return base.BaseGet(index) as ActionElement; }
        }

        public new ActionElement this[string key]
        {
            get { return base.BaseGet(key) as ActionElement; }
        }
        #endregion
    }


    // configuration of log event producers that we want to subscribe
    //
    public class ActionElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public ActionElement()
        { }

        // Create the element.
        public ActionElement(string name, string type, string description)
        {
            Name = name;
            Type = type;
            //Description = description;
        }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the action name.
        [ConfigurationProperty("name",
          DefaultValue = null,
          IsRequired = true)]
        public string Name
        {
            get
            {
                return (string)this["name"];
            }
            set
            {
                this["name"] = value;
            }
        }

        // Get or set the action type.
        [ConfigurationProperty("type",
          DefaultValue = null,
          IsRequired = true)]
        public string Type
        {
            get
            {
                return (string)this["type"];
            }
            set
            {
                this["type"] = value;
            }
        }

        // Get or set the selector query.
        [ConfigurationProperty("description")]
        public DescriptionElement Description
        {
            get
            {
                return (DescriptionElement)this["description"];
            }
        }

        [ConfigurationProperty("options", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(KeyValueConfigurationCollection),
            AddItemName = "option",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public KeyValueConfigurationCollection Options
        {
            get
            {
                return (KeyValueConfigurationCollection)base["options"];
            }
        }
        #endregion
    }




    // configuration of log event producers that we want to subscribe
    //
    public class DescriptionElement : ConfigurationTextElement<string>
    {
        #region Constructors
        // Create the element.
        public DescriptionElement()
        { }
        #endregion
    }

    
    // collection of filter reference names
    //
    public class FilterRefCollection : ConfigurationElementCollection
    {
        #region Overrides
        protected override ConfigurationElement CreateNewElement()
        {
            return new FilterRefElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            FilterRefElement fe = element as FilterRefElement;
            return fe.Name;
        }

        public FilterRefElement this[int index]
        {
            get { return base.BaseGet(index) as FilterRefElement; }
        }

        public new FilterRefElement this[string key]
        {
            get { return base.BaseGet(key) as FilterRefElement; }
        }
        #endregion
    }

    
    // configuration filter reference
    //
    public class FilterRefElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public FilterRefElement()
        { }

        // Create the element.
        public FilterRefElement(string name)
        {
            Name = name;
        }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the processor name.
        [ConfigurationProperty("name",
          DefaultValue = null,
          IsRequired = true)]
        public string Name
        {
            get
            {
                return (string)this["name"];
            }
            set
            {
                this["name"] = value;
            }
        }
        #endregion
    }

    
    // collection of IP addres ranges
    //
    public class RangeCollection : ConfigurationElementCollection
    {
        #region Overrides
        protected override ConfigurationElement CreateNewElement()
        {
            return new RangeElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            RangeElement re = element as RangeElement;
            return re.Network;
        }

        public RangeElement this[int index]
        {
            get { return base.BaseGet(index) as RangeElement; }
        }

        public new RangeElement this[string key]
        {
            get { return base.BaseGet(key) as RangeElement; }
        }
        #endregion
    }


    // converter for IP/prefix type
    //
    public class NetworkConverter : ExpandableObjectConverter
    {
        #region Fields
        private static IPAddress allip = IPAddress.Parse("::0");
        #endregion

        #region Overrides
        public override bool CanConvertFrom(
            ITypeDescriptorContext context, Type sourceType)
        {
            if (sourceType == typeof(string))
            {
                return true;
            }
            return base.CanConvertFrom(context, sourceType);
        }

        public override bool CanConvertTo(
            ITypeDescriptorContext context, Type destinationType)
        {
            if (destinationType == typeof(string))
            {
                return true;
            }
            return base.CanConvertTo(context, destinationType);
        }

        public override object ConvertFrom(ITypeDescriptorContext
            context, CultureInfo culture, object value)
        {
            if (value == null)
            {
                return new Tuple<IPAddress, int>(allip, 0);
            }

            if (value is string)
            {
                string network = ((string)value).Trim();
                if (network.Length == 0)
                {
                    return new Tuple<IPAddress, int>(allip, 0);
                }

                return Utils.ParseNetwork(network);
            }

            return base.ConvertFrom(context, culture, value);
        }

        public override object ConvertTo(
            ITypeDescriptorContext context,
            CultureInfo culture, object value, Type destinationType)
        {
            if (value != null)
            {
                if (!(value is Tuple<IPAddress, int>))
                {
                    throw new ArgumentException(
                        "Invalid Network", "value");
                }
            }

            if (destinationType == typeof(string))
            {
                if (value == null)
                {
                    return String.Empty;
                }

                Tuple<IPAddress, int> network = (Tuple<IPAddress, int>)value;

                return network.Item1 + "/" + network.Item2;
            }

            return base.ConvertTo(context, culture, value,
                destinationType);
        }
        #endregion
    }


    // configuration filter reference
    //
    public class RangeElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public RangeElement()
        { }

        // Create the element.
        public RangeElement(IPAddress network, int prefix)
        {
            Network = new Tuple<IPAddress, int>(network, prefix);
        }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the network IP range.
        [TypeConverter(typeof(NetworkConverter))]
        [ConfigurationProperty("network",
          IsRequired = true)]
          // DefaultValue = new Tuple<IPAddress, int>(IPAddress.Parse("::"), 0),
        public Tuple<IPAddress, int> Network
        {
            get
            {
                return (Tuple<IPAddress, int>)this["network"];
            }
            set
            {
                this["network"] = value;
            }
        }
        #endregion
    }


    // configuration of log event producers that we want to subscribe
    //
    public class GotoElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public GotoElement()
        { }

        // Create the element.
        public GotoElement(string next, string error)
        {
            Next = next;
            Error = error;
            OnErrorNext = false;
        }

        // Create the element.
        public GotoElement(string next, string error, string success = null, string failure = null)
        {
            Next = next;
            Error = error;
            Success = success;
            Failure = failure;
            OnErrorNext = false;
        }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the next label.
        [ConfigurationProperty("next",
          DefaultValue = null,
          IsRequired = false)]
        public string Next
        {
            get
            {
                return (string)this["next"];
            }
            set
            {
                this["next"] = value;
            }
        }

        // Get or set the error label.
        [ConfigurationProperty("error",
          DefaultValue = null,
          IsRequired = false)]
        public string Error
        {
            get
            {
                return (string)this["error"];
            }
            set
            {
                this["error"] = value;
            }
        }

        // Get or set the success label.
        [ConfigurationProperty("success",
          DefaultValue = null,
          IsRequired = false)]
        public string Success
        {
            get
            {
                string value = (string)this["success"];
                if (value != string.Empty)
                {
                    return (string)this["success"];
                }
                else
                {
                    return (string)this["next"];
                }
            }
            set
            {
                this["success"] = value;
            }
        }

        // Get or set the failure label.
        [ConfigurationProperty("failure",
          DefaultValue = null,
          IsRequired = false)]
        public string Failure
        {
            get
            {
                string value = (string)this["failure"];
                if (value != string.Empty)
                {
                    return (string)this["failure"];
                }
                else
                {
                    return (string)this["next"];
                }
            }
            set
            {
                this["failure"] = value;
            }
        }

        // Get or set the failure label.
        [ConfigurationProperty("on_error_next",
          DefaultValue = false,
          IsRequired = false)]
        public bool OnErrorNext
        {
            //get
            //{
            //    string value = (string)this["on_error_next"];
            //    if (value != string.Empty)
            //    {
            //        return value.ToLower() == "true" || value.ToLower() == "t" || value.ToLower() == "yes" || value.ToLower() == "y";
            //    }
            //    else
            //    {
            //        return false;
            //    }
            //}
            //set
            //{
            //    if (value)
            //        this["on_error_next"] = "true";
            //    else
            //        this["on_error_next"] = "false";
            //}
            get
            {
                return (bool)this["on_error_next"];
            }
            set
            {
                this["on_error_next"] = value;
            }
        }
        #endregion
    }



    //
    // Classes that supports ACCOUNT section
    //

    // collection of account sources
    //
    public class AccountCollection : ConfigurationElementCollection
    {
        #region Overrides
        protected override ConfigurationElement CreateNewElement()
        {
            return new AccountElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            AccountElement ae = element as AccountElement;
            return ae.Name;
        }

        public AccountElement this[int index]
        {
            get { return base.BaseGet(index) as AccountElement; }
        }

        public new AccountElement this[string key]
        {
            get { return base.BaseGet(key) as AccountElement; }
        }
        #endregion
    }


    // configuration of account sources
    //
    public class AccountElement : ConfigurationElement
    {
        #region Constructors
        // Create the element.
        public AccountElement()
        { }

        // Create the element.
        public AccountElement(string name, string type, string description)
        {
            Name = name;
            Type = type;
            //Description = description;
        }
        #endregion

        #region Overrides
        public override bool IsReadOnly()
        {
            return false;
        }
        #endregion

        #region Properties
        // Get or set the processor name.
        [ConfigurationProperty("name",
          DefaultValue = null,
          IsRequired = true)]
        public string Name
        {
            get
            {
                return (string)this["name"];
            }
            set
            {
                this["name"] = value;
            }
        }

        // Get or set the processor type.
        [ConfigurationProperty("type",
          DefaultValue = null,
          IsRequired = true)]
        public string Type
        {
            get
            {
                return (string)this["type"];
            }
            set
            {
                this["type"] = value;
            }
        }

        // Get or set the selector query.
        [ConfigurationProperty("description")]
        public DescriptionElement Description
        {
            get
            {
                return (DescriptionElement)this["description"];
            }
        }

        [ConfigurationProperty("options", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(KeyValueConfigurationCollection),
            AddItemName = "option",
            ClearItemsName = "clear",
            RemoveItemName = "remove")]
        public KeyValueConfigurationCollection Options
        {
            get
            {
                return (KeyValueConfigurationCollection)base["options"];
            }
        }
        #endregion
    }
}
