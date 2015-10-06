using System.ComponentModel;
using System.ServiceProcess;
using System.Configuration.Install;

namespace F2B
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : Installer
    {
        private ServiceProcessInstaller serviceProcessInstaller;
        private ServiceInstaller serviceInstaller;

        public ProjectInstaller()
        {
            // serviceProcessInstaller
            // 
            serviceProcessInstaller = new ServiceProcessInstaller();
            serviceProcessInstaller.Account = ServiceAccount.NetworkService;
            serviceProcessInstaller.Password = null;
            serviceProcessInstaller.Username = null;

            // serviceInstaller
            // 
            serviceInstaller = new ServiceInstaller();
            serviceInstaller.ServiceName = Service.NAME;
            serviceInstaller.DisplayName = Service.DISPLAY;
            serviceInstaller.Description = Service.DESCR;
            serviceInstaller.StartType = ServiceStartMode.Automatic;
            serviceInstaller.ServicesDependedOn = new string[] { "eventlog", "MSMQ" };

            // ProjectInstaller
            // 
            Installers.AddRange(new Installer[] {
                serviceProcessInstaller,
                serviceInstaller});
        }

        private string AppendPathParameter(string path, string parameter)
        {
            if (path.Length > 0 && path[0] != '"')
            {
                path = "\"" + path + "\"";
            }
            path += " " + parameter;
            return path;
        }

        protected override void OnBeforeInstall(System.Collections.IDictionary savedState)
        {
            if (Context.Parameters.ContainsKey("f2bLogLevel"))
            {
                Context.Parameters["assemblypath"] = AppendPathParameter(Context.Parameters["assemblypath"], "/log-level " + Context.Parameters["f2bLogLevel"]);
            }
            if (Context.Parameters.ContainsKey("f2bLogFile"))
            {
                Context.Parameters["assemblypath"] = AppendPathParameter(Context.Parameters["assemblypath"], "/log-file " + Context.Parameters["f2bLogFile"]);
            }

            if (Context.Parameters.ContainsKey("f2bUser") && Context.Parameters["f2bUser"] != "")
            {
                string user = Context.Parameters["f2bUser"];
                Log.Info("Configuring account " + user + " to run this service");

                switch (user)
                {
                    case "LocalService":
                        serviceProcessInstaller.Account = ServiceAccount.LocalService;
                        break;
                    case "LocalSystem":
                        serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
                        break;
                    case "NetworkService":
                        serviceProcessInstaller.Account = ServiceAccount.NetworkService;
                        break;
                    default:
                        serviceProcessInstaller.Account = ServiceAccount.User;
                        serviceProcessInstaller.Username = user;
                        //serviceProcessInstaller.Password = secret;
                        break;
                }
            }

            if (Context.Parameters.ContainsKey("f2bState"))
            {
                Context.Parameters["assemblypath"] = AppendPathParameter(Context.Parameters["assemblypath"], "/state " + Context.Parameters["f2bState"]);
            }
            if (Context.Parameters.ContainsKey("f2bHost"))
            {
                Context.Parameters["assemblypath"] = AppendPathParameter(Context.Parameters["assemblypath"], "/host " + Context.Parameters["f2bHost"]);
            }
            if (Context.Parameters.ContainsKey("f2bProducerQueue"))
            {
                Context.Parameters["assemblypath"] = AppendPathParameter(Context.Parameters["assemblypath"], "/producer-queue " + Context.Parameters["f2bProducerQueue"]);
            }
            if (Context.Parameters.ContainsKey("f2bRegistrationQueue"))
            {
                Context.Parameters["assemblypath"] = AppendPathParameter(Context.Parameters["assemblypath"], "/registration-queue " + Context.Parameters["f2bRegistrationQueue"]);
            }
            if (Context.Parameters.ContainsKey("f2bRegistrationInterval"))
            {
                Context.Parameters["assemblypath"] = AppendPathParameter(Context.Parameters["assemblypath"], "/registration-interval " + Context.Parameters["f2bRegistrationInterval"]);
            }
            if (Context.Parameters.ContainsKey("f2bCleanupExpiredInterval"))
            {
                Context.Parameters["assemblypath"] = AppendPathParameter(Context.Parameters["assemblypath"], "/cleanup-interval " + Context.Parameters["f2bCleanupExpiredInterval"]);
            }

            base.OnBeforeInstall(savedState);
        }
    }
}
