﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using LetsEncrypt.ACME.Simple.Configuration;
using LetsEncrypt.ACME.Simple.Extensions;
using Serilog;

namespace LetsEncrypt.ACME.Simple
{
    public class IISSiteServerPlugin : Plugin
    {
        public override string Name => "IISSiteServer";
        //This plugin is designed to allow a user to select multiple sites for a single San certificate or to generate a single San certificate for the entire server.
        //This has seperate code from the main main Program.cs

        public override List<Target> GetTargets()
        {
            var result = new List<Target>();

            return result;
        }

        public override List<Target> GetSites()
        {
            var result = new List<Target>();

            return result;
        }

        public override void Install(Target target, string pfxFilename, X509Store store, X509Certificate2 certificate)
        {
            // TODO: make a system where they can execute a program/batch file to update whatever they need after install.
            Console.WriteLine(" WARNING: Unable to configure server software.");
        }

        public override void Install(Target target)
        {
            // TODO: make a system where they can execute a program/batch file to update whatever they need after install.
            // This method with just the Target paramater is currently only used by Centralized SSL
            Console.WriteLine(" WARNING: Unable to configure server software.");
        }

        public override void PrintMenu()
        {
            if (App.Options.San)
            {
                Console.WriteLine(" S: Generate a single San certificate for multiple sites.");
            }
        }

        public override void HandleMenuResponse(string response, List<Target> targets)
        {
            if (response == "s")
            {
                Log.Information("Running IISSiteServer Plugin");
                if (App.Options.San)
                {
                    List<Target> siteList = new List<Target>();

                    Console.WriteLine("Enter all Site IDs seperated by a comma");
                    Console.Write(" S: for all sites on the server ");
                    var sanInput = Console.ReadLine();
                    if (sanInput == "s")
                    {
                        siteList.AddRange(targets);
                    }
                    else
                    {
                        string[] siteIDs = sanInput.Split(',');
                        foreach (var id in siteIDs)
                        {
                            siteList.AddRange(targets.Where(t => t.SiteId.ToString() == id));
                        }
                    }
                    int hostCount = 0;
                    foreach (var site in siteList)
                    {
                        hostCount = hostCount + site.AlternativeNames.Count();
                    }

                    if (hostCount > 100)
                    {
                        Log.Error(
                            "You have too many hosts for a San certificate. Let's Encrypt currently has a maximum of 100 alternative names per certificate.");
                        Environment.Exit(1);
                    }
                    Target totalTarget = CreateTarget(siteList);
                    ProcessTotaltarget(totalTarget, siteList);
                }
                else
                {
                    Log.Error("Please run the application with --san to generate a San certificate");
                }
            }
        }

        public override void Auto(Target target)
        {
            Console.WriteLine("Auto isn't supported for IISSiteServer Plugin");
        }

        public override void Renew(Target target)
        {
            List<Target> runSites = new List<Target>();
            List<Target> targets = new List<Target>();

            foreach (var plugin in Target.Plugins.Values)
            {
                if (plugin.Name == "IIS")
                {
                    targets.AddRange(plugin.GetSites());
                }
            }

            string[] siteIDs = target.Host.Split(',');
            foreach (var id in siteIDs)
            {
                runSites.AddRange(targets.Where(t => t.SiteId.ToString() == id));
            }

            Target totalTarget = CreateTarget(runSites);
            ProcessTotaltarget(totalTarget, runSites);
        }

        private Target CreateTarget(List<Target> sites)
        {
            Target totalTarget = new Target();
            totalTarget.PluginName = Name;
            totalTarget.SiteId = 0;
            totalTarget.WebRootPath = "";

            foreach (var site in sites)
            {
                var auth = App.LetsEncryptService.Authorize(site);
                if (auth.Status != "valid")
                {
                    Log.Error("All hosts under all sites need to pass authorization before you can continue.");
                    Environment.Exit(1);
                }
                else
                {
                    if (totalTarget.Host == null)
                    {
                        totalTarget.Host = site.SiteId.ToString();
                    }
                    else
                    {
                        totalTarget.Host = String.Format("{0},{1}", totalTarget.Host, site.SiteId);
                    }
                    if (totalTarget.AlternativeNames == null)
                    {
                        Target altNames = site.Copy();
                        //Had to copy the object otherwise the alternative names for the site were being updated from Totaltarget.
                        totalTarget.AlternativeNames = altNames.AlternativeNames;
                    }
                    else
                    {
                        Target altNames = site.Copy();
                        //Had to copy the object otherwise the alternative names for the site were being updated from Totaltarget.
                        totalTarget.AlternativeNames.AddRange(altNames.AlternativeNames);
                    }
                }
            }
            return totalTarget;
        }

        private static void ProcessTotaltarget(Target totalTarget, List<Target> runSites)
        {
            if (!App.Options.CentralSsl)
            {
                var pfxFilename = App.LetsEncryptService.GetCertificate(totalTarget);
                X509Store store;
                X509Certificate2 certificate;
                Log.Information("Installing Non-Central SSL Certificate in the certificate store");
                App.CertificateService.InstallCertificate(totalTarget, pfxFilename, out store, out certificate);
                if (App.Options.Test && !App.Options.Renew)
                {
                    if (!$"\nDo you want to add/update the certificate to your server software?".PromptYesNo())
                        return;
                }
                Log.Information("Installing Non-Central SSL Certificate in server software");
                foreach (var site in runSites)
                {
                    site.Plugin.Install(site, pfxFilename, store, certificate);
                    if (!App.Options.KeepExisting)
                    {
                        App.CertificateService.UninstallCertificate(site.Host, out store, certificate);
                    }
                }
            }
            else if (!App.Options.Renew || !App.Options.KeepExisting)
            {
                var pfxFilename = App.LetsEncryptService.GetCertificate(totalTarget);
                //If it is using centralized SSL, renewing, and replacing existing it needs to replace the existing binding.
                Log.Information("Updating new Central SSL Certificate");
                foreach (var site in runSites)
                {
                    site.Plugin.Install(site);
                }
            }

            if (App.Options.Test && !App.Options.Renew)
            {
                if (!$"\nDo you want to automatically renew this certificate in {App.Options.RenewalPeriodDays} days? This will add a task scheduler task.".PromptYesNo())
                    return;
            }

            if (!App.Options.Renew)
            {
                Log.Information("Adding renewal for {binding}", totalTarget);
                Scheduler.ScheduleRenewal(totalTarget);
            }
        }
    }
}