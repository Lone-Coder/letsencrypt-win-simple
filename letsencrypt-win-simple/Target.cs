﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;

namespace LetsEncrypt.ACME.Simple
{
    public class Target
    {
        public string Host { get; set; }
        public bool? HostIsDns { get; set; }
        public string WebRootPath { get; set; }
        public long SiteId { get; set; }
        public string ExcludeBindings { get; set; }
        public List<string> AlternativeNames { get; set; } = new List<string>();
        public string PluginName { get; set; } = IISPlugin.PluginName;
        public Plugin Plugin => Program.Plugins.GetByName(Program.Plugins.Legacy, PluginName);

        public override string ToString() {
            var x = new StringBuilder();
            x.Append($"[{PluginName}] ");
            if (!AlternativeNames.Contains(Host))
            {
                x.Append($"{Host} ");
            }
            if (SiteId > 0)
            {
                x.Append($"(SiteId {SiteId}) ");
            }
            x.Append("[");
            var num = AlternativeNames.Count();
            if (num > 0)
            {
                x.Append($"{num} binding");
                if (num > 1)
                {
                    x.Append($"s");
                }
                x.Append($" - {AlternativeNames.First()}");
                if (num > 1)
                {
                    x.Append($", ...");
                }
                x.Append($" ");
            }
            if (!string.IsNullOrWhiteSpace(WebRootPath))
            {
                x.Append($"@ {WebRootPath}");
            }
            x.Append("]");
            return x.ToString();
        }

        public List<string> GetHosts(bool asUnicode)
        {
            var hosts = new List<string>();
            if (HostIsDns == true)
            {
                hosts.Add(Host);
            }
            if (AlternativeNames != null && AlternativeNames.Any())
            {
                hosts.AddRange(AlternativeNames);
            }
            var exclude = new List<string>();
            if (!string.IsNullOrEmpty(ExcludeBindings))
            {
                exclude = ExcludeBindings.Split(',').Select(x => x.ToLower().Trim()).ToList();
            }

            var filtered = hosts.
                Where(x => !string.IsNullOrWhiteSpace(x)).
                Distinct().
                Except(exclude);

            if (asUnicode)
            {
                var idn = new IdnMapping();
                filtered = filtered.Select(x => new IdnMapping().GetUnicode(x));
            } 

            if (filtered.Count() == 0)
            {
                Program.Log.Error("No DNS identifiers found.");
                throw new Exception("No DNS identifiers found.");
            }
            else if (filtered.Count() > Settings.maxNames)
            {
                Program.Log.Error("Too many hosts for a single certificate. Let's Encrypt has a maximum of {maxNames}.", Settings.maxNames);
                throw new Exception($"Too many hosts for a single certificate. Let's Encrypt has a maximum of {Settings.maxNames}.");
            }

            return filtered.ToList();
        }
    }
}