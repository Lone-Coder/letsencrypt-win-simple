﻿using System.Collections.Generic;
using Microsoft.Azure.Management.Dns;
using Microsoft.Azure.Management.Dns.Models;
using Microsoft.Rest.Azure.Authentication;
using Nager.PublicSuffix;
using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Services;
using PKISharp.WACS.Services.Interfaces;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    internal class Azure : DnsValidation<AzureOptions, Azure>
    {
	    private readonly DomainParser _domainParser;
	    private readonly DnsManagementClient _dnsClient;

        public Azure(
	        Target target, 
	        AzureOptions options, 
	        DomainParser domainParser,
	        IDnsService dnsService,
	        ILookupClientProvider lookupClientProvider,
	        AcmeDnsValidationClient acmeDnsValidationClient,
	        ILogService log, 
	        string identifier) : base(dnsService, lookupClientProvider, acmeDnsValidationClient, log, options, identifier)
        {
	        _domainParser = domainParser;
	        // Build the service credentials and DNS management client
            var serviceCreds = ApplicationTokenProvider.LoginSilentAsync(
                _options.TenantId,
                _options.ClientId,
                _options.Secret).Result;
            _dnsClient = new DnsManagementClient(serviceCreds) { SubscriptionId = _options.SubscriptionId };
        }

        public override void CreateRecord(string recordName, string token)
        {
            var url = _domainParser.Get(recordName);

            // Create record set parameters
            var recordSetParams = new RecordSet
            {
                TTL = 3600,
                TxtRecords = new List<TxtRecord>
                {
                    new TxtRecord(new[] { token })
                }
            };

            _dnsClient.RecordSets.CreateOrUpdate(_options.ResourceGroupName, 
                url.RegistrableDomain,
                url.SubDomain,
                RecordType.TXT, 
                recordSetParams);
        }

        public override void DeleteRecord(string recordName, string token)
        {
            var url = _domainParser.Get(recordName);
            _dnsClient.RecordSets.Delete(_options.ResourceGroupName, url.RegistrableDomain, url.SubDomain, RecordType.TXT);
        }
    }
}
