﻿using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using DnsClient;
using PKISharp.WACS.Services.Interfaces;

namespace PKISharp.WACS.Services
{
	public class LookupClientProvider : ILookupClientProvider
	{
		private static readonly Lazy<ILookupClient> _defaultLookupClient = new Lazy<ILookupClient>(() => new LookupClient());
		private readonly ConcurrentDictionary<string, ILookupClient> _lookupClients = new ConcurrentDictionary<string, ILookupClient>();
		private readonly IDnsService _dnsService;

		public LookupClientProvider(IDnsService dnsService)
		{
			_dnsService = dnsService;
		}

		/// <summary>
		/// The default <see cref="LookupClient"/>. Internally uses your local network DNS.
		/// </summary>
		public ILookupClient Default => _defaultLookupClient.Value;

		/// <summary>
		/// Caches <see cref="LookupClient"/>s by <see cref="IPAddress"/>. Use <see cref="Default"/> instead if a specific name server is not required.
		/// </summary>
		/// <param name="ipAddress"></param>
		/// <returns>Returns an <see cref="ILookupClient"/> using the specified <see cref="IPAddress"/>.</returns>
		public ILookupClient GetOrAdd(IPAddress ipAddress)
		{
			if (ipAddress == null)
			{
				throw new ArgumentNullException(nameof(ipAddress));
			}

			return _lookupClients.GetOrAdd(ipAddress.ToString(), new LookupClient(ipAddress));
		}

		/// <summary>
		/// Caches <see cref="LookupClient"/>s by domainName. Use <see cref="Default"/> instead if a name server for a specific domain name is not required.
		/// </summary>
		/// <param name="domainName"></param>
		/// <returns>Returns an <see cref="ILookupClient"/> using a name server associated with the specified domain name.</returns>
		public ILookupClient GetOrAdd(string domainName)
		{
			var rootDomain = _dnsService.GetRootDomain(domainName);
			IPAddress[] ipAddresses = _dnsService.GetNameServerIpAddresses(Default, rootDomain).ToArray();

			return _lookupClients.GetOrAdd(rootDomain, new LookupClient(ipAddresses));
		}
	}
}