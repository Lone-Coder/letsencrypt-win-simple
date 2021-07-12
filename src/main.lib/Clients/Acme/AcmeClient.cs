using ACMESharp;
using ACMESharp.Authorizations;
using ACMESharp.Protocol;
using acme = ACMESharp.Protocol.Resources;
using Newtonsoft.Json;
using PKISharp.WACS.Configuration;
using PKISharp.WACS.Configuration.Arguments;
using PKISharp.WACS.Extensions;
using PKISharp.WACS.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using PKISharp.WACS.DomainObjects;

namespace PKISharp.WACS.Clients.Acme
{
    /// <summary>
    /// Main class that talks to the ACME server
    /// </summary>
    internal class AcmeClient : IDisposable
    {
        /// <summary>
        /// https://tools.ietf.org/html/rfc8555#section-7.1.6
        /// </summary>
        public const string OrderPending = "pending"; // new order
        public const string OrderReady = "ready"; // all authorizations done
        public const string OrderProcessing = "processing"; // busy issuing
        public const string OrderInvalid = "invalid"; // validation/order error
        public const string OrderValid = "valid"; // certificate issued

        public const string AuthorizationValid = "valid";
        public const string AuthorizationInvalid = "invalid";
        public const string AuthorizationPending = "pending";
        public const string AuthorizationProcessing = "processing";

        public const string ChallengeValid = "valid";

        private readonly ILogService _log;
        private readonly IInputService _input;
        private readonly ISettingsService _settings;
        private readonly ArgumentsParser _arguments;
        private readonly IProxyService _proxyService;
        private readonly ZeroSsl _zeroSsl;
        private readonly AccountArguments _accountArguments;

        private AcmeProtocolClient? _client;
        private readonly AccountManager _accountManager;
        private bool _initialized = false;

        public AcmeClient(
            IInputService inputService,
            ArgumentsParser arguments,
            ILogService log,
            ISettingsService settings,
            AccountManager accountManager,
            IProxyService proxy,
            ZeroSsl zeroSsl)
        {
            _log = log;
            _settings = settings;
            _arguments = arguments;
            _accountArguments = _arguments.GetArguments<AccountArguments>() ?? new AccountArguments();
            _input = inputService;
            _proxyService = proxy;
            _accountManager = accountManager;
            _zeroSsl = zeroSsl;
        }

        internal async Task ConfigureAcmeClient()
        {
            var httpClient = _proxyService.GetHttpClient();
            httpClient.BaseAddress = _settings.BaseUri;
            _log.Verbose("Constructing ACME protocol client...");
            var client = new AcmeProtocolClient(httpClient, usePostAsGet: _settings.Acme.PostAsGet);
            try
            {
                client.Directory = await client.GetDirectoryAsync();
            }
            catch (Exception)
            {
                // Perhaps the BaseUri *is* the directory, such
                // as implemented by Digicert (#1434)
                client.Directory.Directory = "";
                client.Directory = await client.GetDirectoryAsync();
            }

            // Try to load prexisting account
            if (_accountManager.CurrentAccount != null && 
                _accountManager.CurrentSigner != null)
            {
                _log.Verbose("Using existing ACME account");
                await client.ChangeAccountKeyAsync(_accountManager.CurrentSigner.JwsTool());
                client.Account = _accountManager.CurrentAccount;
            } 
            else
            {
                _log.Verbose("No account found, creating new one");
                await SetupAccount(client);
            }
            if (client.Account == null)
            {
                throw new Exception("AcmeClient was unable to find or create an account");
            }
            _client = client;
            _log.Verbose("ACME client initialized");
        }

        internal async Task<AccountDetails?> GetAccount() => (await GetClient()).Account;

        internal async Task<AcmeProtocolClient> GetClient()
        {
            if (!_initialized)
            {
                await ConfigureAcmeClient();
                _initialized = true;
            }
            if (_client == null)
            {
                throw new InvalidOperationException("Failed to initialize AcmeProtocolClient");
            }
            return _client;
        }

        /// <summary>
        /// Setup a new ACME account
        /// </summary>
        /// <param name="client"></param>
        /// <returns></returns>
        private async Task SetupAccount(AcmeProtocolClient client)
        {
            // Accept the terms of service, if defined by the server
            try 
            {
                var (_, filename, content) = await client.GetTermsOfServiceAsync();
                _log.Verbose("Terms of service downloaded");
                if (!string.IsNullOrEmpty(filename))
                {
                    if (!await AcceptTos(filename, content))
                    {
                        return;
                    }
                }
            } 
            catch (Exception ex)
            {
                _log.Error(ex, "Error getting terms of service");
            }

            var contacts = default(string[]);

            var eabKid = _accountArguments.EabKeyIdentifier;
            var eabKey = _accountArguments.EabKey;
            var eabAlg = _accountArguments.EabAlgorithm ?? "HS256";
            var eabFlow = client.Directory?.Meta?.ExternalAccountRequired == "true";
            var zeroSslFlow = _settings.BaseUri.Host.Contains("zerossl.com");

            // Warn about unneeded EAB
            if (!eabFlow && !string.IsNullOrWhiteSpace(eabKid))
            {
                eabFlow = true;
                _input.CreateSpace();
                _input.Show(null, "You have provided an external account binding key, even though " +
                    "the server does not indicate that this is required. We will attempt to register " +
                    "using this key anyway.");
            }

            if (zeroSslFlow)
            {
                async Task emailRegistration()
                {
                    var registration = await GetContacts(allowMultiple: false, prefix: "");
                    var eab = await _zeroSsl.Register(registration.FirstOrDefault() ?? "");
                    if (eab != null)
                    {
                        eabKid = eab.Kid;
                        eabKey = eab.Hmac;
                    }
                    else
                    {
                        _log.Error("Unable to retrieve EAB credentials using the provided email address");
                    }
                }
                async Task apiKeyRegistration(string accessKey) 
                {
                    var eab = await _zeroSsl.Obtain(accessKey);
                    if (eab != null)
                    {
                        eabKid = eab.Kid;
                        eabKey = eab.Hmac;
                    }
                    else
                    {
                        _log.Error("Unable to retrieve EAB credentials using the provided API access key");
                    }
                };
                async Task apiKeyRegistrationManualInput()
                {
                    var accessKey = await _input.ReadPassword("API access key");
                    await apiKeyRegistration(accessKey ?? "");
                };
                if (!string.IsNullOrWhiteSpace(_accountArguments.EmailAddress))
                {
                    await emailRegistration();
                }
                else if (!string.IsNullOrWhiteSpace(_accountArguments.ApiKey))
                {
                    await apiKeyRegistration(_accountArguments.ApiKey);
                }
                else
                {
                    var instruction = "ZeroSsl can be used either by setting up a new " +
                        "account using your email address or by connecting it to your existing " +
                        "account using the API access key or pre-generated EAB credentials, which can " +
                        "be obtained from the Developer section of the dashboard.";
                    _input.CreateSpace();
                    _input.Show(null, instruction);
                    var chosen = await _input.ChooseFromMenu(
                        "How would you like to create the account?",
                        new List<Choice<Func<Task>>>()
                        {
                            Choice.Create((Func<Task>)apiKeyRegistrationManualInput, "API access key"),
                            Choice.Create((Func<Task>)emailRegistration, "Email address"),
                            Choice.Create<Func<Task>>(() => Task.CompletedTask, "Input EAB credentials directly")
                        });
                    await chosen.Invoke();
                }
            }

            if (eabFlow)
            {
                if (string.IsNullOrWhiteSpace(eabKid))
                {
                    var instruction = "This ACME endpoint requires an external account. " +
                        "You will need to provide a key identifier and a key to proceed. " +
                        "Please refer to the providers instructions on how to obtain these.";
                    _input.CreateSpace();
                    _input.Show(null, instruction);
                    eabKid = await _input.RequestString("Key identifier");
                }
                if (string.IsNullOrWhiteSpace(eabKey))
                {
                    eabKey = await _input.ReadPassword("Key (base64url encoded)");
                }
              
            } 
            else
            {
                contacts = await GetContacts();
            }

            var signer = _accountManager.DefaultSigner();
            try
            {
                await CreateAccount(client, signer, contacts, eabAlg, eabKid, eabKey);
            }
            catch (AcmeProtocolException apex)
            {
                // Some non-ACME compliant server may not support ES256 or other
                // algorithms, so attempt fallback to RS256
                if (apex.ProblemType == acme.ProblemType.BadSignatureAlgorithm && 
                    signer.KeyType != "RS256")
                {
                    signer = _accountManager.NewSigner("RS256");
                    await CreateAccount(client, signer, contacts, eabAlg, eabKid, eabKey);
                } 
                else
                {
                    throw;
                }
            }
            catch (Exception ex)
            {
                _log.Error(ex, "Error creating account");
                throw;
            }
        }

        /// <summary>
        /// Attempt to create an account using specific parameters
        /// </summary>
        /// <param name="client"></param>
        /// <param name="signer"></param>
        /// <param name="contacts"></param>
        /// <param name="eabAlg"></param>
        /// <param name="eabKid"></param>
        /// <param name="eabKey"></param>
        /// <returns></returns>
        private async Task CreateAccount(
            AcmeProtocolClient client, AccountSigner signer,
            string[]? contacts,
            string eabAlg, string? eabKid, string? eabKey)
        {
            if (client.Account != null)
            {
                throw new Exception("Client already has an account!");
            }
            ExternalAccountBinding? externalAccount = null;
            if (!string.IsNullOrWhiteSpace(eabKey) && 
                !string.IsNullOrWhiteSpace(eabKid))
            {
                externalAccount = new ExternalAccountBinding(
                    eabAlg,
                    JsonConvert.SerializeObject(
                        signer.JwsTool().ExportJwk(),
                        Formatting.None),
                    eabKid,
                    eabKey,
                    client.Directory?.NewAccount ?? "");
            }
            await client.ChangeAccountKeyAsync(signer.JwsTool());
            client.Account = await Retry(client, 
                () => client.CreateAccountAsync(
                    contacts,
                    termsOfServiceAgreed: true, 
                    externalAccountBinding: externalAccount?.Payload() ?? null));
            _accountManager.CurrentSigner = signer;
            _accountManager.CurrentAccount = client.Account;
        }

        /// <summary>
        /// Ask the user to accept the terms of service dictated 
        /// by the ACME service operator
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="content"></param>
        /// <returns></returns>
        private async Task<bool> AcceptTos(string filename, byte[] content)
        {
            var tosPath = Path.Combine(_settings.Client.ConfigurationPath, filename);
            _log.Verbose("Writing terms of service to {path}", tosPath);
            await File.WriteAllBytesAsync(tosPath, content);
            _input.CreateSpace();
            _input.Show($"Terms of service", tosPath);
            if (_arguments.GetArguments<AccountArguments>()?.AcceptTos ?? false)
            {
                return true;
            }
            if (await _input.PromptYesNo($"Open in default application?", false))
            {
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = tosPath,
                        UseShellExecute = true
                    });
                }
                catch (Exception ex)
                {
                    _log.Error(ex, "Unable to start application");
                }
            }
            return await _input.PromptYesNo($"Do you agree with the terms?", true);
        }

        /// <summary>
        /// Test the network connection
        /// </summary>
        internal async Task CheckNetwork()
        {
            using var httpClient = _proxyService.GetHttpClient();
            httpClient.BaseAddress = _settings.BaseUri;
            httpClient.Timeout = new TimeSpan(0, 0, 10);
            try
            {
                _log.Verbose("SecurityProtocol setting: {setting}", System.Net.ServicePointManager.SecurityProtocol);
                _ = await httpClient.GetAsync("directory").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log.Error(ex, "Initial connection failed, retrying with TLS 1.2 forced");
                _proxyService.SslProtocols = SslProtocols.Tls12;
                using var altClient = _proxyService.GetHttpClient();
                altClient.BaseAddress = _settings.BaseUri;
                altClient.Timeout = new TimeSpan(0, 0, 10);
                try
                {
                    _ = await altClient.GetAsync("directory").ConfigureAwait(false);
                }
                catch (Exception ex2)
                {
                    _log.Error(ex2, "Unable to connect to ACME server");
                    return;
                }
            }
            _log.Debug("Connection OK!");
        }

        /// <summary>
        /// Get contact information
        /// </summary>
        /// <returns></returns>
        private async Task<string[]> GetContacts(bool allowMultiple = true, string prefix = "mailto:")
        {
            var email = _accountArguments.EmailAddress;
            if (string.IsNullOrWhiteSpace(email))
            {
                var question = allowMultiple ?
                    "Enter email(s) for notifications about problems and abuse (comma-separated)" :
                    "Enter email for notifications about problems and abuse";
                email = await _input.RequestString(question);
            }
            var newEmails = new List<string>();
            if (allowMultiple)
            {
                newEmails = email.ParseCsv();
                if (newEmails == null)
                {
                    return new string[] { };
                }
            } 
            else
            {
                newEmails.Add(email);
            }
            newEmails = newEmails.Where(x =>
            {
                try
                {
                    _ = new MailAddress(x);
                    return true;
                }
                catch
                {
                    _log.Warning($"Invalid email: {x}");
                    return false;
                }
            }).ToList();
            if (!newEmails.Any())
            {
                _log.Warning("No (valid) email address specified");
            }
            return newEmails.Select(x => $"{prefix}{x}").ToArray();
        }

        internal async Task<IChallengeValidationDetails> DecodeChallengeValidation(acme.Authorization auth, acme.Challenge challenge)
        {
            var client = await GetClient();
            return AuthorizationDecoder.DecodeChallengeValidation(auth, challenge.Type, client.Signer);
        }

        internal async Task<acme.Challenge> AnswerChallenge(acme.Challenge challenge)
        {
            // Have to loop to wait for server to stop being pending
            var client = await GetClient();
            challenge = await Retry(client, () => client.AnswerChallengeAsync(challenge.Url));
            var tries = 1;
            while (
                challenge.Status == AuthorizationPending ||
                challenge.Status == AuthorizationProcessing)
            {
                await Task.Delay(_settings.Acme.RetryInterval * 1000);
                _log.Debug("Refreshing authorization ({tries}/{count})", tries, _settings.Acme.RetryCount);
                challenge = await Retry(client, () => client.GetChallengeDetailsAsync(challenge.Url));
                tries += 1;
                if (tries > _settings.Acme.RetryCount)
                {
                    break;
                }
            }
            return challenge;
        }

        internal async Task<OrderDetails> CreateOrder(IEnumerable<Identifier> identifiers)
        {
            var client = await GetClient();
            var acmeIdentifiers = identifiers.Select(i => new acme.Identifier() { 
                Type = i.Type switch
                {
                    IdentifierType.DnsName => "dns", // rfc8555
                    IdentifierType.IpAddress => "ip", // rfc8738
                    _ => throw new NotImplementedException($"Identifier {i.Type} is not supported")
                }, 
                Value = i.Value 
            });
            return await Retry(client, () => client.CreateOrderAsync(acmeIdentifiers));
        }

        internal async Task<acme.Challenge> GetChallengeDetails(string url)
        {
            var client = await GetClient();
            return await Retry(client, () => client.GetChallengeDetailsAsync(url));
        }

        internal async Task<acme.Authorization> GetAuthorizationDetails(string url)
        {
            var client = await GetClient();
            return await Retry(client, () => client.GetAuthorizationDetailsAsync(url));
        }

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
        /// </summary>
        /// <param name="details"></param>
        /// <param name="csr"></param>
        /// <returns></returns>
        internal async Task<OrderDetails> SubmitCsr(OrderDetails details, byte[] csr)
        {
            // First wait for the order to get "ready", meaning that all validations
            // are complete. The program makes sure this is the case at the level of 
            // individual authorizations, but the server might need some extra time to
            // propagate this status at the order level.
            var client = await GetClient();
            await WaitForOrderStatus(details, OrderReady);
            if (details.Payload.Status == OrderReady)
            {
                details = await Retry(client, () => client.FinalizeOrderAsync(details.Payload.Finalize, csr));
                await WaitForOrderStatus(details, OrderProcessing, true);
            } 
            return details;
        }

        /// <summary>
        /// Helper function to check/refresh order state
        /// </summary>
        /// <param name="details"></param>
        /// <param name="status"></param>
        /// <param name="negate"></param>
        /// <returns></returns>
        private async Task WaitForOrderStatus(OrderDetails details, string status, bool negate = false)
        {
            // Wait for processing
            _ = await GetClient();
            var tries = 0;
            do
            {
                if (tries > 0)
                {
                    if (tries > _settings.Acme.RetryCount)
                    {
                        break;
                    }
                    _log.Debug($"Waiting for order to get {(negate ? "NOT " : "")}{{ready}} ({{tries}}/{{count}})", status, tries, _settings.Acme.RetryCount);
                    await Task.Delay(_settings.Acme.RetryInterval * 1000);
                    var update = await GetOrderDetails(details.OrderUrl);
                    details.Payload = update.Payload;
                }
                tries += 1;
            } while (
                (negate && details.Payload.Status == status) ||
                (!negate && details.Payload.Status != status)
            );
        }

        internal async Task<OrderDetails> GetOrderDetails(string url)
        {
            var client = await GetClient();
            return await Retry(client, () => client.GetOrderDetailsAsync(url));
        }

        internal async Task ChangeContacts()
        {
            var client = await GetClient();
            var contacts = await GetContacts();
            var account = await Retry(client, () => client.UpdateAccountAsync(contacts, client.Account));
            await UpdateAccount(client);
        }

        internal async Task UpdateAccount(AcmeProtocolClient client)
        {
            var account = await Retry(client, () => client.CheckAccountAsync());
            _accountManager.CurrentAccount = account;
            client.Account = account;
        }

        internal async Task<AcmeCertificate> GetCertificate(OrderDetails order)
        {
            var client = await GetClient();
            return await Retry(client, () => client.GetOrderCertificateExAsync(order));
        }

        internal async Task<byte[]> GetCertificate(string url)
        {
            var client = await GetClient();
            return await Retry(client, async () => {
                var response = await client.GetAsync(url);
                return await response.Content.ReadAsByteArrayAsync();
            });
        }

        internal async Task RevokeCertificate(byte[] crt)
        {
            var client = await GetClient();
            _ = await Retry(client, async () => client.RevokeCertificateAsync(crt, acme.RevokeReason.Unspecified));
        }

        /// <summary>
        /// According to the ACME standard, we SHOULD retry calls
        /// if there is an invalid nonce. TODO: check for the proper 
        /// exception feedback, now *any* failed request is retried
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="executor"></param>
        /// <returns></returns>
        private async Task<T> Retry<T>(AcmeProtocolClient client, Func<Task<T>> executor, int attempt = 0)
        {
            if (attempt == 0)
            {
                await _requestLock.WaitAsync();  
            }
            try
            {
                if (string.IsNullOrEmpty(client.NextNonce))
                {
                    await client.GetNonceAsync();
                }
                return await executor();
            }
            catch (AcmeProtocolException apex)
            {
                if (attempt < 3 && apex.ProblemType == acme.ProblemType.BadNonce)
                {
                    _log.Warning("First chance error calling into ACME server, retrying with new nonce...");
                    await client.GetNonceAsync();
                    return await Retry(client, executor, attempt + 1);
                }
                else if (apex.ProblemType == acme.ProblemType.UserActionRequired)
                {
                    _log.Error("{detail}: {instance}", apex.ProblemDetail, apex.ProblemInstance);
                    throw;
                } 
                else
                {
                    throw;
                }
            }
            finally
            {
                if (attempt == 0)
                {
                    _requestLock.Release();
                }
            }
        }

        /// <summary>
        /// Prevent sending simulateous requests to the ACME service because it messes
        /// up the nonce tracking mechanism
        /// </summary>
        private readonly SemaphoreSlim _requestLock = new SemaphoreSlim(1, 1);

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing && _client != null)
                {
                    _client.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~AcmeClient()
        // {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose() =>
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);// TODO: uncomment the following line if the finalizer is overridden above.// GC.SuppressFinalize(this);
        #endregion
    }
}
