﻿using ACMESharp;
using ACMESharp.JOSE;

namespace LetsEncrypt.ACME.Simple.Core.Interfaces
{
    public interface IAcmeClientService
    {
        void ConfigureAcmeClient(AcmeClient client);
        void ConfigureSigner(RS256Signer signer);
        AcmeRegistration CreateRegistration(AcmeClient acmeClient, string[] contacts);
        void LoadRegistrationFromFile(AcmeClient acmeClient, string registrationPath);
    }
}