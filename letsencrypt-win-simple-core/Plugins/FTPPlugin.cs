﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using LetsEncrypt.ACME.Simple.Core.Configuration;
using LetsEncrypt.ACME.Simple.Core.Interfaces;
using Serilog;

namespace LetsEncrypt.ACME.Simple.Core.Plugins
{
    public class FTPPlugin : Plugin
    {
        protected IOptions Options;
        protected ICertificateService CertificateService;
        protected ILetsEncryptService LetsEncryptService;
        protected IConsoleService ConsoleService;
        public FTPPlugin(IOptions options, ICertificateService certificateService, 
            ILetsEncryptService letsEncryptService, IConsoleService consoleService, 
            IPluginService pluginService) : base(pluginService)
        {
            Options = options;
            CertificateService = certificateService;
            LetsEncryptService = letsEncryptService;
            ConsoleService = consoleService;
        }

        private NetworkCredential FtpCredentials { get; set; }

        public override string Name => "FTP";

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
            if (!string.IsNullOrWhiteSpace(Options.Script) &&
                !string.IsNullOrWhiteSpace(Options.ScriptParameters))
            {
                var parameters = string.Format(Options.ScriptParameters, target.Host,
                    Properties.Settings.Default.PFXPassword,
                    pfxFilename, store.Name, certificate.FriendlyName, certificate.Thumbprint);
                Log.Information("Running {Script} with {parameters}", Options.Script, parameters);
                Process.Start(Options.Script, parameters);
            }
            else if (!string.IsNullOrWhiteSpace(Options.Script))
            {
                Log.Information("Running {Script}", Options.Script);
                Process.Start(Options.Script);
            }
            else
            {
                Log.Information(" WARNING: Unable to configure server software.");
            }
        }

        public override void Install(Target target)
        {
            // This method with just the Target paramater is currently only used by Centralized SSL
            if (!string.IsNullOrWhiteSpace(Options.Script) &&
                !string.IsNullOrWhiteSpace(Options.ScriptParameters))
            {
                var parameters = string.Format(Options.ScriptParameters, target.Host,
                    Properties.Settings.Default.PFXPassword, Options.CentralSslStore);
                Log.Information("Running {Script} with {parameters}", Options.Script, parameters);
                Process.Start(Options.Script, parameters);
            }
            else if (!string.IsNullOrWhiteSpace(Options.Script))
            {
                Log.Information("Running {Script}", Options.Script);
                Process.Start(Options.Script);
            }
            else
            {
                Log.Warning(" WARNING: Unable to configure server software.");
            }
        }

        public override void Renew(Target target)
        {
            Log.Warning(" WARNING: Renewal is not supported for the FTP Plugin.");
        }

        public override void PrintMenu()
        {
            ConsoleService.WriteLine(" F: Generate a certificate via FTP/ FTPS and install it manually.");
        }

        public override void HandleMenuResponse(string response, List<Target> targets)
        {
            if (response == "f")
            {
                ConsoleService.Write("Enter a host name: ");
                var hostName = ConsoleService.ReadLine();
                string[] alternativeNames = null;
                if (Options.San)
                    alternativeNames = ConsoleService.GetSanNames();
                ConsoleService.WriteLine("Enter a site path (the web root of the host for http authentication)");
                ConsoleService.WriteLine("Example, ftp://domain.com:21/site/wwwroot/");
                ConsoleService.WriteLine("Example, ftps://domain.com:990/site/wwwroot/");
                ConsoleService.Write(": ");
                var ftpPath = ConsoleService.ReadLine();

                ConsoleService.Write("Enter the FTP username: ");
                var ftpUser = ConsoleService.ReadLine();

                ConsoleService.Write("Enter the FTP password: ");
                var ftpPass = ConsoleService.ReadPassword();

                FtpCredentials = new NetworkCredential(ftpUser, ftpPass);

                List<string> sanList = new List<string>();

                if (alternativeNames != null)
                {
                    sanList = new List<string>(alternativeNames);
                }
                if (sanList.Count <= 100)
                {
                    var target = new Target
                    {
                        Host = hostName,
                        WebRootPath = ftpPath,
                        PluginName = Name,
                        AlternativeNames = sanList
                    };

                    Auto(target);
                }
                else
                {
                    Log.Error(
                        "You entered too many hosts for a San certificate. Let's Encrypt currently has a maximum of 100 alternative names per certificate.");
                }
            }
        }

        public override void Auto(Target target)
        {
            if (FtpCredentials != null)
            {
                var auth = LetsEncryptService.Authorize(target);
                if (auth.Status == "valid")
                {
                    var pfxFilename = LetsEncryptService.GetCertificate(target);
                    ConsoleService.WriteLine("");
                    Log.Information("You can find the certificate at {pfxFilename}", pfxFilename);
                }
            }
            else
            {
                Log.Warning("The FTP Credentials are not set. Please specify them and try again.");
            }
        }

        public override void CreateAuthorizationFile(string answerPath, string fileContents)
        {
            Log.Information("Writing challenge answer to {answerPath}", answerPath);
            Upload(answerPath, fileContents);
        }

        private void EnsureDirectories(Uri ftpUri)
        {
            string[] directories = ftpUri.AbsolutePath.Split('/');

            var scheme = ftpUri.Scheme;
            if (ftpUri.Scheme == "ftps")
            {
                scheme = "ftp";
                Log.Debug("Using SSL");
            }
            string ftpConnection = scheme + "://" + ftpUri.Host + ":" + ftpUri.Port + "/";
            Log.Debug("ftpConnection {@ftpConnection}", ftpConnection);

            Log.Debug("UserName {@UserName}", FtpCredentials.UserName);

            if (directories.Length > 1)
            {
                for (int i = 1; i < (directories.Length - 1); i++)
                {
                    ftpConnection = ftpConnection + directories[i] + "/";
                    FtpWebRequest request = (FtpWebRequest) WebRequest.Create(ftpConnection);
                    request.Method = WebRequestMethods.Ftp.MakeDirectory;
                    request.Credentials = FtpCredentials;

                    if (ftpUri.Scheme == "ftps")
                    {
                        request.EnableSsl = true;
                        request.UsePassive = true;
                    }

                    try
                    {
                        FtpWebResponse response = (FtpWebResponse) request.GetResponse();
                        Stream ftpStream = response.GetResponseStream();

                        ftpStream.Close();
                        response.Close();
                    }
                    catch (Exception ex)
                    {
                        Log.Warning("Error creating FTP directory {@ex}", ex);
                    }
                }
            }
        }

        private void Upload(string ftpPath, string content)
        {
            Uri ftpUri = new Uri(ftpPath);
            Log.Debug("ftpUri {@ftpUri}", ftpUri);
            EnsureDirectories(ftpUri);
            var scheme = ftpUri.Scheme;
            if (ftpUri.Scheme == "ftps")
            {
                scheme = "ftp";
                Log.Debug("Using SSL");
            }
            string ftpConnection = scheme + "://" + ftpUri.Host + ":" + ftpUri.Port + ftpUri.AbsolutePath;
            Log.Debug("ftpConnection {@ftpConnection}", ftpConnection);

            Log.Debug("UserName {@UserName}", FtpCredentials.UserName);

            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(content);
            writer.Flush();
            stream.Position = 0;

            FtpWebRequest request = (FtpWebRequest) WebRequest.Create(ftpConnection);

            request.Method = WebRequestMethods.Ftp.UploadFile;
            request.Credentials = FtpCredentials;

            if (ftpUri.Scheme == "ftps")
            {
                request.EnableSsl = true;
                request.UsePassive = true;
            }

            Stream requestStream = request.GetRequestStream();
            stream.CopyTo(requestStream);
            requestStream.Close();

            using (FtpWebResponse response = (FtpWebResponse)request.GetResponse())
                Log.Information("Upload Status {StatusDescription}", response.StatusDescription);
        }

        private void Delete(string ftpPath, FileType fileType)
        {
            Uri ftpUri = new Uri(ftpPath);
            Log.Debug("ftpUri {@ftpUri}", ftpUri);
            var scheme = ftpUri.Scheme;
            if (ftpUri.Scheme == "ftps")
            {
                scheme = "ftp";
                Log.Debug("Using SSL");
            }
            string ftpConnection = scheme + "://" + ftpUri.Host + ":" + ftpUri.Port + ftpUri.AbsolutePath;
            Log.Debug("ftpConnection {@ftpConnection}", ftpConnection);

            Log.Debug("UserName {@UserName}", FtpCredentials.UserName);

            FtpWebRequest request = (FtpWebRequest) WebRequest.Create(ftpConnection);

            if (fileType == FileType.File)
            {
                request.Method = WebRequestMethods.Ftp.DeleteFile;
            }
            else if (fileType == FileType.Directory)
            {
                request.Method = WebRequestMethods.Ftp.RemoveDirectory;
            }
            request.Credentials = FtpCredentials;

            if (ftpUri.Scheme == "ftps")
            {
                request.EnableSsl = true;
                request.UsePassive = true;
            }

            using (FtpWebResponse response = (FtpWebResponse)request.GetResponse())
                Log.Information("Delete Status {StatusDescription}", response.StatusDescription);
        }

        private string GetFiles(string ftpPath)
        {
            Uri ftpUri = new Uri(ftpPath);
            Log.Debug("ftpUri {@ftpUri}", ftpUri);
            var scheme = ftpUri.Scheme;
            if (ftpUri.Scheme == "ftps")
            {
                scheme = "ftp";
                Log.Debug("Using SSL");
            }
            string ftpConnection = scheme + "://" + ftpUri.Host + ":" + ftpUri.Port + ftpUri.AbsolutePath;
            Log.Debug("ftpConnection {@ftpConnection}", ftpConnection);

            Log.Debug("UserName {@UserName}", FtpCredentials.UserName);

            FtpWebRequest request = (FtpWebRequest) WebRequest.Create(ftpConnection);

            request.Method = WebRequestMethods.Ftp.ListDirectory;
            request.Credentials = FtpCredentials;

            if (ftpUri.Scheme == "ftps")
            {
                request.EnableSsl = true;
                request.UsePassive = true;
            }

            FtpWebResponse response = (FtpWebResponse) request.GetResponse();

            Stream responseStream = response.GetResponseStream();
            StreamReader reader = new StreamReader(responseStream);
            string names = reader.ReadToEnd();

            reader.Close();
            response.Close();

            Log.Debug("Files {@names}", names);
            return names.TrimEnd('\r', '\n');
        }

        private readonly string _sourceFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "web_config.xml");

        public override void BeforeAuthorize(Target target, string answerPath, string token)
        {
            answerPath = answerPath.Remove((answerPath.Length - token.Length), token.Length);
            var webConfigPath = Path.Combine(answerPath, "web.config");
            
            Log.Information("Writing web.config to add extensionless mime type to {webConfigPath}", webConfigPath);

            Upload(webConfigPath, File.ReadAllText(_sourceFilePath));
        }

        public override void DeleteAuthorization(string answerPath, string token, string webRootPath, string filePath)
        {
            Log.Information("Deleting answer");
            Delete(answerPath, FileType.File);

            try
            {
                if (Properties.Settings.Default.CleanupFolders == true)
                {
                    var folderPath = answerPath.Remove((answerPath.Length - token.Length), token.Length);
                    var files = GetFiles(folderPath);

                    if (!string.IsNullOrWhiteSpace(files))
                    {
                        if (files == "web.config")
                        {
                            Log.Information("Deleting web.config");
                            Delete(folderPath + "web.config", FileType.File);
                            Log.Information("Deleting {folderPath}", folderPath);
                            Delete(folderPath, FileType.Directory);
                            var filePathFirstDirectory =
                                Environment.ExpandEnvironmentVariables(Path.Combine(webRootPath,
                                    filePath.Remove(filePath.IndexOf("/"), (filePath.Length - filePath.IndexOf("/")))));
                            Log.Information("Deleting {filePathFirstDirectory}", filePathFirstDirectory);
                            Delete(filePathFirstDirectory, FileType.Directory);
                        }
                        else
                        {
                            Log.Warning("Additional files exist in {folderPath} not deleting.", folderPath);
                        }
                    }
                    else
                    {
                        Log.Warning("Additional files exist in {folderPath} not deleting.", folderPath);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("Error occured while deleting folder structure. Error: {@ex}", ex);
            }
        }

        private enum FileType
        {
            File,
            Directory
        }
    }
}