using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using Kentor.AuthServices.WebSso;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using System.Diagnostics.CodeAnalysis;

namespace Sustainsys.Saml2.AspNetCore2
{
    /// <summary>
    /// Authentication handler for Saml2
    /// </summary>
    public class Saml2Handler : IAuthenticationRequestHandler, IAuthenticationSignOutHandler
    {
        private readonly IOptionsMonitorCache<Saml2Options> optionsCache;
        Saml2Options options;
        HttpContext context;
        private readonly IDataProtector dataProtector;
        AuthenticationScheme scheme;
        private readonly IOptionsFactory<Saml2Options> optionsFactory;
        private readonly ILogger<Saml2Handler> logger;

        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="optionsCache">Options</param>
        /// <param name="dataProtectorProvider">Data Protector Provider</param>
        /// <param name="optionsFactory">Factory for options</param>
        /// <param name="logger">Logger</param>
        public Saml2Handler(
            IOptionsMonitorCache<Saml2Options> optionsCache,
            IDataProtectionProvider dataProtectorProvider,
            IOptionsFactory<Saml2Options> optionsFactory,
            ILogger<Saml2Handler> logger)
        {
            if (dataProtectorProvider == null)
            {
                throw new ArgumentNullException(nameof(dataProtectorProvider));
            }

            dataProtector = dataProtectorProvider.CreateProtector(GetType().FullName);

            this.optionsFactory = optionsFactory;
            this.optionsCache = optionsCache;
            this.logger = logger;
        }

        /// <InheritDoc />
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1500:VariableNamesShouldNotMatchFieldNames", MessageId = "scheme")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1500:VariableNamesShouldNotMatchFieldNames", MessageId = "context")]
        public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
        {
            this.context = context;
            this.scheme = scheme;
            options = optionsCache.GetOrAdd(scheme.Name, () => optionsFactory.Create(scheme.Name));

            return Task.CompletedTask;
        }

        /// <InheritDoc />
        [ExcludeFromCodeCoverage]
        public Task<AuthenticateResult> AuthenticateAsync()
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        /// <InheritDoc />
        public async Task ChallengeAsync(AuthenticationProperties properties)
        {
            properties = properties ?? new AuthenticationProperties();

            // Don't serialize the return url twice, move it to our location.
            var redirectUri = properties.RedirectUri;
            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = (context.Features.Get<IAuthenticationFeature>()?.OriginalPathBase ?? context.Request.PathBase) + context.Request.Path + context.Request.QueryString;
            }
            properties.RedirectUri = null;

            var requestData = context.ToHttpRequestData(null);

            var result = SignInCommand.Run(
                null,
                redirectUri,
                requestData,
                options,
                properties.Items);

            await result.Apply(context, dataProtector, scheme.Name);
            logger.LogInformation($"AuthenticationScheme: {scheme.Name} was challenged.");
        }

        /// <InheritDoc />
        [ExcludeFromCodeCoverage]
        public Task ForbidAsync(AuthenticationProperties properties)
        {
            return Task.CompletedTask;
        }

        /// <InheritDoc />
        public async Task<bool> HandleRequestAsync()
        {
            if(context.Request.Path.StartsWithSegments(options.SPOptions.ModulePath, StringComparison.Ordinal))
            {
                var commandName = context.Request.Path.Value.Substring(
                    options.SPOptions.ModulePath.Length).TrimStart('/');

                // Exclude logout, since that is handled in the middleware
                if (commandName == CommandFactory.LogoutCommandName) {
                    return false;
                }

                var commandResult = CommandFactory.GetCommand(commandName).Run(
                    context.ToHttpRequestData(dataProtector.Unprotect), options);

                await commandResult.Apply(context, dataProtector, options.SignInScheme);

                return true;
            }
            return false;
        }

        /// <InheritDoc />
        public async Task SignOutAsync(AuthenticationProperties properties)
        {
            properties = properties ?? new AuthenticationProperties();

            // Don't serialize the return url twice, move it to our location.
            var redirectUri = properties.RedirectUri;
            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = (context.Features.Get<IAuthenticationFeature>()?.OriginalPathBase ?? context.Request.PathBase) + context.Request.Path + context.Request.QueryString;
            }
            properties.RedirectUri = null;

            var requestData = context.ToHttpRequestData(null);

            var result = LogoutCommand.Run(
                requestData,
                redirectUri,
                options);

            result.TerminateLocalSession = false;

            await result.Apply(context, dataProtector, scheme.Name);
            logger.LogInformation($"AuthenticationScheme: {scheme.Name} started signout.");
        }
    }
}
