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
using Microsoft.Extensions.DependencyInjection;

namespace Sustainsys.Saml2.AspNetCore2
{
    /// <summary>
    /// Logout middleware for Saml2. This is required because, in the handler, we don't know the user yet, and the user is required for logout,
    /// so we need a middlewear which runs after authorization is complete.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
    public class Saml2LogoutMiddleware : IMiddleware
    {
        private readonly IOptionsMonitorCache<Saml2Options> optionsCache;
        private readonly IDataProtector dataProtector;
        private readonly IOptionsFactory<Saml2Options> optionsFactory;
        private readonly IAuthenticationSchemeProvider schemes;

        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="optionsCache">Options</param>
        /// <param name="dataProtectorProvider">Data Protector Provider</param>
        /// <param name="optionsFactory">Factory for options</param>
        /// <param name="schemes">Authentication Scheme Provider</param>
        public Saml2LogoutMiddleware(
            IOptionsMonitorCache<Saml2Options> optionsCache,
            IDataProtectionProvider dataProtectorProvider,
            IOptionsFactory<Saml2Options> optionsFactory,
            IAuthenticationSchemeProvider schemes)
        {
            if (dataProtectorProvider == null)
            {
                throw new ArgumentNullException(nameof(dataProtectorProvider));
            }

            dataProtector = dataProtectorProvider.CreateProtector(GetType().FullName);

            this.optionsFactory = optionsFactory;
            this.optionsCache = optionsCache;
            this.schemes = schemes;
        }


        /// <InheritDoc />
        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            var handlers = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
            foreach(var scheme in await schemes.GetRequestHandlerSchemesAsync())
            {
                var handler = await handlers.GetHandlerAsync(context, scheme.Name) as Saml2Handler;
                if (handler == null)
                {
                    continue;
                }

                var options = optionsCache.GetOrAdd(scheme.Name, () => optionsFactory.Create(scheme.Name));

                if (options.SPOptions == null) {
                    continue;
                }

                if(context.Request.Path.StartsWithSegments(options.SPOptions.ModulePath, StringComparison.Ordinal))
                {
                    var commandName = context.Request.Path.Value.Substring(
                        options.SPOptions.ModulePath.Length).TrimStart('/');

                    if (commandName == CommandFactory.LogoutCommandName)
                    {
                        var commandResult = CommandFactory.GetCommand(commandName).Run(
                            context.ToHttpRequestData(dataProtector.Unprotect), options);

                        await commandResult.Apply(context, dataProtector, options.SignInScheme);
                        return;
                    }
                }
            }

            await next(context);
        }
    }
}
