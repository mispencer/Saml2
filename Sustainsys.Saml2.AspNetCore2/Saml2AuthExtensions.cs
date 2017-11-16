using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Sustainsys.Saml2.AspNetCore2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extensions methods for adding Saml2 authentication
    /// </summary>
    public static class Saml2AuthExtensions
    {
        /// <summary>
        /// Register Saml2 Authentication with default scheme name.
        /// </summary>
        /// <param name="builder">Authentication Builder</param>
        /// <param name="configureOptions">Action that configures the Saml2 Options</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSaml2(
            this AuthenticationBuilder builder,
            Action<Saml2Options> configureOptions)
            => builder.AddSaml2(Saml2Defaults.Scheme, configureOptions);

        /// <summary>
        /// Register Saml2 Authentication with a custom scheme name.
        /// </summary>
        /// <param name="builder">Authentication Builder</param>
        /// <param name="scheme">Name of the authentication scheme</param>
        /// <param name="configureOptions">Action that configures Saml2 Options</param>
        /// <returns>Authentication Builder</returns>
        public static AuthenticationBuilder AddSaml2(
            this AuthenticationBuilder builder,
            string scheme,
            Action<Saml2Options> configureOptions)
        {
            if(builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<Saml2Options>, PostConfigureSaml2Options>());

            builder.Services.Configure<AuthenticationOptions>(o =>
            {
                o.AddScheme(scheme, s =>
                {
                    s.HandlerType = typeof(Saml2Handler);
                    s.DisplayName = Saml2Defaults.DisplayName;
                });
            });
            
            if (configureOptions != null)
            {
                builder.Services.Configure(scheme, configureOptions);
            }

            builder.Services.AddTransient<Saml2Handler>();

            return builder;
        }

        /// <summary>
        /// Register the Saml2 Logout middlewear. This is required because logout must happen AFTER the Authentication so we know which user to logout.
        /// </summary>
        /// <param name="app">Application Builder</param>
        /// <returns>Application Builder</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
        public static IApplicationBuilder UseSaml2Logout(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<Saml2LogoutMiddleware>();
        }
    }
}
