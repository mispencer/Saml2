﻿using Kentor.AuthServices.WebSso;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Sustainsys.Saml2.AspNetCore2
{
    static class CommandResultExtensions
    {
        public async static Task Apply(
            this CommandResult commandResult,
            HttpContext httpContext,
            IDataProtector dataProtector,
            string SignInScheme)
        {
            httpContext.Response.StatusCode = (int)commandResult.HttpStatusCode;

            if(commandResult.Location != null)
            {
                httpContext.Response.Headers["Location"] = commandResult.Location.ToString();
            }

            if(!string.IsNullOrEmpty(commandResult.SetCookieName))
            {
                var cookieData = HttpRequestData.ConvertBinaryData(
                    dataProtector.Protect(commandResult.GetSerializedRequestState()));

                httpContext.Response.Cookies.Append(
                    commandResult.SetCookieName,
                    cookieData,
                    new CookieOptions()
                    {
                        HttpOnly = true,
                        // We are expecting a different site to POST back to us,
                        // so the ASP.Net Core default of Lax is not appropriate in this case
                        SameSite = SameSiteMode.None
                    });
            }

            if(!string.IsNullOrEmpty(commandResult.ClearCookieName))
            {
                httpContext.Response.Cookies.Delete(commandResult.ClearCookieName);
            }

            if(!string.IsNullOrEmpty(commandResult.Content))
            {
                var buffer = Encoding.UTF8.GetBytes(commandResult.Content);
                httpContext.Response.ContentType = commandResult.ContentType;
                httpContext.Response.Body.Write(buffer, 0, buffer.Length);
            }

            if(commandResult.Principal != null)
            {
                var authProps = new AuthenticationProperties(commandResult.RelayData)
                {
                    RedirectUri = commandResult.Location.OriginalString
                };
                await httpContext.SignInAsync(SignInScheme, commandResult.Principal, authProps);
            }
        }
    }
}
