/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenId.Steam
{
    public class SteamAuthenticationOptions : OpenIdAuthenticationOptions
    {
        public SteamAuthenticationOptions()
        {
            Authority = new Uri(SteamAuthenticationDefaults.Authority);
            CallbackPath = new PathString(SteamAuthenticationDefaults.CallbackPath);
        }

        /// <summary>
        /// Gets or sets the application key used to retrive user details from Steam's API.
        /// </summary>
        public string ApplicationKey { get; set; }

        /// <summary>
        /// Gets or sets the endpoint used to retrieve user details.
        /// </summary>
        public string UserInformationEndpoint { get; set; } = SteamAuthenticationDefaults.UserInformationEndpoint;
    }
}
