/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNet.Http;

namespace AspNet.Security.OpenId.Steam {
    public class SteamAuthenticationOptions : OpenIdAuthenticationOptions {
        public SteamAuthenticationOptions() {
            AuthenticationScheme = SteamAuthenticationDefaults.AuthenticationScheme;
            Caption = SteamAuthenticationDefaults.Caption;
            Authority = new Uri(SteamAuthenticationDefaults.Authority);
            CallbackPath = new PathString(SteamAuthenticationDefaults.CallbackPath);
        }

        public string AppKey { get; set; }
    }
}
