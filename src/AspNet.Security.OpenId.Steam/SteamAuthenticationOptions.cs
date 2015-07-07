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
