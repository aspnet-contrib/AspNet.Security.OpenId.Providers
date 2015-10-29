/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.Extensions.Internal;

namespace AspNet.Security.OpenId {
    public class OpenIdAuthenticationOptions : RemoteAuthenticationOptions {
        public OpenIdAuthenticationOptions() {
            AuthenticationScheme = OpenIdAuthenticationDefaults.AuthenticationScheme;
            DisplayName = OpenIdAuthenticationDefaults.DisplayName;
            CallbackPath = new PathString(OpenIdAuthenticationDefaults.CallbackPath);
            Events = new OpenIdAuthenticationEvents();
        }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public Uri Authority { get; set; }

        public string Realm { get; set; }

        public string Endpoint { get; set; }

        public new IOpenIdAuthenticationEvents Events {
            get { return base.Events as IOpenIdAuthenticationEvents; }
            set { base.Events = value; }
        }

        public RandomNumberGenerator RandomNumberGenerator { get; [param: NotNull] set; } = RandomNumberGenerator.Create();

        public HttpClient Client { get; set; }

        public IDictionary<string, string> Attributes { get; } = new Dictionary<string, string> {
            ["email"] = "http://axschema.org/contact/email",
            ["name"] = "http://axschema.org/namePerson",
            ["first"] = "http://axschema.org/namePerson/first",
            ["last"] = "http://axschema.org/namePerson/last",

            ["email2"] = "http://schema.openid.net/contact/email",
            ["name2"] = "http://schema.openid.net/namePerson",
            ["first2"] = "http://schema.openid.net/namePerson/first",
            ["last2"] = "http://schema.openid.net/namePerson/last"
        };
    }
}
