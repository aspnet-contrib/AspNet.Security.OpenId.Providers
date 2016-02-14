/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Net.Http;
using AngleSharp.Parser.Html;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;

namespace AspNet.Security.OpenId {
    public class OpenIdAuthenticationOptions : RemoteAuthenticationOptions {
        public OpenIdAuthenticationOptions() {
            AuthenticationScheme = OpenIdAuthenticationDefaults.AuthenticationScheme;
            DisplayName = OpenIdAuthenticationDefaults.DisplayName;
            CallbackPath = new PathString(OpenIdAuthenticationDefaults.CallbackPath);
            Events = new OpenIdAuthenticationEvents();
        }

        /// <summary>
        /// Gets or sets the data format used to serialize the
        /// authentication properties used for the "state" parameter.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the address used to discover the OpenID provider.
        /// </summary>
        public Uri Authority { get; set; }

        /// <summary>
        /// Gets or sets the address of the OpenID provider.
        /// </summary>
        public Uri Endpoint { get; set; }

        /// <summary>
        /// Gets or sets the realm associated with this instance.
        /// A default value is automatically inferred from the
        /// current URL when this value is left to <c>null</c>.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets or sets the default AX attributes added to the OpenID request.
        /// </summary>
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

        /// <summary>
        /// Gets or sets the events provider associated with this instance.
        /// </summary>
        public new IOpenIdAuthenticationEvents Events {
            get { return base.Events as IOpenIdAuthenticationEvents; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Gets or sets the HTTP client used to communicate with the OpenID provider.
        /// </summary>
        public HttpClient HttpClient { get; set; }

        /// <summary>
        /// Gets or sets the HTML parser used to parse discovery documents.
        /// </summary>
        public HtmlParser HtmlParser { get; set; }
    }
}
