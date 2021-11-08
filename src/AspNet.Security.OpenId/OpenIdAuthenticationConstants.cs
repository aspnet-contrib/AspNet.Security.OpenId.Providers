﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OpenId;

public static class OpenIdAuthenticationConstants
{
    public static class Aliases
    {
        public const string Ax = "ax";
    }

    public static class Attributes
    {
        public const string Email = "http://axschema.org/contact/email";
        public const string Firstname = "http://axschema.org/namePerson/first";
        public const string Lastname = "http://axschema.org/namePerson/last";
        public const string Name = "http://axschema.org/namePerson";
    }

    public static class Headers
    {
        public const string XrdsLocation = "X-XRDS-Location";
    }

    public static class Media
    {
        public const string Html = "text/html";
        public const string Json = "application/json";
        public const string Xhtml = "application/xhtml+xml";
        public const string Xml = "text/xml";
        public const string Xrds = "application/xrds+xml";

    }

    public static class Metadata
    {
        public const string Content = "content";
        public const string HttpEquiv = "http-equiv";
        public const string Meta = "meta";
        public const string XrdsLocation = "X-XRDS-Location";
    }

    public static class Modes
    {
        public const string Cancel = "cancel";
        public const string CheckAuthentication = "check_authentication";
        public const string CheckIdSetup = "checkid_setup";
        public const string Error = "error";
        public const string FetchRequest = "fetch_request";
        public const string IdRes = "id_res";
    }

    public static class Namespaces
    {
        public const string Ax = "http://openid.net/srv/ax/1.0";
        public const string OpenId = "http://specs.openid.net/auth/2.0";
    }

    public static class Parameters
    {
        public const string ClaimedId = "claimed_id";
        public const string Error = "error";
        public const string Identity = "identity";
        public const string IsValid = "is_valid";
        public const string Mode = "mode";
        public const string Namespace = "ns";
        public const string Realm = "realm";
        public const string Required = "required";
        public const string ReturnTo = "return_to";
        public const string State = "state";
    }

    public static class Prefixes
    {
        public const string Ax = "openid.ax";
        public const string Namespace = "openid.ns";
        public const string OpenId = "openid";
        public const string Type = "type";
    }

    public static class Properties
    {
        public const string ReturnTo = ".return_to";
    }

    public static class Suffixes
    {
        public const string Type = "type";
        public const string Value = "value";
    }
}
