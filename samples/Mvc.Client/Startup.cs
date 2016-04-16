/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;

namespace Mvc.Client {
    public class Startup {
        public void ConfigureServices(IServiceCollection services) {
            services.AddAuthentication(options => {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app) {
            app.UseForwardedHeaders(new ForwardedHeadersOptions {
                ForwardedHeaders = ForwardedHeaders.All
            });

            app.UseStaticFiles();

            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                AuthenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                LoginPath = new PathString("/signin")
            });

            app.UseOpenIdAuthentication(new OpenIdAuthenticationOptions {
                AuthenticationScheme = "Orange",
                DisplayName = "Orange",
                Authority = new Uri("http://orange.fr/"),
                CallbackPath = new PathString("/signin-orange")
            });

            app.UseOpenIdAuthentication(new OpenIdAuthenticationOptions {
                AuthenticationScheme = "StackExchange",
                DisplayName = "StackExchange",
                Authority = new Uri("https://openid.stackexchange.com/"),
                CallbackPath = new PathString("/signin-stackexchange")
            });

            app.UseOpenIdAuthentication(new OpenIdAuthenticationOptions {
                AuthenticationScheme = "Intuit",
                DisplayName = "Intuit",
                CallbackPath = new PathString("/signin-intuit"),
                Endpoint = new Uri("https://openid.intuit.com/OpenId/Provider")
            });

            app.UseSteamAuthentication();

            app.UseMvc();
        }
    }
}