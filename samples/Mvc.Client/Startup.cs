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
using Microsoft.Extensions.DependencyInjection;

namespace Mvc.Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(o => {
                    o.LoginPath = new PathString("/login");
                    o.LogoutPath = new PathString("/signout");
                })
                .AddOpenId("Orange", "Orange", options =>
                {
                    options.Authority = new Uri("https://openid.orange.fr/");
                    options.CallbackPath = "/signin-orange";
                })
                .AddOpenId("StackExchange", "StackExchange", options =>
                {
                    options.Authority = new Uri("https://openid.stackexchange.com/");
                    options.CallbackPath = "/signin-stackexchange";
                })
                .AddOpenId("Intuit", "Intuit", options =>
                {
                    options.CallbackPath = "/signin-intuit";
                    options.Configuration = new OpenIdAuthenticationConfiguration
                    {
                        AuthenticationEndpoint = "https://openid.intuit.com/OpenId/Provider"
                    };
                })
                .AddSteam();

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvc();
        }
    }
}