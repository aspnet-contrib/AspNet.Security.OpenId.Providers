/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Mvc.Client {
    public class Startup {
        public static void Main(string[] args) {
            var application = new WebApplicationBuilder()
                .UseConfiguration(WebApplicationConfiguration.GetDefault(args))
                .UseStartup<Startup>()
                .Build();

            application.Run();
        }

        public void ConfigureServices(IServiceCollection services) {
            services.AddAuthentication();
            services.AddMvc();

            services.Configure<SharedAuthenticationOptions>(options => {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });
        }

        public void Configure(IApplicationBuilder app) {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();

            app.UseStaticFiles();

            app.UseCookieAuthentication(options => {
                options.AutomaticAuthenticate = true;
                options.AutomaticChallenge = true;
                options.AuthenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.LoginPath = new PathString("/signin");
            });

            app.UseOpenIdAuthentication(options => {
                options.AuthenticationScheme = "Orange";
                options.DisplayName = "Orange";
                options.Authority = new Uri("http://orange.fr/");
                options.CallbackPath = new PathString("/signin-orange");
            });

            app.UseOpenIdAuthentication(options => {
                options.AuthenticationScheme = "StackExchange";
                options.DisplayName = "StackExchange";
                options.Authority = new Uri("https://openid.stackexchange.com/");
                options.CallbackPath = new PathString("/signin-stackexchange");
            });

            app.UseOpenIdAuthentication(options => {
                options.AuthenticationScheme = "Intuit";
                options.DisplayName = "Intuit";
                options.CallbackPath = new PathString("/signin-intuit");
                options.Endpoint = "https://openid.intuit.com/OpenId/Provider";
            });

            app.UseSteamAuthentication();

            app.UseMvc();
        }
    }
}