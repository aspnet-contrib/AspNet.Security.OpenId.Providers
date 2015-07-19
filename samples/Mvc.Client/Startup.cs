using System;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;

namespace Mvc.Client {
    public class Startup {
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
                options.AutomaticAuthentication = true;
                options.AuthenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.LoginPath = new PathString("/signin");
            });

            app.UseOpenIdAuthentication("Orange", options => {
                options.AuthenticationScheme = "Orange";
                options.Caption = "Orange";
                options.Authority = new Uri("http://orange.fr/");
                options.CallbackPath = new PathString("/signin-orange");
            });

            app.UseOpenIdAuthentication("StackExchange", options => {
                options.AuthenticationScheme = "StackExchange";
                options.Caption = "StackExchange";
                options.Authority = new Uri("https://openid.stackexchange.com/");
                options.CallbackPath = new PathString("/signin-stackexchange");
            });

            app.UseSteamAuthentication();

            app.UseMvc();
        }
    }
}