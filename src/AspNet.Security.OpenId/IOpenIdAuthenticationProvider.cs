using System.Threading.Tasks;
using AspNet.Security.OpenId.Notifications;

namespace AspNet.Security.OpenId {
    public interface IOpenIdAuthenticationProvider {
        Task Authenticated(OpenIdAuthenticatedNotification notification);
        Task ReturnEndpoint(OpenIdReturnEndpointNotification notification);
    }
}
