// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using System.Threading;

namespace Microsoft.Owin.Security.OAuth
{
    /// <summary>
    /// Base class used for certain event contexts
    /// </summary>
    public abstract class BaseValidatingTicketContext<TOptions> : BaseValidatingContext<TOptions>
    {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingTicketContext(
            IOwinContext context,
            TOptions options,
            AuthenticationTicket ticket)
            : base(context, options)
        {
            Ticket = ticket;
        }

        /// <summary>
        /// Contains the identity and properties for the application to authenticate. If the Validated method
        /// is invoked with an AuthenticationTicket or ClaimsIdentity argument, that new value is assigned to 
        /// this property in addition to changing IsValidated to true.
        /// </summary>
        public AuthenticationTicket Ticket { get; private set; }

       
        

//*****************************************      How is ticket created?        ********************************************************
        /* OAuthGrantResourceOwnerCredentialsContext OAuthGrantResourceOwnerCredentialsContext OAuthGrantResourceOwnerCredentialsContext 
         * OAuthGrantResourceOwnerCredentialsContext OAuthGrantResourceOwnerCredentialsContext OAuthGrantResourceOwnerCredentialsContext
         * 
         * this is the default MVC Web API 2 implementation
                 public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
                 {
                         ApplicationUser user = await userManager.FindAsync(context.UserName, context.Password);
                         ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(userManager,
                                                              OAuthDefaults.AuthenticationType);
                         AuthenticationProperties properties = CreateProperties(user.UserName);
                         //create ticket explicitly
                         AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, properties);
                         context.Validated(ticket);
                }    
         * cardholder/card holder  site, card holder site
         *  var tempIdentity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
            tempIdentity.AddClaim(new Claim("EntityId", entityId.ToString(CultureInfo.InvariantCulture)));
            var properties = CreateProperties("Valued Card Holder");
            var ticket = new AuthenticationTicket(tempIdentity, properties);
           context.Validated(ticket);
         * 
         */

        /// <summary>
       /// bochen [critical]
       /// public class OAuthGrantResourceOwnerCredentialsContext : BaseValidatingTicketContext<OAuthAuthorizationServerOptions>
       /// so the  context.Validated(ticket) method call in your code is calling me 
        public bool Validated(AuthenticationTicket ticket)  //explictily passin a ticket
        {
            Ticket = ticket;
            return Validated();
        }
        //this is used by the integration test, 
        /*
                     var claims = new List<Claim>
                    {
                        new Claim(ClaimsIdentity.DefaultNameClaimType, ctx.UserName)
                    };
                 
                    ctx.Validated(new ClaimsIdentity(claims, "Bearer"));         
         */
        //ClaimsIdentity: IIdentity is a .net class defined in mscorlib  (.net CLR , GC and JIT)
        //  [ComVisible(true)]
        //  public interface IIdentity
        //  {
        //      string AuthenticationType { get; }
        //      bool IsAuthenticated { get; }
        //      string Name { get; }
        //  }    

// internal ClaimsIdentity(IIdentity identity, IEnumerable<Claim> claims, string authenticationType, string nameType, string roleType, bool checkAuthType)
        //IsAuthenticated ==> if AuthenticationType is set (which in our case is Bearer", it returns true)
        //that's why you can always assume that ticket.idnetity != null and ticket.identity.IsAuthenticated = true;
        public bool Validated(ClaimsIdentity identity)
        {
            AuthenticationProperties properties = Ticket != null ? Ticket.Properties : new AuthenticationProperties();
            return Validated(new AuthenticationTicket(identity, properties));
        }
    }
//***************************************************************************************************************************************
}
