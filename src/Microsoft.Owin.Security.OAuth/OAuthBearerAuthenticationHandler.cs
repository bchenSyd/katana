// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;

namespace Microsoft.Owin.Security.OAuth
{
    internal class OAuthBearerAuthenticationHandler : AuthenticationHandler<OAuthBearerAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly string _challenge;

        public OAuthBearerAuthenticationHandler(ILogger logger, string challenge)
        {
            _logger = logger;
            _challenge = challenge;
        }

        /// <summary>
        /// bchen:  decrypt token ; 
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            try
            {
                // Find token in default location
                string requestToken = null;
                string authorization = Request.Headers.Get("Authorization");
                if (!string.IsNullOrEmpty(authorization))
                {
                    if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        requestToken = authorization.Substring("Bearer ".Length).Trim();
                    }
                }

                // Give application opportunity to find from a different location, adjust, or reject token
                //if you want to store token in a different location, here you go!
                var requestTokenContext = new OAuthRequestTokenContext(Context, requestToken);
                //you need to hook to OAuthBearerAuthenticationProvider.OnRequestToken event
                await Options.Provider.RequestToken(requestTokenContext); 

                // If no token found, no further work possible
                if (string.IsNullOrEmpty(requestTokenContext.Token))
                {
                    return null;
                }


                //======================================================================================================================================
                //by now we should have got the token string (still encrptyed)
                var tokenReceiveContext = new AuthenticationTokenReceiveContext(
                    Context,
                    Options.AccessTokenFormat,
                    requestTokenContext.Token);

                await Options.AccessTokenProvider.ReceiveAsync(tokenReceiveContext);  //I don't think too many ppl would bother hook up to OnRecive event in AccessTokenProvider provider
                if (tokenReceiveContext.Ticket == null)
                {
                    //most ppl won't override the decrption algorithm, default the system implemenation
                    tokenReceiveContext.DeserializeTicket(tokenReceiveContext.Token);
                }

                AuthenticationTicket ticket = tokenReceiveContext.Ticket; //fuck! you are trying to fool me!
                if (ticket == null)
                {
                    _logger.WriteWarning("invalid bearer token received. a fraudulent access token");
                    return null;
                }

                // Validate expiration time if present
                DateTimeOffset currentUtc = Options.SystemClock.UtcNow;

                //look, what we have deserialized while authorization (issue ticket) has now been fully restored
                if (ticket.Properties.ExpiresUtc.HasValue &&
                    ticket.Properties.ExpiresUtc.Value < currentUtc)
                {
                    _logger.WriteWarning("expired bearer token received"); // a valid token, but has already expired
                    return null;
                }

            
                var context = new OAuthValidateIdentityContext(Context, Options, ticket);
                
                
                //????????????????????????????????
                if (ticket != null &&
                    ticket.Identity != null &&            // when did I set ticket.Identity????????????
                    ticket.Identity.IsAuthenticated)      // when did I set IsAuthenticated????????????
                {
                    context.Validated();
                }
                //to understand why ticket.Identity != null and ticket.Identity.IsAuthenticated, you need to check how we create the ticket
                //sample code:
                //
                     //if (ctx.UserName == userName && ctx.Password == password)
                     //{
                     //    var claims = new List<Claim>
                     //     {
                     //         new Claim(ClaimsIdentity.DefaultNameClaimType, ctx.UserName)
                     //     };
                     //    string scope = string.Join(" ", ctx.Scope);
                     //    if (!String.IsNullOrEmpty(scope))
                     //    {
                     //        claims.Add(new Claim("scope", scope));
                     //    }
                     //    if (!String.IsNullOrEmpty(ctx.ClientId))
                     //    {
                     //        claims.Add(new Claim("client", ctx.ClientId));
                     //    }
                     //    ctx.Validated( /****  public class ClaimsIdentity : IIdentity   ************ / new  ClaimsIdentity(claims, "Bearer"));
                     //}
// for detailed information on how ticket is created see
//D:\__work\katana\src\Microsoft.Owin.Security.OAuth\Provider\BaseValidatingTicketContext.cs
                        //ctx.Validated will create a ticket , identiy is a parameter pass in, which is new  ClaimsIdentity(claims, "Bearer")
                        // public bool Validated(ClaimsIdentity identity)
                        //{
                        //    AuthenticationProperties properties = Ticket != null ? Ticket.Properties : new AuthenticationProperties();
                        //    return Validated(new AuthenticationTicket(identity, properties));
                        //}

                /* public class ClaimsIdentity:Identity
                 * {
                 *   //we create our ClaimsIdentity by calling new  ClaimsIdentity(claims, "Bearer")
                 *   pubic  ClaimsIdentity(IEnumerable<Claim> claims, string authenticationType)
                     {
                              m_authenticationType = authenticationType;  //IsAuthenticated is always true!!
                     }
               
                 * public virtual bool IsAuthenticated
                      {
                          get { return !string.IsNullOrEmpty(m_authenticationType); }
                      }
                 * 
                 * 
  */

                //??????????????????????????????????



                //bchen [important] : can be used to force log out  ==> after user clicks logout button in cardholder/card holder  site, 
                //                    add that access token to invlidated token list (session), and implement our own ValidateIdentity function
                //if you want some further validation, e.g. verify that access_token hasn't been invalided since it was issued, here is your last chance!!
                if (Options.Provider != null)
                {
                    //you can hook up to the OAuthBearerAuthenticationProvider::OnValidateIdentity event
                    await Options.Provider.ValidateIdentity(context);  //owin will send you the ticket, do whatever you want to and tell me whether
                    //it is validated or not IN YOUR CONTEXT (the context is just a object to hold result, call context.Validated() to set the result to true
                    //by default the result is set to false;
                }

                //context.validated() never get called
                if (!context.IsValidated)
                {
                    return null;
                }

                // resulting identity values go back to caller
                return context.Ticket;
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return null;
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                OAuthChallengeContext challengeContext = new OAuthChallengeContext(Context, _challenge);
                Options.Provider.ApplyChallenge(challengeContext);
            }

            return Task.FromResult<object>(null);
        }
    }
}
