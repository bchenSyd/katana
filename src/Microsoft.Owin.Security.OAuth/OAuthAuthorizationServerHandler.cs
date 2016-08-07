// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth.Messages;
using Newtonsoft.Json;

namespace Microsoft.Owin.Security.OAuth
{
    internal class OAuthAuthorizationServerHandler : AuthenticationHandler<OAuthAuthorizationServerOptions>
    {
        private readonly ILogger _logger;

        private AuthorizeEndpointRequest _authorizeEndpointRequest;
        private OAuthValidateClientRedirectUriContext _clientContext;

        public OAuthAuthorizationServerHandler(ILogger logger)
        {
            _logger = logger;
        }

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            return Task.FromResult<AuthenticationTicket>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            var matchRequestContext = new OAuthMatchEndpointContext(Context, Options);
            if (Options.AuthorizeEndpointPath.HasValue && Options.AuthorizeEndpointPath == Request.Path)
            {
                matchRequestContext.MatchesAuthorizeEndpoint();
            }
            else if (Options.TokenEndpointPath.HasValue && Options.TokenEndpointPath == Request.Path)
            {
                matchRequestContext.MatchesTokenEndpoint();
            }
            await Options.Provider.MatchEndpoint(matchRequestContext);
            if (matchRequestContext.IsRequestCompleted)
            {
                return true;
            }

            if (matchRequestContext.IsAuthorizeEndpoint || matchRequestContext.IsTokenEndpoint)
            {
                if (!Options.AllowInsecureHttp &&
                    String.Equals(Request.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.WriteWarning("Authorization server ignoring http request because AllowInsecureHttp is false.");
                    return false;
                }
                if (matchRequestContext.IsAuthorizeEndpoint)
                {
                    return await InvokeAuthorizeEndpointAsync();
                }
                if (matchRequestContext.IsTokenEndpoint)
                {
                    await InvokeTokenEndpointAsync();
                    return true;
                }
            }
            return false;
        }

        private async Task<bool> InvokeAuthorizeEndpointAsync()
        {
            var authorizeRequest = new AuthorizeEndpointRequest(Request.Query);

            var clientContext = new OAuthValidateClientRedirectUriContext(
                Context,
                Options,
                authorizeRequest.ClientId,
                authorizeRequest.RedirectUri);

            if (!String.IsNullOrEmpty(authorizeRequest.RedirectUri))
            {
                bool acceptableUri = true;
                Uri validatingUri;
                if (!Uri.TryCreate(authorizeRequest.RedirectUri, UriKind.Absolute, out validatingUri))
                {
                    // The redirection endpoint URI MUST be an absolute URI
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2
                    acceptableUri = false;
                }
                else if (!String.IsNullOrEmpty(validatingUri.Fragment))
                {
                    // The endpoint URI MUST NOT include a fragment component.
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2
                    acceptableUri = false;
                }
                else if (!Options.AllowInsecureHttp &&
                    String.Equals(validatingUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
                {
                    // The redirection endpoint SHOULD require the use of TLS
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2.1
                    acceptableUri = false;
                }
                if (!acceptableUri)
                {
                    clientContext.SetError(Constants.Errors.InvalidRequest);
                    return await SendErrorRedirectAsync(clientContext, clientContext);
                }
            }

            await Options.Provider.ValidateClientRedirectUri(clientContext);

            if (!clientContext.IsValidated)
            {
                _logger.WriteVerbose("Unable to validate client information");
                return await SendErrorRedirectAsync(clientContext, clientContext);
            }

            var validatingContext = new OAuthValidateAuthorizeRequestContext(
                Context,
                Options,
                authorizeRequest,
                clientContext);

            if (string.IsNullOrEmpty(authorizeRequest.ResponseType))
            {
                _logger.WriteVerbose("Authorize endpoint request missing required response_type parameter");
                validatingContext.SetError(Constants.Errors.InvalidRequest);
            }
            else if (!authorizeRequest.IsAuthorizationCodeGrantType &&
                !authorizeRequest.IsImplicitGrantType)
            {
                _logger.WriteVerbose("Authorize endpoint request contains unsupported response_type parameter");
                validatingContext.SetError(Constants.Errors.UnsupportedResponseType);
            }
            else
            {
                await Options.Provider.ValidateAuthorizeRequest(validatingContext);
            }

            if (!validatingContext.IsValidated)
            {
                // an invalid request is not processed further
                return await SendErrorRedirectAsync(clientContext, validatingContext);
            }

            _clientContext = clientContext;
            _authorizeEndpointRequest = authorizeRequest;

            var authorizeEndpointContext = new OAuthAuthorizeEndpointContext(Context, Options, authorizeRequest);

            await Options.Provider.AuthorizeEndpoint(authorizeEndpointContext);

            return authorizeEndpointContext.IsRequestCompleted;
        }

        protected override async Task ApplyResponseGrantAsync()
        {
            // only successful results of an authorize request are altered
            if (_clientContext == null ||
                _authorizeEndpointRequest == null ||
                Response.StatusCode != 200)
            {
                return;
            }

            // only apply with signin of matching authentication type
            AuthenticationResponseGrant signin = Helper.LookupSignIn(Options.AuthenticationType);
            if (signin == null)
            {
                return;
            }

            var returnParameter = new Dictionary<string, string>();

            if (_authorizeEndpointRequest.IsAuthorizationCodeGrantType)
            {
                DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
                signin.Properties.IssuedUtc = currentUtc;
                signin.Properties.ExpiresUtc = currentUtc.Add(Options.AuthorizationCodeExpireTimeSpan);

                // associate client_id with all subsequent tickets
                signin.Properties.Dictionary[Constants.Extra.ClientId] = _authorizeEndpointRequest.ClientId;
                if (!string.IsNullOrEmpty(_authorizeEndpointRequest.RedirectUri))
                {
                    // keep original request parameter for later comparison
                    signin.Properties.Dictionary[Constants.Extra.RedirectUri] = _authorizeEndpointRequest.RedirectUri;
                }

                var context = new AuthenticationTokenCreateContext(
                    Context,
                    Options.AuthorizationCodeFormat,
                    new AuthenticationTicket(signin.Identity, signin.Properties));

                await Options.AuthorizationCodeProvider.CreateAsync(context);

                string code = context.Token;
                if (string.IsNullOrEmpty(code))
                {
                    _logger.WriteError("response_type code requires an Options.AuthorizationCodeProvider implementing a single-use token.");
                    var errorContext = new OAuthValidateAuthorizeRequestContext(Context, Options, _authorizeEndpointRequest, _clientContext);
                    errorContext.SetError(Constants.Errors.UnsupportedResponseType);
                    await SendErrorRedirectAsync(_clientContext, errorContext);
                    return;
                }

                var authResponseContext = new OAuthAuthorizationEndpointResponseContext(
                                Context,
                                Options,
                                new AuthenticationTicket(signin.Identity, signin.Properties),
                                _authorizeEndpointRequest,
                                null,
                                code);

                await Options.Provider.AuthorizationEndpointResponse(authResponseContext);

                foreach (var parameter in authResponseContext.AdditionalResponseParameters)
                {
                    returnParameter[parameter.Key] = parameter.Value.ToString();
                }

                returnParameter[Constants.Parameters.Code] = code;

                if (!String.IsNullOrEmpty(_authorizeEndpointRequest.State))
                {
                    returnParameter[Constants.Parameters.State] = _authorizeEndpointRequest.State;
                }

                string location = string.Empty;
                if (_authorizeEndpointRequest.IsFormPostResponseMode)
                {
                    location = Options.FormPostEndpoint.ToString();
                    returnParameter[Constants.Parameters.RedirectUri] = _clientContext.RedirectUri;
                }
                else
                {
                    location = _clientContext.RedirectUri;
                }

                foreach (var key in returnParameter.Keys)
                {
                    location = WebUtilities.AddQueryString(location, key, returnParameter[key]);
                }

                Response.Redirect(location);
            }
            else if (_authorizeEndpointRequest.IsImplicitGrantType)
            {
                string location = _clientContext.RedirectUri;

                DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
                signin.Properties.IssuedUtc = currentUtc;
                signin.Properties.ExpiresUtc = currentUtc.Add(Options.AccessTokenExpireTimeSpan);

                // associate client_id with access token
                signin.Properties.Dictionary[Constants.Extra.ClientId] = _authorizeEndpointRequest.ClientId;

                var accessTokenContext = new AuthenticationTokenCreateContext(
                    Context,
                    Options.AccessTokenFormat,
                    new AuthenticationTicket(signin.Identity, signin.Properties));

                await Options.AccessTokenProvider.CreateAsync(accessTokenContext);

                string accessToken = accessTokenContext.Token;
                if (string.IsNullOrEmpty(accessToken))
                {
                    accessToken = accessTokenContext.SerializeTicket();
                }

                DateTimeOffset? accessTokenExpiresUtc = accessTokenContext.Ticket.Properties.ExpiresUtc;

                var appender = new Appender(location, '#');
                appender
                    .Append(Constants.Parameters.AccessToken, accessToken)
                    .Append(Constants.Parameters.TokenType, Constants.TokenTypes.Bearer);
                if (accessTokenExpiresUtc.HasValue)
                {
                    TimeSpan? expiresTimeSpan = accessTokenExpiresUtc - currentUtc;
                    var expiresIn = (long)(expiresTimeSpan.Value.TotalSeconds + .5);
                    appender.Append(Constants.Parameters.ExpiresIn, expiresIn.ToString(CultureInfo.InvariantCulture));
                }
                if (!String.IsNullOrEmpty(_authorizeEndpointRequest.State))
                {
                    appender.Append(Constants.Parameters.State, _authorizeEndpointRequest.State);
                }

                var authResponseContext = new OAuthAuthorizationEndpointResponseContext(
                                Context,
                                Options,
                                new AuthenticationTicket(signin.Identity, signin.Properties),
                                _authorizeEndpointRequest,
                                accessToken,
                                null);

                await Options.Provider.AuthorizationEndpointResponse(authResponseContext);

                foreach (var parameter in authResponseContext.AdditionalResponseParameters)
                {
                    appender.Append(parameter.Key, parameter.Value.ToString());
                }

                Response.Redirect(appender.ToString());
            }
        }

        /// <summary>
        /// bchen: validate user and create token 
        /// </summary>
        /// <returns></returns>
        private async Task InvokeTokenEndpointAsync()
        {
            DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
            // remove milliseconds in case they don't round-trip
            currentUtc = currentUtc.Subtract(TimeSpan.FromMilliseconds(currentUtc.Millisecond));

            IFormCollection form = await Request.ReadFormAsync();

            var clientContext = new OAuthValidateClientAuthenticationContext(
                Context,
                Options,
                form);

            //step 1: application level validation i.e. the application(client) that issued the request must be a registered client
            //        this normally involves look up client database and check client_id/client_secret are registered and match eachother
            //        when only doing grant_type=password, ignore this part (always return validated = true)
            // you code is called!!
            /*MVC Web API default Implementation
             public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
                {
                    // Resource owner password credentials does not provide a client ID.
                    if (context.ClientId == null)
                    {
                        context.Validated();
                    }

                    return Task.FromResult<object>(null);
                }
             */
            await Options.Provider.ValidateClientAuthentication(clientContext);

            if (!clientContext.IsValidated)
            {
                _logger.WriteError("clientID is not valid.");
                if (!clientContext.HasError)
                {
                    clientContext.SetError(Constants.Errors.InvalidClient);
                }
                await SendErrorAsJsonAsync(clientContext);
                return;
            }

            var tokenEndpointRequest = new TokenEndpointRequest(form);

            //********** how do I understand validatingContext object?  ****************
            //
            var validatingContext = new OAuthValidateTokenRequestContext(Context, Options, tokenEndpointRequest, clientContext);

            //step2: user level validation 
            //// you code is called!!
            AuthenticationTicket ticket = null;
            if (tokenEndpointRequest.IsAuthorizationCodeGrantType)
            {
                // Authorization Code Grant http://tools.ietf.org/html/rfc6749#section-4.1
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.1.3
                ticket = await InvokeTokenEndpointAuthorizationCodeGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsResourceOwnerPasswordCredentialsGrantType)
            {
                // Resource Owner Password Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.3
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.3.2
                ticket = await InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsClientCredentialsGrantType)
            {
                // Client Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.4
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.4.2
                ticket = await InvokeTokenEndpointClientCredentialsGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsRefreshTokenGrantType)
            {
                // Refreshing an Access Token
                // http://tools.ietf.org/html/rfc6749#section-6
                ticket = await InvokeTokenEndpointRefreshTokenGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsCustomExtensionGrantType)
            {
                // Defining New Authorization Grant Types
                // http://tools.ietf.org/html/rfc6749#section-8.3
                ticket = await InvokeTokenEndpointCustomGrantAsync(validatingContext, currentUtc);
            }
            else
            {
                // Error Response http://tools.ietf.org/html/rfc6749#section-5.2
                // The authorization grant type is not supported by the
                // authorization server.
                _logger.WriteError("grant type is not recognized");
                validatingContext.SetError(Constants.Errors.UnsupportedGrantType);
            }

            if (ticket == null)
            {
                await SendErrorAsJsonAsync(validatingContext);
                return;
            }

            //now you code has returned me a ticket, which is a combination of Claims and Properties;
            //a copy of properties will be sent to client in clear text (claims won't);
            //you normally add claimIdentities in the ticket you returned;
            //peroperties would normally be empty; however, the oauth will auto append .issue and .expire to the ticket

            ticket.Properties.IssuedUtc = currentUtc; //auto append .issue properties
            ticket.Properties.ExpiresUtc = currentUtc.Add(Options.AccessTokenExpireTimeSpan); //auto append .expire to the ticket properties

            var tokenEndpointContext = new OAuthTokenEndpointContext(
                Context,
                Options,
                ticket,
                tokenEndpointRequest);
            //last change to modify the token before it gets finally serialized to client
            await Options.Provider.TokenEndpoint(tokenEndpointContext);

            if (tokenEndpointContext.TokenIssued)
            {
                ticket = new AuthenticationTicket(
                    tokenEndpointContext.Identity,
                    tokenEndpointContext.Properties);
            }
            else
            {
                _logger.WriteError("Token was not issued to tokenEndpointContext");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                await SendErrorAsJsonAsync(validatingContext);
                return;
            }

            //************************ ACCESS TOKEN GET CREATED HERE  **********************************************************
            var accessTokenContext = new AuthenticationTokenCreateContext(
                Context,
                Options.AccessTokenFormat,
                ticket);

            await Options.AccessTokenProvider.CreateAsync(accessTokenContext);

            string accessToken = accessTokenContext.Token;
            if (string.IsNullOrEmpty(accessToken))
            {
                //bchen, bochen, if you can under this line, you know how oauth is implemented
                //the default token provider only provide events for server provider to hook up, 
                //in most cases, server provider won't provide their own implementation of encrypting access token,
                //default to the system implementation which is machine_key + base64 encoding
                accessToken = accessTokenContext.SerializeTicket();
            }
            DateTimeOffset? accessTokenExpiresUtc = ticket.Properties.ExpiresUtc;
            //*******************************************************************************************************************

            //encrypt the same ticket, but using different token provider (refresh token provider, which must be implemented by developer)
            //the system doesn't provide a default referesh token provider, below is an example used by card holder site (cardholder/card holder  site)
            /*
             
             * public class OAuthRefreshTokenProvider : AuthenticationTokenProvider
                {
                    public override void Create(AuthenticationTokenCreateContext context)
                    {
                        var issueUtc = context.Ticket.Properties.IssuedUtc;
                        if (issueUtc.HasValue)
                        {
                            context.Ticket.Properties.ExpiresUtc = issueUtc.Value.Add(Startup.RefreshTokenExpiry);
                            context.SetToken(context.SerializeTicket());
                        }

                    }

                    public override void Receive(AuthenticationTokenReceiveContext context)
                    {
                        context.DeserializeTicket(context.Token);
                    }
                }
             
             */

            var refreshTokenCreateContext = new AuthenticationTokenCreateContext(
                Context,
                Options.RefreshTokenFormat,
                accessTokenContext.Ticket);
            await Options.RefreshTokenProvider.CreateAsync(refreshTokenCreateContext);
            string refreshToken = refreshTokenCreateContext.Token;

            var tokenEndpointResponseContext = new OAuthTokenEndpointResponseContext(
                Context,
                Options,
                ticket,
                tokenEndpointRequest,
                accessToken,
                tokenEndpointContext.AdditionalResponseParameters);

            await Options.Provider.TokenEndpointResponse(tokenEndpointResponseContext);

            //************************************** TOKEN GET SERIALIZED HERE ************************************************************************
            var memory = new MemoryStream();
            byte[] body;
            using (var writer = new JsonTextWriter(new StreamWriter(memory)))
            {
                writer.WriteStartObject();
                writer.WritePropertyName(Constants.Parameters.AccessToken);
                writer.WriteValue(accessToken);
                writer.WritePropertyName(Constants.Parameters.TokenType);
                writer.WriteValue(Constants.TokenTypes.Bearer);
                if (accessTokenExpiresUtc.HasValue)
                {
                    TimeSpan? expiresTimeSpan = accessTokenExpiresUtc - currentUtc;
                    var expiresIn = (long)expiresTimeSpan.Value.TotalSeconds;
                    if (expiresIn > 0)
                    {
                        writer.WritePropertyName(Constants.Parameters.ExpiresIn);
                        writer.WriteValue(expiresIn);
                    }
                }
                if (!String.IsNullOrEmpty(refreshToken))
                {
                    writer.WritePropertyName(Constants.Parameters.RefreshToken);
                    writer.WriteValue(refreshToken);
                }
                foreach (var additionalResponseParameter in tokenEndpointResponseContext.AdditionalResponseParameters)
                {
                    writer.WritePropertyName(additionalResponseParameter.Key);
                    writer.WriteValue(additionalResponseParameter.Value);
                }
                writer.WriteEndObject();
                writer.Flush();
                body = memory.ToArray(); //--> an example of body is as below (note the ticket properties have a clear text copy in the returned json file
                /*     
                 {  
                    "access_token":"gJZNQA99G0WfsfsYmQV3qIEwRKxBbqoWjW2NsWjwYGkc-9MKEPrDxpAYlQ7_QZQA8aOH-lWQW4PtglDD78z5fL2QOYKM72YhsKT7h5FlGK_Z-ZixhPH3qtEK6SQIdAtARfx587Pau4khsiD8RdOPXFJIMVcaTG2SmzU8sn4It76cyB8x330Hx4ShYi_yxMkl_atyBqEEOJwCLqxXv7vySSwO96QuBpeFzHJB3IDyIqE0Mk7tbPrQkiA6kqX4PGNtDMewejS5R7Oe87jhZedItsAdjekPP-v2PDpG0aiWVeliAh760Usay5j02ZpPldcWSqAsBB38JsPxI1Gnzf5zY-G3_H3HPNNqP9Xkg9B58mH0GWBICjS18-02ReJ_qcTheB_kgH57gfz2Hg97bVMSVgZZFwIjkGztp4f7hhZqqbDTpgB8Aym9KC1zATI7cqp8y7AusnxA5rbX4SY8DFq4Nk_w910Z1LUwDRKEHsgT5euo5pIq5IJu6vdLtYg58R0JDSVUpDtDH3DQjsBQ_c8KTwzWlvhRrLWHTlkj03EWlzvrc6JAI7ep6nKVWQxaBwUwM4FoG5sXI1j0dXKxKqtL90PDcbbmHCwo5jDPCsnvE",
                    "token_type":"bearer",
                    "expires_in":59,
                    "refresh_token":"o-Flfz8v7YixwqprJu0G9Wg_1vQfsfsfsIHDQDjawoHKSmJ9wWDsi0HFQxrteYIeIa5auMyNcoB1aZvMPAsPDj6t-C5OdMuEj2PAGBVx6J9Y1D1PdWQ0ALDPRPtUbSsX7YIxS87VuYU3vp3gtmptG5CrtE0eOOXTXGxAdEynuAUzjYR_YeFd4sxIxlHxXtagzPq0DE1FE73OrHWxR_FCAE62d7hUDdHxLkP6mjLajSPBt1V7PYxaP2VO-YvnzS_4e_F4r7wg4uDh6wV28loYZ5Mhu7ho3ZI_TnFbfD2y8DI3XfRBgjQZWQ0i5PtPJ6nyaR_YQFvVqnZUFctilplA7YngxuU1EboSJdfDYhcg53C2HDbu4E1X2E9FA0mwVyk1tM4DV6urHDZz32dCpQuuon4Y6zmKP0MZ_2mwwK4_E2B2Pyh7njVF14JmNdxf2Bp9KMuA0g38uFTC-9N7rPhQ4mfMZ1rkLuNa_r6_SP7fzdnDoFCJGQ8yuXICoBu8h5c9Kg2EtIAU2CfNjhKQYRBvM4eATKS_wpLEVLF1UlameWzlm99NNCiIFb9v8oVorvENWaeDGhTBDpvSWTVHgpJKvWUMwkDJX08K3EKs",
                    "userName":"Valued Card Holder",
                    "IsSessionExpiryWarningEnabled":"true",
                    "SessionExpiryWarningMilliseconds":"60000",
                    "SessionExpiryTotalMilliseconds":"600000",
                    ".issued":"Sun, 07 Aug 2016 05:11:20 GMT",
                    ".expires":"Sun, 07 Aug 2016 05:12:20 GMT"
                  }
                 */
            }
            Response.ContentType = "application/json;charset=UTF-8";
            Response.Headers.Set("Cache-Control", "no-cache");
            Response.Headers.Set("Pragma", "no-cache");
            Response.Headers.Set("Expires", "-1");
            Response.ContentLength = memory.ToArray().Length;
            await Response.WriteAsync(body, Request.CallCancelled);
            //*********************************************************************************************************************************
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointAuthorizationCodeGrantAsync(
            OAuthValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            var authorizationCodeContext = new AuthenticationTokenReceiveContext(
                Context,
                Options.AuthorizationCodeFormat,
                tokenEndpointRequest.AuthorizationCodeGrant.Code);

            await Options.AuthorizationCodeProvider.ReceiveAsync(authorizationCodeContext);

            AuthenticationTicket ticket = authorizationCodeContext.Ticket;

            if (ticket == null)
            {
                _logger.WriteError("invalid authorization code");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                ticket.Properties.ExpiresUtc < currentUtc)
            {
                _logger.WriteError("expired authorization code");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            string clientId;
            if (!ticket.Properties.Dictionary.TryGetValue(Constants.Extra.ClientId, out clientId) ||
                !String.Equals(clientId, validatingContext.ClientContext.ClientId, StringComparison.Ordinal))
            {
                _logger.WriteError("authorization code does not contain matching client_id");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            string redirectUri;
            if (ticket.Properties.Dictionary.TryGetValue(Constants.Extra.RedirectUri, out redirectUri))
            {
                ticket.Properties.Dictionary.Remove(Constants.Extra.RedirectUri);
                if (!String.Equals(redirectUri, tokenEndpointRequest.AuthorizationCodeGrant.RedirectUri, StringComparison.Ordinal))
                {
                    _logger.WriteError("authorization code does not contain matching redirect_uri");
                    validatingContext.SetError(Constants.Errors.InvalidGrant);
                    return null;
                }
            }

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OAuthGrantAuthorizationCodeContext(
                Context, Options, ticket);

            if (validatingContext.IsValidated)
            {
                await Options.Provider.GrantAuthorizationCode(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(
            OAuthValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OAuthGrantResourceOwnerCredentialsContext(
                Context,
                Options,
                validatingContext.ClientContext.ClientId,
                tokenEndpointRequest.ResourceOwnerPasswordCredentialsGrant.UserName,
                tokenEndpointRequest.ResourceOwnerPasswordCredentialsGrant.Password,
                tokenEndpointRequest.ResourceOwnerPasswordCredentialsGrant.Scope);

            if (validatingContext.IsValidated)
            {
                //bchen: here is how GrantResourceOwnerCredentials is called
                //note that the context we pass in to your code is grantcontext, which hold the validation result,
                //you can call context.validate() to set to be true (validated)
                //the first thing ReturnOutcome will do is to check whether grantContext has been set to validated
                await Options.Provider.GrantResourceOwnerCredentials(grantContext);
            }

            return ReturnOutcome(   //the first thing this method does is check grantContext.IsValid
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointClientCredentialsGrantAsync(
            OAuthValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            await Options.Provider.ValidateTokenRequest(validatingContext);
            if (!validatingContext.IsValidated)
            {
                return null;
            }

            var grantContext = new OAuthGrantClientCredentialsContext(
                Context,
                Options,
                validatingContext.ClientContext.ClientId,
                tokenEndpointRequest.ClientCredentialsGrant.Scope);

            await Options.Provider.GrantClientCredentials(grantContext);

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.UnauthorizedClient);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointRefreshTokenGrantAsync(
            OAuthValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            var refreshTokenContext = new AuthenticationTokenReceiveContext(
                Context,
                Options.RefreshTokenFormat,
                tokenEndpointRequest.RefreshTokenGrant.RefreshToken);

            await Options.RefreshTokenProvider.ReceiveAsync(refreshTokenContext);

            AuthenticationTicket ticket = refreshTokenContext.Ticket;

            if (ticket == null)
            {
                _logger.WriteError("invalid refresh token");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                ticket.Properties.ExpiresUtc < currentUtc)
            {
                _logger.WriteError("expired refresh token");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OAuthGrantRefreshTokenContext(Context, Options, ticket, validatingContext.ClientContext.ClientId);

            if (validatingContext.IsValidated)
            {
                await Options.Provider.GrantRefreshToken(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointCustomGrantAsync(
            OAuthValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc)
        {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OAuthGrantCustomExtensionContext(
                Context,
                Options,
                validatingContext.ClientContext.ClientId,
                tokenEndpointRequest.GrantType,
                tokenEndpointRequest.CustomExtensionGrant.Parameters);

            if (validatingContext.IsValidated)
            {
                await Options.Provider.GrantCustomExtension(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.UnsupportedGrantType);
        }

        private static AuthenticationTicket ReturnOutcome(
            OAuthValidateTokenRequestContext validatingContext,
            BaseValidatingContext<OAuthAuthorizationServerOptions> grantContext,
            AuthenticationTicket ticket,
            string defaultError)
        {
            if (!validatingContext.IsValidated)
            {
                return null;
            }

            if (!grantContext.IsValidated)
            {
                if (grantContext.HasError)
                {
                    validatingContext.SetError(
                        grantContext.Error,
                        grantContext.ErrorDescription,
                        grantContext.ErrorUri);
                }
                else
                {
                    validatingContext.SetError(defaultError);
                }
                return null;
            }

            if (ticket == null)
            {
                validatingContext.SetError(defaultError);
                return null;
            }

            return ticket;
        }

        [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "The MemoryStream is Disposed by the StreamWriter")]
        private Task SendErrorAsJsonAsync(
            BaseValidatingContext<OAuthAuthorizationServerOptions> validatingContext)
        {
            string error = validatingContext.HasError ? validatingContext.Error : Constants.Errors.InvalidRequest;
            string errorDescription = validatingContext.HasError ? validatingContext.ErrorDescription : null;
            string errorUri = validatingContext.HasError ? validatingContext.ErrorUri : null;

            var memory = new MemoryStream();
            byte[] body;
            using (var writer = new JsonTextWriter(new StreamWriter(memory)))
            {
                writer.WriteStartObject();
                writer.WritePropertyName(Constants.Parameters.Error);
                writer.WriteValue(error);
                if (!string.IsNullOrEmpty(errorDescription))
                {
                    writer.WritePropertyName(Constants.Parameters.ErrorDescription);
                    writer.WriteValue(errorDescription);
                }
                if (!string.IsNullOrEmpty(errorUri))
                {
                    writer.WritePropertyName(Constants.Parameters.ErrorUri);
                    writer.WriteValue(errorUri);
                }
                writer.WriteEndObject();
                writer.Flush();
                body = memory.ToArray();
            }
            Response.StatusCode = 400;
            Response.ContentType = "application/json;charset=UTF-8";
            Response.Headers.Set("Cache-Control", "no-cache");
            Response.Headers.Set("Pragma", "no-cache");
            Response.Headers.Set("Expires", "-1");
            Response.Headers.Set("Content-Length", body.Length.ToString(CultureInfo.InvariantCulture));
            return Response.WriteAsync(body, Request.CallCancelled);
        }

        private Task<bool> SendErrorRedirectAsync(
            OAuthValidateClientRedirectUriContext clientContext,
            BaseValidatingContext<OAuthAuthorizationServerOptions> validatingContext)
        {
            if (clientContext == null)
            {
                throw new ArgumentNullException("clientContext");
            }

            string error = validatingContext.HasError ? validatingContext.Error : Constants.Errors.InvalidRequest;
            string errorDescription = validatingContext.HasError ? validatingContext.ErrorDescription : null;
            string errorUri = validatingContext.HasError ? validatingContext.ErrorUri : null;

            if (!clientContext.IsValidated)
            {
                // write error in response body if client_id or redirect_uri have not been validated
                return SendErrorPageAsync(error, errorDescription, errorUri);
            }

            // redirect with error if client_id and redirect_uri have been validated
            string location = WebUtilities.AddQueryString(clientContext.RedirectUri, Constants.Parameters.Error, error);
            if (!string.IsNullOrEmpty(errorDescription))
            {
                location = WebUtilities.AddQueryString(location, Constants.Parameters.ErrorDescription, errorDescription);
            }
            if (!string.IsNullOrEmpty(errorUri))
            {
                location = WebUtilities.AddQueryString(location, Constants.Parameters.ErrorUri, errorUri);
            }
            Response.Redirect(location);
            // request is handled, does not pass on to application
            return Task.FromResult(true);
        }

        private async Task<bool> SendErrorPageAsync(string error, string errorDescription, string errorUri)
        {
            Response.StatusCode = 400;
            Response.Headers.Set("Cache-Control", "no-cache");
            Response.Headers.Set("Pragma", "no-cache");
            Response.Headers.Set("Expires", "-1");

            if (Options.ApplicationCanDisplayErrors)
            {
                Context.Set("oauth.Error", error);
                Context.Set("oauth.ErrorDescription", errorDescription);
                Context.Set("oauth.ErrorUri", errorUri);
                // request is not handled - pass through to application for rendering
                return false;
            }

            var memory = new MemoryStream();
            byte[] body;
            using (var writer = new StreamWriter(memory))
            {
                writer.WriteLine("error: {0}", error);
                if (!string.IsNullOrEmpty(errorDescription))
                {
                    writer.WriteLine("error_description: {0}", errorDescription);
                }
                if (!string.IsNullOrEmpty(errorUri))
                {
                    writer.WriteLine("error_uri: {0}", errorUri);
                }
                writer.Flush();
                body = memory.ToArray();
            }

            Response.ContentType = "text/plain;charset=UTF-8";
            Response.Headers.Set("Content-Length", body.Length.ToString(CultureInfo.InvariantCulture));
            await Response.WriteAsync(body, Request.CallCancelled);
            // request is handled, does not pass on to application
            return true;
        }

        private class Appender
        {
            private readonly char _delimiter;
            private readonly StringBuilder _sb;
            private bool _hasDelimiter;

            public Appender(string value, char delimiter)
            {
                _sb = new StringBuilder(value);
                _delimiter = delimiter;
                _hasDelimiter = value.IndexOf(delimiter) != -1;
            }

            public Appender Append(string name, string value)
            {
                _sb.Append(_hasDelimiter ? '&' : _delimiter)
                   .Append(Uri.EscapeDataString(name))
                   .Append('=')
                   .Append(Uri.EscapeDataString(value));
                _hasDelimiter = true;
                return this;
            }

            public override string ToString()
            {
                return _sb.ToString();
            }
        }
    }
}
