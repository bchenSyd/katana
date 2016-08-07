// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Infrastructure
{
    //bchen: two types of "providers", a server provider (IOAuthAuthorizationServerProvider  ) and a TokenProvider (IAuthenticationTokenProvider)
    //when you can IAppBuilder to use oAuth, if you don't provide an AccessTokenProvider, owin will use the default one
    //NOTE:this Token Provider doesn't know how to serialize a token, all it does is to expose a couple of events
    //     where your server provider can hook to and provide functions to create YOU OWN TOKEN using YOU OWN ENCRYPTION ALGORITH
    //default to machine key encrytion and then base64 encoding 
    //see: D:\__work\katana\src\Microsoft.Owin.Security.OAuth\OAuthAuthorizationServerHandler.cs
    //     oauthauthorizationseraccessToken = accessTokenContext.SerializeTicket();

       //D:\__work\katana\src\Microsoft.Owin.Security.OAuth\OAuthBearerAuthenticationMiddleware.cs
       //      if (Options.AccessTokenProvider == null)
       //      {
       //          Options.AccessTokenProvider = new AuthenticationTokenProvider();
       //      }
    public class AuthenticationTokenProvider : IAuthenticationTokenProvider
    {
        public Action<AuthenticationTokenCreateContext> OnCreate { get; set; }
        public Func<AuthenticationTokenCreateContext, Task> OnCreateAsync { get; set; }
        public Action<AuthenticationTokenReceiveContext> OnReceive { get; set; }
        public Func<AuthenticationTokenReceiveContext, Task> OnReceiveAsync { get; set; }
        
        public virtual void Create(AuthenticationTokenCreateContext context)
        {
            if (OnCreateAsync != null && OnCreate == null)
            {
                throw new InvalidOperationException(Resources.Exception_AuthenticationTokenDoesNotProvideSyncMethods);
            }
            if (OnCreate != null)
            {
                OnCreate.Invoke(context);
            }
        }

        public virtual async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            if (OnCreateAsync != null && OnCreate == null)
            {
                throw new InvalidOperationException(Resources.Exception_AuthenticationTokenDoesNotProvideSyncMethods);
            }
            if (OnCreateAsync != null)
            {
                await OnCreateAsync.Invoke(context);
            }
            else
            {
                Create(context);
            }
        }

        public virtual void Receive(AuthenticationTokenReceiveContext context)
        {
            if (OnReceiveAsync != null && OnReceive == null)
            {
                throw new InvalidOperationException(Resources.Exception_AuthenticationTokenDoesNotProvideSyncMethods);
            }

            if (OnReceive != null)
            {
                OnReceive.Invoke(context);
            }
        }

        public virtual async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            if (OnReceiveAsync != null && OnReceive == null)
            {
                throw new InvalidOperationException(Resources.Exception_AuthenticationTokenDoesNotProvideSyncMethods);
            }
            if (OnReceiveAsync != null)
            {
                await OnReceiveAsync.Invoke(context);
            }
            else
            {
                Receive(context);
            }
        }
    }
}
