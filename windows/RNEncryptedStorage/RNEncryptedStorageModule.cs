using Microsoft.ReactNative.Managed;
using System;
using System.Collections.Generic;
using System.Linq;
using Windows.Security.Credentials;

namespace RNEncryptedStorage
{
  [ReactModule("RNEncryptedStorage")]
  class RNEncryptedStorageModule
  {
    private static string PASSWORD_VAULT_RESOURCE_NAME = "RN_ENCRYPTED_STORAGE_VAULT";
    private PasswordVault vault = new PasswordVault();

    [ReactMethod("setItem")]
    public void SetItem(string key, string value, ReactPromise<JSValue> promise)
    {
      try
      {
        var credential = GetCredentials().FirstOrDefault(x => x.UserName == key);
        if (credential != null)
        {
          // deleting existing
          vault.Remove(credential);
        }

        vault.Add(new PasswordCredential(PASSWORD_VAULT_RESOURCE_NAME, key, value));
        promise.Resolve(value);
      }
      catch (Exception ex)
      {
        promise.Reject(new ReactError() { Exception = ex, Message = $"An error occurred while saving {key}" });
      }
    }

    [ReactMethod("getItem")]
    public void GetItem(string key, ReactPromise<JSValue> promise)
    {
      try
      {
        var credential = GetCredentials().FirstOrDefault(x => x.UserName == key);
        if (credential != null)
        {
          credential.RetrievePassword();
          promise.Resolve(credential.Password);
        }
        else
        {
          promise.Resolve(new JSValue());
        }
      }
      catch (Exception ex)
      {
        promise.Reject(new ReactError() { Exception = ex, Message = $"An error occurred while getting {key}" });
      }
    }

    [ReactMethod("removeItem")]
    public void RemoveItem(string key, ReactPromise<JSValue> promise)
    {
      try
      {
        var credential = GetCredentials().FirstOrDefault(x => x.UserName == key);
        if (credential != null)
        {
          vault.Remove(credential);
        }
        promise.Resolve(key);
      }
      catch (Exception ex)
      {
        promise.Reject(new ReactError() { Exception = ex, Message = $"An error occurred while removing {key}" });
      }
    }

    [ReactMethod("clear")]
    public void Clear(ReactPromise<JSValue> promise)
    {
      try
      {
        var credentials = GetCredentials();
        foreach (var credential in credentials)
        {
          vault.Remove(credential);
        }
        promise.Resolve(new JSValue());
      }
      catch (Exception ex)
      {
        promise.Reject(new ReactError() { Exception = ex, Message = "An error occurred while clearing PasswordVault" });
      }
    }

    private IEnumerable<PasswordCredential> GetCredentials()
    {
      try
      {
        return vault.FindAllByResource(PASSWORD_VAULT_RESOURCE_NAME);
      }
      catch
      {
        return new PasswordCredential[] { };
      }
    }
  }
}
