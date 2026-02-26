# DBN.ActiveDirectory

Lightweight, production-ready LDAP-based Active Directory manager for .NET.

`DBN.ActiveDirectory` provides a clean, async-first API for searching users, validating credentials, and managing group membership in Windows Active Directory environments.

It provides functionality to:

- 🔍 Search users
- 🔐 Validate credentials
- 👥 Check group membership
- 📋 Retrieve group members
- ➕➖ Add or remove users from groups

---

## Features

- Search users by:
  - `sAMAccountName`
  - Email
  - First and/or last name
- Validate user credentials
- Check if a user belongs to a specific group
- Retrieve members of a specific group
- Retrieve all groups a user belongs to
- Add and remove users from groups

---

## Created by

Daniel Nunes  
📧 dbnunesg40@hotmail.com

---

## Requirements

- Uses:
  - `System.DirectoryServices.Protocols`

# Dependency Injection Setup

## With Domain Only

```csharp
services.AddSingleton<IActiveDirectoryManager>(provider => new ActiveDirectoryManager("myDomain"));

//OR

services.AddSingleton<IActiveDirectoryManager>(provider =>
{
    var domain = "myDomain";
    return new ActiveDirectoryManager(domain);
});

//OR

services.AddSingleton<IActiveDirectoryManager>(provider =>
{
    var configuration = provider.GetRequiredService<IConfiguration>();
    var domain = configuration["ActiveDirectory:Domain"];
    return new ActiveDirectoryManager(domain, serviceAccount, accountPassword);
});
```

---

## With Service Account Credentials

> ⚠ Prefer configuration providers, environment variables, or secure vaults over hardcoding values.

```csharp
 services.AddSingleton<IActiveDirectoryManager>(provider => new ActiveDirectoryManager("myDomain", "myServiceAccount", "myStrongPassword123!"));

 //OR

services.AddSingleton<IActiveDirectoryManager>(provider =>
{
    var domain = "myDomain";
    var serviceAccount = "myServiceAccount";
    var accountPassword = "myStrongPassword123!";
    return new ActiveDirectoryManager(domain, serviceAccount, accountPassword);
});

//OR

services.AddSingleton<IActiveDirectoryManager>(provider =>
{
    var configuration = provider.GetRequiredService<IConfiguration>();
    var domain = configuration["ActiveDirectory:Domain"];
    var serviceAccount = configuration["ActiveDirectory:ServiceAccount"];
    var accountPassword = configuration["ActiveDirectory:Password"];
    return new ActiveDirectoryManager(domain, serviceAccount, accountPassword);
});
```

---

# Usage Examples

## Search User by sAMAccountName

```csharp
var user = await _activeDirectoryManager.FindUserBySamAccountName("user_xx");

if (user != null)
{
    Console.WriteLine($"{user.FirstName} {user.LastName}");
}
```

---

## Search User by Email

```csharp
var user = await _activeDirectoryManager.FindUserByEmail("user_xx@email.com");

if (user != null)
{
    Console.WriteLine($"{user.FirstName} {user.LastName}");
}
```

---

## Search Users by Name

```csharp
// By first name
var users = await _activeDirectoryManager.FindUserByName(firstName: "John");

// By last name
var users = await _activeDirectoryManager.FindUserByName(lastName: "Smith");

// By first and last name
var users = await _activeDirectoryManager.FindUserByName("John", "Smith");

foreach (var user in users)
{
    Console.WriteLine($"{user.FirstName} {user.LastName}");
}
```

---

## Validate User Password

```csharp
bool isValid = await _activeDirectoryManager.ValidateCredentials("user_xx", "SuperSecretPassword!");

Console.WriteLine(isValid ? "Password is valid ✅" : "Password is invalid ❌");
```

---

## Check Group Membership

```csharp
bool isMember = await _activeDirectoryManager.IsUserMemberOfGroup("user_xx", "GroupA");

Console.WriteLine(isMember ? "User is a member." : "User is not a member.");
```

---

## Retrieve Members of a Group

```csharp
var members = await _activeDirectoryManager.GetGroupMembers("GroupA");

foreach (var member in members)
{
    Console.WriteLine($"{member.FirstName} {member.LastName}");
}
```

---

## Get All Groups of a User

```csharp
var groups = await _activeDirectoryManager.GetUserGroups("user_xx");

foreach (var group in groups)
{
    Console.WriteLine(group);
}
```

---

## Add User to Group

```csharp
await _activeDirectoryManager.AddMember("user_xx", "GroupB");
```

---

## Remove User from Group

```csharp
_await _activeDirectoryManager.RemoveMember("user_xx", "GroupB");
```

---

## Notes

- Exceptions may be thrown if:
  - There are insufficient permissions
  - Network connectivity issues occur (e.g., unable to reach the AD server).
  - The domain controller is unavailable.
  - Internet or VPN issues prevent access to the AD infrastructure.
  - Configuration errors in the AD manager (wrong domain, credentials, etc.).

- Always ensure proper exception handling in production environments, including logging, retry logic, and meaningful error messages.
