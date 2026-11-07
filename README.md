# DBN.ActiveDirectory

Lightweight and fast Active Directory access for .NET using LDAP.

`DBN.ActiveDirectory` provides an async-first API for looking up users, validating credentials, checking group membership, and managing group membership in Windows Active Directory environments.

It is designed to be simple to register in DI, easy to call from application services, and efficient enough for common enterprise identity workflows.

---

## Features

- Search users by:
  - `sAMAccountName`
  - email address
  - first and/or last name
- Validate credentials by performing an LDAP bind
- Check whether a user belongs to a specific AD group
- Retrieve a user’s direct group names
- Retrieve group members
- Add and remove a user from a group
- Built on `System.DirectoryServices.Protocols`

---

## Installation

Install the package from NuGet:

```bash
dotnet add package DBN.ActiveDirectory
```

Or via Package Manager:

```powershell
Install-Package DBN.ActiveDirectory
```

---

## Requirements

- .NET 8+
- Access to a Windows Active Directory / LDAP endpoint
- A valid domain name, and optionally a service account with permissions to query or manage groups
- Because the library uses LDAP, the host machine must be able to reach the domain controller or infrastructure that exposes LDAP

---

## Registering in DI

### 1) Domain only

Use this when the app is running under a user context that already has permission to query AD.

```csharp
using DBN.ActiveDirectory;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();

services.AddSingleton<IActiveDirectoryManager>(_ =>
    new ActiveDirectoryManager("example.com"));

var provider = services.BuildServiceProvider();
var activeDirectory = provider.GetRequiredService<IActiveDirectoryManager>();
```

### 2) With a service account

Use this when the app needs explicit credentials for LDAP access.

```csharp
using DBN.ActiveDirectory;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();

services.AddSingleton<IActiveDirectoryManager>(_ =>
    new ActiveDirectoryManager(
        "example.com",
        "MYDOMAIN\\svc-ad-reader",
        "SuperStrongPassword!"));

var provider = services.BuildServiceProvider();
var activeDirectory = provider.GetRequiredService<IActiveDirectoryManager>();
```

### 3) From configuration

```csharp
using DBN.ActiveDirectory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

var configuration = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

var services = new ServiceCollection();

services.AddSingleton<IActiveDirectoryManager>(_ =>
{
    var domain = configuration["ActiveDirectory:Domain"];
    var serviceAccount = configuration["ActiveDirectory:ServiceAccount"];
    var password = configuration["ActiveDirectory:Password"];

    return new ActiveDirectoryManager(domain!, serviceAccount, password);
});
```

Example `appsettings.json`:

```json
{
  "ActiveDirectory": {
    "Domain": "example.com",
    "ServiceAccount": "MYDOMAIN\\svc-ad-reader",
    "Password": "********"
  }
}
```

> Prefer storing credentials in environment variables, a secret store, or a secure configuration provider. Avoid hardcoding secrets in source code.

---

## Basic usage examples

### Search by `sAMAccountName`

```csharp
var user = await activeDirectory.FindUserBySamAccountName("jdoe");

if (user is not null)
{
    Console.WriteLine($"User: {user.DisplayName}");
    Console.WriteLine($"Email: {user.Email}");
    Console.WriteLine($"Enabled: {user.IsEnabled}");
}
else
{
    Console.WriteLine("User not found.");
}
```

### Search by email

```csharp
var user = await activeDirectory.FindUserByEmail("jdoe@example.com");

if (user is not null)
{
    Console.WriteLine($"{user.FirstName} {user.LastName}");
}
```

### Search by first and/or last name

```csharp
var users = await activeDirectory.FindUserByName(firstName: "John");

foreach (var user in users)
{
    Console.WriteLine($"{user.SamAccountName} - {user.DisplayName}");
}

var usersByFullName = await activeDirectory.FindUserByName("John", "Smith");
```

### Validate credentials

```csharp
var isValid = await activeDirectory.ValidateCredentials("jdoe", "MyPassword123!");

Console.WriteLine(isValid ? "Credentials are valid." : "Credentials are invalid.");
```

### Get user groups

```csharp
var groups = await activeDirectory.GetUserGroups("jdoe");

foreach (var group in groups)
{
    Console.WriteLine(group);
}
```

### Check whether a user is in a group

```csharp
var isMember = await activeDirectory.IsUserMemberOfGroup("jdoe", "Developers");

Console.WriteLine(isMember ? "User is a member of Developers." : "User is not a member.");
```

### Get all members of a group

```csharp
var members = await activeDirectory.GetGroupMembers("Developers");

foreach (var member in members)
{
    Console.WriteLine($"{member.SamAccountName} - {member.DisplayName}");
}
```

### Add a user to a group

```csharp
await activeDirectory.AddMember("jdoe", "Developers");
Console.WriteLine("User added to Developers.");
```

### Remove a user from a group

```csharp
await activeDirectory.RemoveMember("jdoe", "Developers");
Console.WriteLine("User removed from Developers.");
```

---

## User model

The library returns `ActiveDirectoryUser` objects with the following common properties:

```csharp
public class ActiveDirectoryUser
{
    public string SamAccountName { get; set; }
    public string? DisplayName { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Email { get; set; }
    public string? PhoneNumber { get; set; }
    public string? Title { get; set; }
    public string? Department { get; set; }
    public string? EmployeeNumber { get; set; }
    public DateTime? AccountExpirationDate { get; set; }
    public DateTime? CreatedDate { get; set; }
    public DateTime? ModifiedDate { get; set; }
    public DateTime? LastLogonDate { get; set; }
    public bool IsEnabled { get; set; }
    public IReadOnlyCollection<string> Groups { get; }
}
```

When `includeGroups` is `true`, the returned user will also include the direct group memberships available from the LDAP `memberOf` attribute.

---

## Error handling

This library throws `ActiveDirectoryManagerException` for operational and LDAP failures, and it may also throw `OperationCanceledException` if a cancellation token is triggered.

```csharp
try
{
    var user = await activeDirectory.FindUserBySamAccountName("jdoe");
}
catch (ActiveDirectoryManagerException ex)
{
    Console.WriteLine($"AD error: {ex.Message}");
}
catch (OperationCanceledException)
{
    Console.WriteLine("Request cancelled.");
}
```

---

## Notes and recommendations

- The library is built for Windows domain environments and Active Directory LDAP access.
- Access rights matter: some operations require permissions to read group membership or modify group membership.
- Domain controller connectivity, network restrictions, DNS, VPN, and permissions are common causes of runtime failures.
- Use cancellation tokens for long-running operations and avoid blocking calls in ASP.NET workloads.
- Prefer storing secret values in secure configuration providers such as environment variables or user secrets.

---

## Authors

Daniel Nunes  
📧 dbnunesg40@hotmail.com

