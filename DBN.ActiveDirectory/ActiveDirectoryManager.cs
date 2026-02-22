using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;

namespace DBN.ActiveDirectory
{
    public class ActiveDirectoryManager : IActiveDirectoryManager, IDisposable
    {
        private readonly string? _serviceAccount;
        private readonly string? _accountPassword;
        private readonly string _domain;
        private readonly string _baseDomain;
        private readonly List<string> _attributeList;

        private readonly ConcurrentQueue<LdapConnection> _ldapPool = new();
        private readonly int _maxPoolSize = 5; // Max simultaneous reusable connections
        private readonly object _poolLock = new();

        private bool _disposed = false;

        private readonly ConcurrentDictionary<string, TimedCacheItem> _groupDnCache = new();
        private readonly ConcurrentDictionary<string, TimedCacheItem> _userDnCache = new();

        private readonly TimeSpan _cacheDuration = TimeSpan.FromMinutes(2);

        public ActiveDirectoryManager(string domain, string? serviceAccount = null, string? accountPassword = null)
        {
            if (!string.IsNullOrWhiteSpace(serviceAccount) && !string.IsNullOrWhiteSpace(accountPassword))
            {
                _serviceAccount = serviceAccount;
                _accountPassword = accountPassword;
            }
            else
            {
                _serviceAccount = null;
                _accountPassword = null;
            }

            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ActiveDirectoryManagerException("Domain is mandatory.");
            }

            _domain = domain;

            _baseDomain = string.Join(",", domain.Split('.').Select(d => $"DC={d}"));

            _attributeList =
            [
                "sAMAccountName",
                "displayName",
                "cn",
                "mail",
                "givenName",
                "sn",
                "title",
                "telephonenumber",
                "department",
                "lastLogontimestamp",
                "accountexpires",
                "userAccountControl",
                "whenCreated",
                "whenChanged",
                "lastLogon",
                "employeeNumber",
                "memberOf"
            ];
        }

        #region Search

        public async Task<ActiveDirectoryUser?> FindUserBySamAccountName(string sAMAccountName, bool includeGroups = true, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sAMAccountName))
            {
                return null;
            }

            var filter = $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={EscapeLdapFilter(sAMAccountName)}))";

            return (await InternalFindUsers(filter, includeGroups, cancellationToken)).FirstOrDefault();
        }

        public async Task<ActiveDirectoryUser?> FindUserByEmail(string email, bool includeGroups = true, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                return null;
            }

            var filter = $"(&(objectCategory=person)(objectClass=user)(mail={EscapeLdapFilter(email)}))";

            return (await InternalFindUsers(filter, includeGroups, cancellationToken)).FirstOrDefault();
        }

        public async Task<IEnumerable<ActiveDirectoryUser>> FindUserByName(string? firstName = null, string? lastName = null, bool includeGroups = true, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(firstName) && string.IsNullOrWhiteSpace(lastName))
            {
                return [];
            }

            var filterParts = new List<string>();

            if (!string.IsNullOrWhiteSpace(firstName))
            {
                filterParts.Add($"(givenName={EscapeLdapFilter(firstName)})");
            }

            if (!string.IsNullOrWhiteSpace(lastName))
            {
                filterParts.Add($"(sn={EscapeLdapFilter(lastName)})");
            }

            var filter = $"(&(objectCategory=person)(objectClass=user){string.Concat(filterParts)})";

            return await InternalFindUsers(filter, includeGroups, cancellationToken);
        }

        private async Task<List<ActiveDirectoryUser>> InternalFindUsers(string filter, bool includeGroups, CancellationToken cancellationToken)
        {
            try
            {
                var attributes = _attributeList.ToList();

                if (!includeGroups)
                {
                    attributes.RemoveAll(a => a == "memberOf");
                }

                var request = new SearchRequest(
                    _baseDomain,
                    filter,
                    SearchScope.Subtree,
                    [.. attributes]);

                var response = await UseConnectionAsync(connection => SendLdapRequestAsync<SearchResponse>(connection, request, cancellationToken), cancellationToken);

                var users = new List<ActiveDirectoryUser>();

                if (response.Entries.Count == 0)
                {
                    return users;
                }

                return [.. response.Entries.Cast<SearchResultEntry>().Select(entry => MapToUser(entry, includeGroups))];
            }
            catch (DirectoryOperationException exc)
            {
                throw new ActiveDirectoryManagerException($"LDAP operation failed while searching users with filter '{filter}'.", exc);
            }
            catch (LdapException exc)
            {
                throw new ActiveDirectoryManagerException($"LDAP error while searching users with filter '{filter}'.", exc);
            }
            catch (Exception exc)
            {
                throw new ActiveDirectoryManagerException($"Unexpected error while searching users with filter '{filter}'.", exc);
            }
        }


        #endregion


        #region Authentication

        public async Task<bool> ValidateCredentials(string sAMAccountName, string password, CancellationToken cancellationToken = default)
        {
            try
            {
                var credential = new NetworkCredential(sAMAccountName, password);

                using var connection = new LdapConnection(_domain)
                {
                    AuthType = AuthType.Negotiate,
                    Credential = credential
                };

                connection.SessionOptions.ProtocolVersion = 3;

                await Task.Run(() => connection.Bind(), cancellationToken);

                return true;
            }
            catch (LdapException)
            {
                return false;
            }
            catch (DirectoryOperationException exc)
            {
                throw new ActiveDirectoryManagerException($"Failed to validate password for user '{sAMAccountName}'.", exc);
            }
            catch (Exception exc)
            {
                throw new ActiveDirectoryManagerException($"Unexpected error while validating password for user '{sAMAccountName}'.", exc);
            }
        }

        #endregion


        #region Membership Checks

        public async Task<bool> IsUserMemberOfGroup(string sAMAccountName, string group, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sAMAccountName) || string.IsNullOrWhiteSpace(group))
                {
                    return false;
                }

                var groupDn = await GetGroupDn(group, cancellationToken);

                if (groupDn == null)
                {
                    return false;
                }

                var filter = $"(&(objectCategory=person)(objectClass=user)" +
                             $"(sAMAccountName={EscapeLdapFilter(sAMAccountName)})" +
                             $"(memberOf:1.2.840.113556.1.4.1941:={EscapeLdapFilter(groupDn)}))";

                var request = new SearchRequest(_baseDomain, filter, SearchScope.Subtree, null);

                var response = await UseConnectionAsync(connection => SendLdapRequestAsync<SearchResponse>(connection, request, cancellationToken), cancellationToken);

                return response.Entries.Count > 0;
            }
            catch (DirectoryOperationException exc)
            {
                throw new ActiveDirectoryManagerException($"Failed to check if user '{sAMAccountName}' is a member of group '{group}'.", exc);
            }
            catch (LdapException exc)
            {
                throw new ActiveDirectoryManagerException($"LDAP error while checking membership for user '{sAMAccountName}' in group '{group}'.", exc);
            }
            catch (Exception exc)
            {
                throw new ActiveDirectoryManagerException($"Unexpected error while checking if user '{sAMAccountName}' is a member of group '{group}'.", exc);
            }
        }

        #endregion


        #region Group Retrieval

        public async Task<IEnumerable<ActiveDirectoryUser>> GetGroupMembers(string group, bool includeGroups, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(group))
                {
                    return [];
                }

                var groupFilter = $"(&(objectClass=group)(cn={EscapeLdapFilter(group)}))";

                var groupRequest = new SearchRequest(
                    _baseDomain,
                    groupFilter,
                    SearchScope.Subtree,
                    ["member"]);

                var groupResponse = await UseConnectionAsync(connection => SendLdapRequestAsync<SearchResponse>(connection, groupRequest, cancellationToken), cancellationToken);

                if (groupResponse.Entries.Count == 0)
                {
                    return [];
                }

                var groupEntry = groupResponse.Entries[0];

                if (!groupEntry.Attributes.Contains("member"))
                {
                    return [];
                }

                var memberDns = groupEntry.Attributes["member"]
                    .GetValues(typeof(string))
                    .Cast<string>()
                    .ToList();

                if (memberDns.Count == 0)
                {
                    return [];
                }

                var orFilter = "(|" + string.Join("", memberDns.Select(dn => $"(distinguishedName={EscapeLdapFilter(dn)})")) + ")";

                var attributes = _attributeList.ToList();

                if (!includeGroups)
                {
                    attributes.RemoveAll(a => a == "memberOf");
                }

                var userRequest = new SearchRequest(
                    _baseDomain,
                    orFilter,
                    SearchScope.Subtree,
                    [.. attributes]);

                var userResponse = await UseConnectionAsync(connection => SendLdapRequestAsync<SearchResponse>(connection, userRequest, cancellationToken), cancellationToken);

                if (userResponse.Entries.Count == 0)
                {
                    return [];
                }

                return [.. userResponse.Entries
                    .Cast<SearchResultEntry>()
                    .Select(entry => MapToUser(entry, includeGroups))];
            }
            catch (DirectoryOperationException exc)
            {
                throw new ActiveDirectoryManagerException($"Failed to retrieve members of group '{group}'.", exc);
            }
            catch (LdapException exc)
            {
                throw new ActiveDirectoryManagerException($"LDAP error while retrieving members of group '{group}'.", exc);
            }
            catch (Exception exc)
            {
                throw new ActiveDirectoryManagerException($"Unexpected error while retrieving members of group '{group}'.", exc);
            }
        }

        #endregion


        #region Group Listings

        public async Task<IEnumerable<string>> GetUserGroups(string sAMAccountName, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sAMAccountName))
                {
                    return [];
                }

                var filter =
                    $"(&(objectCategory=person)(objectClass=user)" +
                    $"(sAMAccountName={EscapeLdapFilter(sAMAccountName)}))";

                var request = new SearchRequest(
                    _baseDomain,
                    filter,
                    SearchScope.Subtree,
                    ["memberOf"]);

                var response = await UseConnectionAsync(connection => SendLdapRequestAsync<SearchResponse>(connection, request, cancellationToken), cancellationToken);

                if (response.Entries.Count == 0)
                {
                    return [];
                }

                var entry = response.Entries[0];

                if (!entry.Attributes.Contains("memberOf"))
                {
                    return [];
                }

                var groups = entry.Attributes["memberOf"]
                    .GetValues(typeof(string))
                    .Cast<string>()
                    .Select(ExtractCnFromDn)
                    .ToList();

                return groups;
            }
            catch (DirectoryOperationException exc)
            {
                throw new ActiveDirectoryManagerException($"Failed to retrieve groups for user '{sAMAccountName}'.", exc);
            }
            catch (LdapException exc)
            {
                throw new ActiveDirectoryManagerException($"LDAP error while retrieving groups for user '{sAMAccountName}'.", exc);
            }
            catch (Exception exc)
            {
                throw new ActiveDirectoryManagerException($"Unexpected error while retrieving groups for user '{sAMAccountName}'.", exc);
            }
        }

        #endregion


        #region Membership Management

        public async Task AddMember(string sAMAccountName, string group, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sAMAccountName) || string.IsNullOrWhiteSpace(group))
                {
                    return;
                }

                if (await IsUserMemberOfGroup(sAMAccountName, group, cancellationToken))
                {
                    return;
                }

                var userDn = await GetUserDn(sAMAccountName, cancellationToken);

                var groupDn = await GetGroupDn(group, cancellationToken);

                if (userDn == null || groupDn == null)
                {
                    return;
                }

                var modification = new DirectoryAttributeModification
                {
                    Name = "member",
                    Operation = DirectoryAttributeOperation.Add
                };

                modification.Add(userDn);

                var request = new ModifyRequest(groupDn, modification);

                await UseConnectionAsync(connection => SendLdapRequestAsync<ModifyResponse>(connection, request, cancellationToken), cancellationToken);
            }
            catch (DirectoryOperationException exc)
            {
                throw new ActiveDirectoryManagerException($"Failed to add user '{sAMAccountName}' to group '{group}'.", exc);
            }
            catch (Exception exc)
            {
                throw new ActiveDirectoryManagerException($"Unexpected error while adding user '{sAMAccountName}' to group '{group}'.", exc);
            }
        }

        public async Task RemoveMember(string sAMAccountName, string group, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sAMAccountName) || string.IsNullOrWhiteSpace(group))
                {
                    return;
                }

                if (!await IsUserMemberOfGroup(sAMAccountName, group, cancellationToken))
                {
                    return;
                }

                var userDn = await GetUserDn(sAMAccountName, cancellationToken);

                var groupDn = await GetGroupDn(group, cancellationToken);

                if (userDn == null || groupDn == null)
                {
                    return;
                }

                var modification = new DirectoryAttributeModification
                {
                    Name = "member",
                    Operation = DirectoryAttributeOperation.Delete
                };

                modification.Add(userDn);

                var request = new ModifyRequest(groupDn, modification);

                await UseConnectionAsync(connection => SendLdapRequestAsync<ModifyResponse>(connection, request, cancellationToken), cancellationToken);
            }
            catch (DirectoryOperationException exc)
            {
                throw new ActiveDirectoryManagerException($"Failed to remove user '{sAMAccountName}' from group '{group}'.", exc);
            }
            catch (Exception exc)
            {
                throw new ActiveDirectoryManagerException($"Unexpected error while removing user '{sAMAccountName}' from group '{group}'.", exc);
            }
        }

        #endregion


        #region Helpers

        /// <summary>
        /// Maps a <see cref="SearchResultEntry"/> returned from an LDAP query
        /// to an <see cref="ActiveDirectoryUser"/> domain model.
        /// </summary>
        /// <param name="entry">
        /// The LDAP search result entry representing a user object.
        /// </param>
        /// <param name="includeGroups">
        /// If <c>true</c>, the user's direct group memberships (memberOf attribute)
        /// are extracted and populated into the <see cref="ActiveDirectoryUser"/>.
        /// </param>
        /// <returns>
        /// An <see cref="ActiveDirectoryUser"/> populated with available attributes
        /// from the LDAP entry.
        /// </returns>
        /// <remarks>
        /// Only attributes present in the search result are mapped.
        /// Missing attributes are left as <c>null</c> or default values.
        /// Group membership is extracted from the <c>memberOf</c> attribute
        /// and only includes direct memberships.
        /// </remarks>
        private static ActiveDirectoryUser MapToUser(SearchResultEntry entry, bool includeGroups)
        {
            var user = new ActiveDirectoryUser
            {
                SamAccountName = GetAttribute(entry, "sAMAccountName") ?? "",
                DisplayName = GetAttribute(entry, "displayName"),
                FirstName = GetAttribute(entry, "givenName"),
                LastName = GetAttribute(entry, "sn"),
                Email = GetAttribute(entry, "mail"),
                PhoneNumber = GetAttribute(entry, "telephonenumber"),
                Title = GetAttribute(entry, "title"),
                Department = GetAttribute(entry, "department"),
                EmployeeNumber = GetAttribute(entry, "employeeNumber"),
                CreatedDate = GetAttributeDate(entry, "whenCreated"),
                ModifiedDate = GetAttributeDate(entry, "whenChanged"),
                LastLogonDate = GetAttributeDate(entry, "lastLogon"),
                AccountExpirationDate = GetAttributeDate(entry, "accountexpires"),
                IsEnabled = GetUserAccountEnabled(entry)
            };

            if (includeGroups && entry.Attributes.Contains("memberOf"))
            {
                foreach (var group in entry.Attributes["memberOf"].GetValues(typeof(string)))
                {
                    var groupName = ExtractCnFromDn(group.ToString());
                    user.AddGroup(groupName);
                }
            }

            return user;
        }

        /// <summary>
        /// Extracts the Common Name (CN) component from a Distinguished Name (DN).
        /// </summary>
        /// <param name="dn">
        /// The full distinguished name (DN) of an Active Directory object
        /// (for example: "CN=John Doe,OU=Users,DC=example,DC=com").
        /// May be <c>null</c> or whitespace.
        /// </param>
        /// <returns>
        /// The value of the first CN component found in the DN.
        /// Returns an empty string if <paramref name="dn"/> is null or whitespace.
        /// If no CN component is found, returns the original DN value.
        /// </returns>
        /// <remarks>
        /// This method performs a simple string-based extraction and does not
        /// validate full DN syntax or handle escaped commas.
        /// </remarks>
        public static string ExtractCnFromDn(string? dn)
        {
            if (string.IsNullOrWhiteSpace(dn))
            {
                return "";
            }

            int start = dn.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);

            if (start < 0)
            {
                return dn;
            }

            int end = dn.IndexOf(',', start);

            if (end < 0)
            {
                end = dn.Length;
            }

            return dn.Substring(start + 3, end - start - 3).Trim();
        }

        /// <summary>
        /// Escapes special characters in a value so it can be safely used
        /// within an LDAP search filter.
        /// </summary>
        /// <param name="value">
        /// The raw value to escape. May be <c>null</c> or whitespace.
        /// </param>
        /// <returns>
        /// A properly escaped LDAP filter string. Returns an empty string
        /// if the input is null or whitespace.
        /// </returns>
        /// <remarks>
        /// The following characters are escaped according to RFC 4515:
        /// <list type="bullet">
        /// <item><description>\ (backslash)</description></item>
        /// <item><description>* (asterisk)</description></item>
        /// <item><description>( (left parenthesis)</description></item>
        /// <item><description>) (right parenthesis)</description></item>
        /// <item><description>null character</description></item>
        /// </list>
        /// </remarks>
        private static string EscapeLdapFilter(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "";
            }

            var sb = new StringBuilder(value!.Length);

            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': sb.Append(@"\5c"); break;
                    case '*': sb.Append(@"\2a"); break;
                    case '(': sb.Append(@"\28"); break;
                    case ')': sb.Append(@"\29"); break;
                    case '\0': sb.Append(@"\00"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        /// <summary>
        /// Retrieves the first string value of the specified LDAP attribute
        /// from a search result entry.
        /// </summary>
        /// <param name="entry">The LDAP search result entry.</param>
        /// <param name="name">The attribute name.</param>
        /// <returns>
        /// The attribute value as a string if present; otherwise <c>null</c>.
        /// </returns>
        /// <remarks>
        /// If the attribute contains multiple values, only the first value is returned.
        /// </remarks>
        private static string? GetAttribute(SearchResultEntry entry, string name)
        {
            if (!entry.Attributes.Contains(name))
            {
                return null;
            }

            var values = entry.Attributes[name];

            if (values.Count == 0)
            {
                return null;
            }

            return values[0]?.ToString();
        }

        /// <summary>
        /// Determines whether the user account represented by the LDAP entry is enabled.
        /// </summary>
        /// <param name="entry">The LDAP search result entry.</param>
        /// <returns>
        /// <c>true</c> if the account is enabled; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This method evaluates the <c>userAccountControl</c> attribute.
        /// The ACCOUNTDISABLE flag (0x2) indicates a disabled account.
        /// If the attribute is missing or invalid, the account is considered disabled.
        /// </remarks>
        private static bool GetUserAccountEnabled(SearchResultEntry entry)
        {
            var uacAttr = GetAttribute(entry, "userAccountControl");
            if (uacAttr == null)
            {
                return false;
            }

            if (int.TryParse(uacAttr, out int uac))
            {
                return (uac & 2) == 0; // 2 = ACCOUNTDISABLE
            }

            return false;
        }

        /// <summary>
        /// Retrieves and converts an LDAP date/time attribute to a <see cref="DateTime"/>.
        /// </summary>
        /// <param name="entry">The LDAP search result entry.</param>
        /// <param name="attributeName">The name of the date attribute.</param>
        /// <returns>
        /// A UTC <see cref="DateTime"/> if the attribute can be parsed; otherwise <c>null</c>.
        /// </returns>
        /// <remarks>
        /// This method supports:
        /// <list type="bullet">
        /// <item>
        /// Windows FileTime format (e.g., <c>lastLogon</c>, <c>accountExpires</c>)
        /// </item>
        /// <item>
        /// LDAP GeneralizedTime format (e.g., <c>whenCreated</c>, <c>whenChanged</c>)
        /// </item>
        /// </list>
        /// Invalid, zero, or maximum file time values return <c>null</c>.
        /// All returned values are normalized to UTC.
        /// </remarks>
        private static DateTime? GetAttributeDate(SearchResultEntry entry, string attributeName)
        {
            if (!entry.Attributes.Contains(attributeName))
            {
                return null;
            }

            var value = entry.Attributes[attributeName][0];

            if (value == null)
            {
                return null;
            }

            // 1️⃣ If already DateTime (rare but possible)
            if (value is DateTime dt)
            {
                return dt;
            }

            var stringValue = value.ToString();

            if (string.IsNullOrWhiteSpace(stringValue))
            {
                return null;
            }

            // 2️⃣ Handle FileTime (lastLogon, accountExpires, etc.)
            if (long.TryParse(stringValue, out long fileTime))
            {
                if (fileTime <= 0 || fileTime == long.MaxValue)
                {
                    return null;
                }

                return DateTime.FromFileTimeUtc(fileTime);
            }

            // Handle LDAP GeneralizedTime (whenCreated, whenChanged)
            // Format: yyyyMMddHHmmss.0Z
            if (DateTime.TryParseExact(
                    stringValue,
                    "yyyyMMddHHmmss.0Z",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal,
                    out var generalizedTime))
            {
                return generalizedTime.ToUniversalTime();
            }

            return null;
        }

        /// <summary>
        /// Retrieves the distinguished name (DN) of a group by its common name (CN).
        /// </summary>
        /// <param name="group">The group name (CN).</param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <returns>
        /// The distinguished name of the group if found; otherwise <c>null</c>.
        /// </returns>
        /// <exception cref="OperationCanceledException">
        /// Thrown if the operation is canceled.
        /// </exception>
        /// <remarks>
        /// The search is performed within the configured base domain
        /// and matches groups by their <c>cn</c> attribute.
        /// </remarks>
        private async Task<string?> GetGroupDn(string group, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(group))
            {
                return null;
            }

            if (_groupDnCache.TryGetValue(group, out var cached) && cached.Expiration > DateTime.UtcNow)
            {
                return cached.Value;
            }

            var filter = $"(&(objectClass=group)(cn={EscapeLdapFilter(group)}))";

            var request = new SearchRequest(_baseDomain, filter, SearchScope.Subtree, null);

            var response = await UseConnectionAsync(connection => SendLdapRequestAsync<SearchResponse>(connection, request, cancellationToken), cancellationToken);

            if (response.Entries.Count == 0)
            {
                return null;
            }

            var dn = response.Entries[0].DistinguishedName;

            _groupDnCache[group] = new TimedCacheItem
            {
                Value = dn,
                Expiration = DateTime.UtcNow.Add(_cacheDuration)
            };

            return dn;
        }

        /// <summary>
        /// Retrieves the distinguished name (DN) of a user by their sAMAccountName.
        /// </summary>
        /// <param name="sAMAccountName">The user logon name (sAMAccountName).</param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <returns>
        /// The distinguished name of the user if found; otherwise <c>null</c>.
        /// </returns>
        /// <exception cref="OperationCanceledException">
        /// Thrown if the operation is canceled.
        /// </exception>
        /// <remarks>
        /// The search filters for objects with:
        /// <list type="bullet">
        /// <item><description>objectCategory=person</description></item>
        /// <item><description>objectClass=user</description></item>
        /// <item><description>Matching sAMAccountName</description></item>
        /// </list>
        /// </remarks>
        private async Task<string?> GetUserDn(string sAMAccountName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(sAMAccountName))
            {
                return null;
            }

            if (_userDnCache.TryGetValue(sAMAccountName, out var cached) && cached.Expiration > DateTime.UtcNow)
            {
                return cached.Value;
            }

            var filter = $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={EscapeLdapFilter(sAMAccountName)}))";

            var request = new SearchRequest(_baseDomain, filter, SearchScope.Subtree, null);

            var response = await UseConnectionAsync(connection => SendLdapRequestAsync<SearchResponse>(connection, request, cancellationToken), cancellationToken);

            if (response.Entries.Count == 0)
            {
                return null;
            }

            var dn = response.Entries[0].DistinguishedName;

            _userDnCache[sAMAccountName] = new TimedCacheItem
            {
                Value = dn,
                Expiration = DateTime.UtcNow.Add(_cacheDuration)
            };

            return dn;
        }

        /// <summary>
        /// Gets an LDAP connection from the pool or creates a new one.
        /// </summary>
        private LdapConnection GetConnectionFromPool()
        {
            if (_ldapPool.TryDequeue(out var connection))
            {
                try
                {
                    // Test the connection with a simple operation
                    connection.SendRequest(new SearchRequest(_baseDomain, "(objectClass=*)", SearchScope.Base, null));
                    return connection;
                }
                catch
                {
                    // Connection failed; dispose and create a new one
                    connection.Dispose();
                    return CreateConnection();
                }
            }

            return CreateConnection();
        }

        /// <summary>
        /// Returns an LDAP connection to the pool, or disposes it if the pool is full.
        /// </summary>
        private void ReturnConnectionToPool(LdapConnection connection)
        {
            if (connection == null) return;

            lock (_poolLock)
            {
                if (_ldapPool.Count < _maxPoolSize)
                {
                    _ldapPool.Enqueue(connection);
                }
                else
                {
                    connection.Dispose();
                }
            }
        }

        /// <summary>
        /// Executes an async function using a pooled LDAP connection.
        /// </summary>
        private async Task<T> UseConnectionAsync<T>(Func<LdapConnection, Task<T>> func, CancellationToken cancellationToken = default)
        {
            var connection = GetConnectionFromPool();
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return await func(connection);
            }
            finally
            {
                ReturnConnectionToPool(connection);
            }
        }

        private static Task<T> SendLdapRequestAsync<T>(LdapConnection connection, DirectoryRequest request, CancellationToken cancellationToken) where T : DirectoryResponse
        {
            return Task.Run(() => (T)connection.SendRequest(request), cancellationToken);
        }

        /// <summary>
        /// Creates and binds an <see cref="LdapConnection"/> using the configured
        /// domain and credentials.
        /// </summary>
        /// <returns>
        /// A bound <see cref="LdapConnection"/> instance ready for use.
        /// </returns>
        /// <remarks>
        /// If a service account is configured, it is used for authentication.
        /// Otherwise, the default network credentials are used.
        /// The connection uses LDAP protocol version 3 and <see cref="AuthType.Negotiate"/>.
        /// </remarks>
        /// <exception cref="LdapException">
        /// Thrown if the bind operation fails.
        /// </exception>
        private LdapConnection CreateConnection()
        {
            var identifier = new LdapDirectoryIdentifier(_domain);

            var credential = string.IsNullOrWhiteSpace(_serviceAccount) ? CredentialCache.DefaultNetworkCredentials : new NetworkCredential(_serviceAccount, _accountPassword);

            var connection = new LdapConnection(identifier, credential)
            {
                AuthType = AuthType.Negotiate
            };

            connection.SessionOptions.ProtocolVersion = 3;
            connection.Bind(); // Fast operation

            return connection;
        }

        #endregion


        public void Dispose()
        {
            if (_disposed) return;

            lock (_poolLock)
            {
                while (_ldapPool.TryDequeue(out var connection))
                {
                    try
                    {
                        connection.Dispose();
                    }
                    catch
                    {
                        // ignored, best effort
                    }
                }
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
