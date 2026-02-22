namespace DBN.ActiveDirectory
{
    /// <summary>
    /// Defines operations for managing and querying Active Directory users and groups.
    /// </summary>
    public interface IActiveDirectoryManager
    {
        #region Search

        /// <summary>
        /// Asynchronously searches Active Directory for a user matching the specified
        /// <paramref name="sAMAccountName"/>.
        /// </summary>
        /// <param name="sAMAccountName">
        /// The user logon name (sAMAccountName) to search for.
        /// </param>
        /// <param name="includeGroups">
        /// If <c>true</c>, populates the user's <c>Groups</c> collection with the 
        /// groups the user belongs to; otherwise group information is not loaded.
        /// </param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <returns>
        /// The matching <see cref="ActiveDirectoryUser"/> if found; otherwise <c>null</c>.
        /// </returns>
        /// <exception cref="OperationCanceledException">
        /// Thrown if the operation is canceled.
        /// </exception>
        Task<ActiveDirectoryUser?> FindUserBySamAccountName(string sAMAccountName, bool includeGroups = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// Searches Active Directory for a single user matching the specified email address.
        /// </summary>
        /// <param name="email">The email address of the user to search for.</param>
        /// <param name="includeGroups">
        /// If <c>true</c>, include the list of groups the user belongs to; 
        /// if <c>false</c>, only the user object is returned without group information.
        /// </param>
        /// <returns>
        /// An <see cref="ActiveDirectoryUser"/> object representing the user if found; otherwise, <c>null</c>.
        /// </returns>
        Task<ActiveDirectoryUser?> FindUserByEmail(string email, bool includeGroups = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// Asynchronously searches Active Directory for users matching the specified
        /// first and/or last name.
        /// </summary>
        /// <param name="firstName">
        /// Optional first name filter. If <c>null</c> or empty, no filtering by first name is applied.
        /// </param>
        /// <param name="lastName">
        /// Optional last name filter. If <c>null</c> or empty, no filtering by last name is applied.
        /// </param>
        /// <param name="includeGroups">
        /// If <c>true</c>, populates each user's <c>Groups</c> collection; otherwise group
        /// information is not loaded.
        /// </param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <returns>
        /// A collection of matching <see cref="ActiveDirectoryUser"/> instances. 
        /// Returns an empty collection if no users are found.
        /// </returns>
        Task<IEnumerable<ActiveDirectoryUser>> FindUserByName(string? firstName = null, string? lastName = null, bool includeGroups = true, CancellationToken cancellationToken = default);

        #endregion


        #region Authentication

        /// <summary>
        /// Asynchronously validates the supplied credentials against Active Directory
        /// by attempting an LDAP bind.
        /// </summary>
        /// <param name="sAMAccountName">The user logon name (sAMAccountName).</param>
        /// <param name="password">The user's password.</param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <returns>
        /// <c>true</c> if the credentials are valid; otherwise <c>false</c>.
        /// </returns>
        Task<bool> ValidateCredentials(string sAMAccountName, string password, CancellationToken cancellationToken = default);

        #endregion


        #region Membership Checks

        /// <summary>
        /// Asynchronously determines whether a user is a member of the specified group.
        /// </summary>
        /// <param name="sAMAccountName">The user logon name (sAMAccountName).</param>
        /// <param name="group">The name of the group to check.</param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <returns>
        /// <c>true</c> if the user is a member of the specified group; otherwise <c>false</c>.
        /// </returns>
        Task<bool> IsUserMemberOfGroup(string sAMAccountName, string group, CancellationToken cancellationToken = default);

        #endregion


        #region Group Retrieval

        /// <summary>
        /// Asynchronously retrieves the members of the specified Active Directory group.
        /// </summary>
        /// <param name="group">The name of the group.</param>
        /// <param name="includeGroups">
        /// If <c>true</c>, populates each returned user's <c>Groups</c> collection.
        /// </param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <returns>
        /// A collection of <see cref="ActiveDirectoryUser"/> instances representing
        /// the group's members. Returns an empty collection if the group has no members
        /// or does not exist.
        /// </returns>
        Task<IEnumerable<ActiveDirectoryUser>> GetGroupMembers(string group, bool includeGroups, CancellationToken cancellationToken = default);

        #endregion


        #region Group Listings

        /// <summary>
        /// Asynchronously retrieves the names of the groups the specified user belongs to.
        /// </summary>
        /// <param name="sAMAccountName">The user logon name (sAMAccountName).</param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <returns>
        /// A collection of group names. Returns an empty collection if the user does not
        /// exist or does not belong to any groups.
        /// </returns>
        Task<IEnumerable<string>> GetUserGroups(string sAMAccountName, CancellationToken cancellationToken = default);

        #endregion


        #region Membership Management

        /// <summary>
        /// Asynchronously adds the specified user to the specified Active Directory group.
        /// </summary>
        /// <param name="sAMAccountName">The user logon name (sAMAccountName).</param>
        /// <param name="group">The name of the group.</param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <remarks>
        /// The executing account must have sufficient permissions to modify group membership.
        /// </remarks>
        Task AddMember(string sAMAccountName, string group, CancellationToken cancellationToken = default);

        /// <summary>
        /// Asynchronously removes the specified user from the specified Active Directory group.
        /// </summary>
        /// <param name="sAMAccountName">The user logon name (sAMAccountName).</param>
        /// <param name="group">The name of the group.</param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation.
        /// </param>
        /// <remarks>
        /// The executing account must have sufficient permissions to modify group membership.
        /// </remarks>
        Task RemoveMember(string sAMAccountName, string group, CancellationToken cancellationToken = default);

        #endregion
    }
}
