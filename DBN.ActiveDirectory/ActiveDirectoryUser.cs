namespace DBN.ActiveDirectory
{
    public class ActiveDirectoryUser
    {
        public string SamAccountName { get; set; } = string.Empty;

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


        private readonly List<string> _groups = [];
        public IReadOnlyCollection<string> Groups => [.. _groups];

        public void AddGroup(string group)
        {
            if (!string.IsNullOrWhiteSpace(group))
            {
                _groups.Add(group);
            }
        }
    }
}
