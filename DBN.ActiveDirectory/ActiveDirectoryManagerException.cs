namespace DBN.ActiveDirectory
{
    public class ActiveDirectoryManagerException : Exception
    {
        public ActiveDirectoryManagerException(string message) : base(message)
        {
        }

        public ActiveDirectoryManagerException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
