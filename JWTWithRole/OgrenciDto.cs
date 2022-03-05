namespace JWTWithRole
{
    public class OgrenciDto
    {
        public string Ad { get; set; } = string.Empty;
        public byte[] OgrenciNoHash { get; set; }
        public byte[] OgrenciNoSalt { get; set; }
    }
}
