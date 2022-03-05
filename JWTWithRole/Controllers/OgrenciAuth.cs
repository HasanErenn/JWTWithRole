using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTWithRole.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OgrenciAuth : ControllerBase
    {
        public static OgrenciDto ogrenciDto=new OgrenciDto();
        private IConfiguration _configuration;

        public OgrenciAuth(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("Ogrenci_Register")]
        public async Task<ActionResult<Ogrenci>> OgrenciRegister(Ogrenci ogrenci)
        {
            CreateOgrenciNoHash(ogrenci.OgrenciNo, out byte[] ogrenciNoHash, out byte[] ogrenciNoSalt);
            
            ogrenciDto.Ad=ogrenci.OgrenciNo;
            ogrenciDto.OgrenciNoHash=ogrenciNoHash;
            ogrenciDto.OgrenciNoSalt=ogrenciNoSalt;
            return Ok(ogrenciDto);
        }

        [HttpPost("Ogrenci_Login")]
        public async Task<ActionResult<string>> OgrenciLogin(Ogrenci ogrenci)
        {
            if (ogrenciDto.Ad != ogrenci.Ad)
                return BadRequest("Ogrenci Bulunamadi");
            if (!CheckOgrenciNoHash(ogrenci.OgrenciNo, ogrenciDto.OgrenciNoHash, ogrenciDto.OgrenciNoSalt))
                return BadRequest("Sifre yanlis");

            var token = CreateToken(ogrenciDto);
            return Ok(token);
        }

        private string CreateToken(OgrenciDto ogrencidto)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, ogrenciDto.Ad),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var creds =new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token =new JwtSecurityToken
                (
                claims:claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
        private void CreateOgrenciNoHash(string ogrenciNo, out byte[] ogrenciNoHash, out byte[] ogrenciNoSalt)
        {
            using (var hmac=new HMACSHA512())
            {
                ogrenciNoSalt = hmac.Key;
                ogrenciNoHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(ogrenciNo));
            }
        }

        private bool CheckOgrenciNoHash(string ogrenciNo,byte[] ogrenciNoHash,byte[] ogrenciNoSalt)
        {
            using (var hmac= new HMACSHA512(ogrenciNoSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(ogrenciNo));
                return computedHash.SequenceEqual(ogrenciNoHash);
            }
        }
    }
}
