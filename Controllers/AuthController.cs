using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using dot.net6_Identity.Data;
using dot.net6_Identity.Domain.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace dot.net6_Identity.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    public static User _user = new User();
    private readonly UserManager<User> _userManager;
    public AuthController(UserManager<User> userManager)
    {
        _userManager = userManager;
    }

    
    [HttpPost("[action]")]
    public async Task<ActionResult<User>> Register(UserDto userDto)
    {
        CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);
        _user.UserName = userDto.UserName;
        _user.PasswordHash = passwordHash;
        _user.PasswordSalt = passwordSalt;

        return Ok(_user);
    }

    
    [HttpPost("[action]")]
    public async Task<ActionResult<string>> Login(UserDto userDto)
    {
        var users = _userManager.Users.FirstOrDefault(u => u.UserName == ClaimTypes.Name);
        if (!VerifyPassword(userDto.Password, _user.PasswordHash, _user.PasswordSalt))
        {
            return BadRequest("Wrong Password");
        }
        var token = CreateToken(userDto);
        return Ok(token);
    }

    

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512())
        {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }
    }

    private bool VerifyPassword(string password, byte[] passwordHash, byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512(passwordSalt))
        {
            var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return computeHash.SequenceEqual(passwordHash);
        }
    }

    private string CreateToken(UserDto user)
    {
        List<Claim> claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Role, "Admin"),
        };
        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("some-secret-here"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
        var token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(1), signingCredentials: creds);
        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        return jwt;
    }
}