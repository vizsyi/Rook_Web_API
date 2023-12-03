using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Rook01.Data.EF;
using Rook01.Models.Auth;
using Rook01.Models.Auth.Constans;
using Rook01.Models.Auth.DTOs;
using Rook01.Models.Auth.Tokens;
using Rook01.Models.Auth.Tokens.DTOs;
using Rook01.Services.Auth;
using Rook01.Services.EMail.Views;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Rook01.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly ApplicationDBContext context;
        private readonly IConfiguration configuration;
        private readonly TokenValidationParameters tokenValidationParameters;

        public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager
            , ApplicationDBContext context, IConfiguration configuration, TokenValidationParameters tokenValidationParameters)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.context = context;
            this.configuration = configuration;
            this.tokenValidationParameters = tokenValidationParameters;
        }

        [AllowAnonymous]
        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterDTO model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Please provide all required fields"); //todo: Sending back the model errors
            }

            var mailUser = await userManager.FindByEmailAsync(model.Email);
            var nameUser = await userManager.FindByNameAsync(model.UserName);

            if (mailUser != null || nameUser != null)
            {
                var errorMess = (mailUser != null) ? ((nameUser != null)
                        ? $"Both User {model.UserName} and E-mail {model.Email} already exist!"
                        : $"E-mail {model.Email} already exists!")
                    : $"User {model.UserName} already exists!";

                return BadRequest(errorMess);
            }

            ApplicationUser newUser = new ApplicationUser(model);

            var result = await userManager.CreateAsync(newUser, model.Password);
            if (!result.Succeeded)
            {
                ModelState.AddModelError("Signup",
                    String.Join(", ", result.Errors.Select(e => e.Description)));

                return BadRequest("User could not be created");
            }

            newUser = await userManager.FindByEmailAsync(model.Email);
            if (newUser is null)
            {
                return BadRequest("Confirmation process failed");
            }

            var roleResult = await userManager.AddToRoleAsync(newUser, UserRoles.CelebEditor);

            var confToken = await userManager.GenerateEmailConfirmationTokenAsync(newUser);
            var confLink = Url.ActionLink("ConfirmEmail", "Auth"
                , new { userId = newUser.Id, token = confToken });//todo: to the Page
            await AuthEMailView.SendConfirmationAsync(newUser.Email, newUser.UserName, confLink);

            return Created(nameof(Register), $"User {model.UserName} created");
        }

        [HttpGet("Confirm")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var result = await userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return Ok("You have confirmed it.");
                }
            }

            return new NotFoundResult();
        }

        private async Task<AuthResult> GenerateJwtTokenAsync(ApplicationUser user, string existingRefreshToken)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.UserKey),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Name , user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti , user.UserName),
                new Claim("role", UserRoles.Admin),
                new Claim("role", UserRoles.CelebEditor),
                new Claim("role", UserRoles.Custom),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
             };

            var SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Key"]));

            var token = new JwtSecurityToken(
                issuer : configuration["JWT:Issuer"],
                audience : configuration["JWT:Audience"],
                claims: authClaims,
                expires: DateTime.UtcNow.AddMinutes(71),
                signingCredentials: new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256)
                );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            string refreshTokenValue;

            if (String.IsNullOrEmpty(existingRefreshToken))
            {
                var refreshToken = new RefreshToken()
                {
                    UserKey = user.UserKey,
                    UserId = user.Id,
                    SecKey = Chid.NewFullChid(7),
                    LongToken = Chid.NewFullChid(5) + "<" + Chid.NewFullChid(6),
                    DateExpire = DateTime.UtcNow.AddHours(6),
                    IsRevoked = false
                };

                await context.RefreshToken.AddAsync(refreshToken);
                await context.SaveChangesAsync();

                refreshTokenValue = refreshToken.LongToken;
            }
            else
            {
                refreshTokenValue = existingRefreshToken;
            }

            var response = new AuthResult()
            {
                Token = jwtToken,
                RefreshToken = refreshTokenValue,
                DateExpire = token.ValidTo
            };

            return response;
        }

        [AllowAnonymous]
        [HttpPost("user-login")]
        public async Task<IActionResult> Login(LoginDTO model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Please provide all required fields");
            }

            var user = await userManager.FindByEmailAsync(model.Email);

            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var authTokens = await GenerateJwtTokenAsync(user, null);
                return Ok(authTokens);
            }

            return Unauthorized();
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest model)
        {
            return Ok();
        }

        private DateTime UnixTimeStampToDateInUTC(long unixTimeStamp)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimeStamp);
        }


    }
}
