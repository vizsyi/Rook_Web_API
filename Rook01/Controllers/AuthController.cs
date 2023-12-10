using Dapper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Rook01.Data.Dapper;
using Rook01.Data.EF;
using Rook01.Models.Auth;
using Rook01.Models.Auth.Constans;
using Rook01.Models.Auth.DTOs;
using Rook01.Models.Auth.Tokens;
using Rook01.Models.Auth.Tokens.DTOs;
using Rook01.Services.Auth;
using Rook01.Services.EMail.Views;
using System.Data;
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
        //private readonly TokenValidationParameters tokenValidationParameters;
        private readonly DataContextDapper dapper;

        public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager
            , ApplicationDBContext context, IConfiguration configuration)//, TokenValidationParameters tokenValidationParameters)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.context = context;
            this.configuration = configuration;
            //this.tokenValidationParameters = tokenValidationParameters;
            this.dapper = new DataContextDapper(configuration);
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

        private async Task<RefreshToken> GenerateRefreshTokenAsync(string userKey, int userId)
        {
            var refreshToken = new RefreshToken()
            {
                UserKey = userKey,
                UserId = userId,
                SecKey = Chid.NewChid(64, 7),
                LongToken = Chid.NewChid(64, 5) + "<" + Chid.NewChid(64, 6),
                DateExpire = DateTime.UtcNow.AddMinutes(79),
                IsRevoked = false
            };

            string sqlComm = "EXEC Auth.SP_RefreshT_Ups @userKey=@userKeyP, @userId=@userIdP"
                + ",@secKey=@secKeyP, @longToken=@longTokenP, @dateExpire=@dateExpireP";
            DynamicParameters dparams = new();
            dparams.Add("@userKeyP", refreshToken.UserKey, DbType.String);
            dparams.Add("@userIdP", refreshToken.UserId, DbType.Int32);
            dparams.Add("@secKeyP", refreshToken.SecKey, DbType.String);
            dparams.Add("@longTokenP", refreshToken.LongToken, DbType.String);
            dparams.Add("@dateExpireP", refreshToken.DateExpire, DbType.DateTime);

            dapper.ExecuteWithParametersAsync(sqlComm, dparams);//todo: handle the result
            //dapper.ExecuteWithParameters("Auth.SP_RefreshT_Ups", dparams);

            //await context.RefreshToken.AddAsync(refreshToken);
            //await context.SaveChangesAsync();//todo: with storedprocedure

            return refreshToken;
        }

        private async Task<AuthResult> GenerateJwtTokenAsync(RefreshToken refreshToken, bool isNewRefreshToken = false)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.NameId , refreshToken.UserKey),
                new Claim(JwtRegisteredClaimNames.Nonce, refreshToken.SecKey)
             };

            //Add user roles
            string sqlComm = "EXEC Auth.SP_RolesGetByUserId @userId = @userIdP";
            DynamicParameters dparams = new();
            dparams.Add("@userIdP", refreshToken.UserId, DbType.Int32);

            var userRoles = await dapper.LoadDataWithParametersAsync<string>(sqlComm, dparams);
            //var userRoles = await userManager.GetRolesAsync(user);
            foreach(var role in userRoles)
            {
                authClaims.Add(new Claim("role", role));
            }

            var SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Key"]));
            var token = new JwtSecurityToken(
                issuer : configuration["JWT:Issuer"],
                audience : configuration["JWT:Audience"],
                claims: authClaims,
                expires: DateTime.UtcNow.AddSeconds(457),
                signingCredentials: new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256)
                );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return new AuthResult()
            {
                Token = jwtToken,
                RefreshToken = isNewRefreshToken ? refreshToken.LongToken : "",
                DateExpire = token.ValidTo
            };
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDTO model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Please provide all required fields");
            }

            //todo: e-mail or username
            var user = await userManager.FindByEmailAsync(model.Email);

            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                return Ok(await GenerateJwtTokenAsync(await GenerateRefreshTokenAsync(user.UserKey, user.Id), true));
            }

            return Unauthorized();
        }

        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest model)
        {
            //if (!ModelState.IsValid)
            //{
            //    return BadRequest("Please provide all required fields");
            //}

            var jwtNid = JwtRegisteredClaimNames.NameId;
            var jwtNid2 = ClaimTypes.NameIdentifier;
            var jwtNonce = JwtRegisteredClaimNames.Nonce;
            //var jwtExp = JwtRegisteredClaimNames.Exp;
            var keyClaim = User.Claims.FirstOrDefault(c => (c.Type == jwtNid2 || c.Type == jwtNid));
            var secClaim = User.Claims.FirstOrDefault(c => c.Type == jwtNonce);
            //var expClaim = User.Claims.FirstOrDefault(c => c.Type == jwtExp);

            if (keyClaim != null && secClaim != null)
            {
                var userKey = keyClaim.Value;
                var refreshToken = context.RefreshToken.FirstOrDefault(rt => rt.UserKey == userKey);
                if (refreshToken != null && model.RefreshToken == refreshToken.LongToken)
                {
                    var equ = secClaim.Value == refreshToken.SecKey;//todo: checking
                    var user = await userManager.FindByIdAsync(refreshToken.UserId.ToString());//todo: delete

                    if (refreshToken.DateExpire <  DateTime.UtcNow.AddMinutes(24))
                    {
                        return Ok(await GenerateJwtTokenAsync(
                            await GenerateRefreshTokenAsync(refreshToken.UserKey, refreshToken.UserId), true));
                    }
                    return Ok(await GenerateJwtTokenAsync(refreshToken));
                }
            }

            var i = 1;
            return Unauthorized();
        }

        private DateTime UnixTimeStampToDateInUTC(long unixTimeStamp)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimeStamp);
        }


    }
}
