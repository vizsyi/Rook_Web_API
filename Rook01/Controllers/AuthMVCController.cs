using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Rook01.Data.Identity;
using Rook01.Models.Auth;
using Rook01.Services.EMail;
using System.Runtime.InteropServices;
using System.Security.Claims;

namespace Rook01.RookLog
{
    //[ApiController]
    [Route("[controller]")]
    public class AuthMVCController : Controller //Base
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IEMailer eMailer;

        //private readonly IConfiguration _config;
        //private readonly ILogger<> _logger;
        //private readonly DataContextDapper _dapper;
        
        public AuthMVCController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager
            ,RoleManager<IdentityRole> roleManager, IEMailer eMailer)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this.eMailer = eMailer;
            //this._config = config;
            //this._dapper = new DataContextDapper(config);
        }

        [HttpGet]
        public async Task<IActionResult> Signup()
        {
            var model = new SignupDTO();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupDTO model)
        {
            if (ModelState.IsValid)
            {
                var roleName = "Member";
                if(!(await roleManager.RoleExistsAsync(roleName)))
                {
                    var role = new IdentityRole() { Name = roleName};
                    var roleResult = await roleManager.CreateAsync(role);
                    if (!roleResult.Succeeded)
                    {
                        var errors = roleResult.Errors.Select(e => e.Description);
                        ModelState.AddModelError("Role", String.Join(", ", errors));
                        return View(model);
                    }
                }

                if((await userManager.FindByEmailAsync(model.Email)) == null)
                {
                    var user = new ApplicationUser()
                    {
                        UserName = model.UserName,
                        Email = model.Email
                    };
                    var result = await userManager.CreateAsync(user, model.Password);
                    user = await userManager.FindByEmailAsync(model.Email);
                    if (result.Succeeded && user != null)
                    {
                        var claim = new Claim(ClaimTypes.DateOfBirth, "1971");
                        await userManager.AddClaimAsync(user, claim);

                        await userManager.AddToRoleAsync(user, roleName);

                        var confToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
                        var confLink = Url.ActionLink("ConfirmEmail", "Auth"
                            ,new { userId = user.Id, token = confToken });//todo: to the Page
                        this.eMailer.SendEMailAsync(user.Email, "Confirm your e-mail address", confLink);

                        return RedirectToAction("Signin");
                    }

                    ModelState.AddModelError("Signup",
                        String.Join(", ", result.Errors.Select(e => e.Description)));
                    return View(model);
                }
            }
            return View(model);
        }

        public async Task<IActionResult> Signin()
        {
            var model = new SigninDTO();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signin(SigninDTO model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByEmailAsync(model.UserName);
                if (user != null)
                {
                    var result = await signInManager.PasswordSignInAsync(user, model.Password
                        , model.RememberMe, false);
                    //var result = await signInManager.PasswordSignInAsync(model.UserName, model.Password
                    //    , model.RememberMe, false);

                    if (result.Succeeded)
                    {
                        var userClaims = await userManager.GetClaimsAsync(user);

                        if (!userClaims.Any(c => c.Type == "Department"))
                        {
                            ModelState.AddModelError("Claims", "User has not got department");
                            return View(model);
                        }

                        if(await userManager.IsInRoleAsync(user, "Member"))
                        {
                            return RedirectToAction("Member", "Home");
                        }
                    }
                }

                ModelState.AddModelError("Login", "Cannot login.");
            }
            //var model = new SignupDTO();
            return View(model);
        }

        public async Task<IActionResult> Signout()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Signin");
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var result = await userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return RedirectToAction(nameof(Signin));
                }
            }

            return new NotFoundResult();
        }

        public async Task<IActionResult> AccessDenied()
        {
            return View();
        }

    }
}