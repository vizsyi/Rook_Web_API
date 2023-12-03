using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Rook01.Data;
using Rook01.Data.EF;
using Rook01.Models.Auth;
using Rook01.Services.EMail;

//using Rook01.Services.EMail;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

//Identity store
builder.Services.AddDbContext<ApplicationDBContext>(option => 
    option.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

//Token Validation Parameters
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                builder.Configuration["JWT:Key"])),
    ValidateIssuer = true,
    ValidIssuer = builder.Configuration["JWT:Issuer"],
    ValidateAudience = true,
    ValidAudience = builder.Configuration["JWT:Audience"],

    ValidateLifetime= true,
    ClockSkew = TimeSpan.Zero
};
builder.Services.AddSingleton(tokenValidationParameters);

//Identity middleware
builder.Services.AddIdentity<ApplicationUser, IdentityRole<int>>()
    .AddEntityFrameworkStores<ApplicationDBContext>()
    .AddDefaultTokenProviders();//todo: test it

//Configuration of the identity
builder.Services.Configure<IdentityOptions>(options => {
    options.Password.RequiredLength = 5;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;

    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);

    options.SignIn.RequireConfirmedEmail = true;
});

//builder.Services.ConfigureApplicationCookie(options =>
//{
//    options.LoginPath = "/Auth/Signin";
//    options.AccessDeniedPath = "/Auth/AccessDenied";
//    options.ExpireTimeSpan = TimeSpan.FromHours(5);
//});

builder.Services.AddAuthentication(option =>
{
    option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    option.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = tokenValidationParameters;
    })
    .AddFacebook(options =>
    {
        options.AppId = builder.Configuration["FacebookAppId"];
        options.AppSecret = builder.Configuration["FacebookAppSecret"];
    });

//builder.Services.AddAuthorization(option =>
//{
//    option.AddPolicy("MemberDep", p =>
//    {
//        p.RequireClaim("Department", "Tech").RequireRole("Member");
//    });
//    option.AddPolicy("AdminDep", p =>
//    {
//        p.RequireClaim("Department").RequireRole("Admin");
//    });
//});

//Program services
//builder.Services.AddSingleton<IEMailer, GMailer>();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Beare", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header.\r\n\r\n" +
            "Enter 'Bearer' [space] and your token in the input field below.\r\n\r\n",
        Name = "Authorization ez a nev",
        In = ParameterLocation.Header,
        Scheme = "Bearer"
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference()
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = ParameterLocation.Header
            },
            new List<string>()
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

GMailer.SetMailbox(builder.Configuration);

app.Run();
