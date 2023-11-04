using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Rook01.Data.EF;
using Rook01.Data.Identity;
using Rook01.Services.EMail;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connString = "Server=localhost;Database=Rook;Trusted_Connection=True;TrustServerCertificate=true";
//string connString = ConfigurationExtensions.GetConnectionString("DefaultConnection");

//Identity store
builder.Services.AddDbContext<ApplicationDBContext>(o => o.UseSqlServer(connString));

//Identity middleware
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
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

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Auth/Signin";
    options.AccessDeniedPath = "/Auth/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromHours(5);
});

builder.Services.AddAuthorization(option =>
{
    option.AddPolicy("MemberDep", p =>
    {
        p.RequireClaim("Department", "Tech").RequireRole("Member");
    });
    option.AddPolicy("AdminDep", p =>
    {
        p.RequireClaim("Department").RequireRole("Admin");
    });
});

builder.Services.AddSingleton<IEMailer, GMailer>();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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

app.Run();
