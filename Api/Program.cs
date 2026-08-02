using ScamShield.Api.Services;

var builder = WebApplication.CreateBuilder(args);

var port = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrEmpty(port))
{
    builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
}

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpClient<ILlmClient, GeminiClient>();
builder.Services.AddScoped<IScamAnalysisService, ScamAnalysisService>();

// The extension's background service worker calls this API cross-origin. Extension
// pages with host_permissions bypass CORS entirely for their own fetches, but this
// policy is kept permissive too since this is a personal, single-user local tool -
// not a multi-tenant service handling other people's data.
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});

var app = builder.Build();

app.UseCors();

app.UseSwagger();
app.UseSwaggerUI();
app.MapGet("/", () => Results.Redirect("/swagger"));

app.MapControllers();

app.Run();
