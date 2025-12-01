using AspNetCore.BasicAuthentication.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddBasicAuthGuard(options =>
{
    options.WithAuditLog(audit =>
    {
        audit.Enabled = true;
        audit.IncludeIpAddress = true;
        audit.IncludeUserAgent = true;
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Option 1: Add BasicAuthGuard for specific URL with inline credentials
app.AddBasicAuthGuard("/health", "healthuser", "healthpass");

// Option 2: Add BasicAuthGuard for URL pattern with wildcard support
app.AddBasicAuthGuard("/api/admin/*", "admin", "adminpass", "Admin Area");

// Option 3: Use builder pattern to configure multiple URL patterns at once
app.UseBasicAuthGuard(auth =>
{
    auth.AddPattern("/metrics", "metricsuser", "metricspass");
    auth.AddPattern("/api/internal/**", options =>
    {
        options.Username = "internal";
        options.Password = "internalpass";
        options.Realm = "Internal API";
        options.Roles.Add("InternalUser");
    });
});

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

// Health endpoint (protected by URL-based auth above)
app.MapGet("/health", () => Results.Ok(new { status = "healthy" }))
    .WithName("HealthCheck");

app.MapGet("/weatherforecast", () =>
    {
        var forecast = Enumerable.Range(1, 5).Select(index =>
                new WeatherForecast
                (
                    DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                    Random.Shared.Next(-20, 55),
                    summaries[Random.Shared.Next(summaries.Length)]
                ))
            .ToArray();
        return forecast;
    })
    .RequireBasicAuth("admin", "admin")
    .WithName("GetWeatherForecast");

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}