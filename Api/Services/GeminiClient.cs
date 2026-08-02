using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace ScamShield.Api.Services;

public class GeminiClient : ILlmClient
{
    private readonly HttpClient _http;
    private readonly IConfiguration _config;

    public GeminiClient(HttpClient http, IConfiguration config)
    {
        _http = http;
        _config = config;
    }

    public async Task<string> CompleteAsync(string systemPrompt, string userPrompt, CancellationToken ct = default)
    {
        var apiKey = _config["Gemini:ApiKey"];
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new InvalidOperationException("Gemini:ApiKey is not configured. Set it via user-secrets or an environment variable.");

        var model = _config["Gemini:Model"] ?? "gemini-flash-latest";
        var baseUrl = _config["Gemini:BaseUrl"] ?? "https://generativelanguage.googleapis.com/v1beta/models";
        var url = $"{baseUrl}/{model}:generateContent?key={apiKey}";

        const int maxAttempts = 4;
        for (var attempt = 1; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = JsonContent.Create(new GeminiRequest
            {
                SystemInstruction = new GeminiContent { Parts = new[] { new GeminiPart { Text = systemPrompt } } },
                Contents = new[]
                {
                    new GeminiContent { Role = "user", Parts = new[] { new GeminiPart { Text = userPrompt } } }
                },
                GenerationConfig = new GeminiGenerationConfig { MaxOutputTokens = 512 }
            });

            var response = await _http.SendAsync(request, ct);

            if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests && attempt < maxAttempts)
            {
                var delay = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(Math.Pow(2, attempt) * 5);
                await Task.Delay(delay, ct);
                continue;
            }

            response.EnsureSuccessStatusCode();

            var body = await response.Content.ReadFromJsonAsync<GeminiResponse>(cancellationToken: ct)
                ?? throw new InvalidOperationException("Gemini API returned an empty response.");

            return body.Candidates.FirstOrDefault()?.Content.Parts.FirstOrDefault()?.Text ?? "";
        }
    }

    private class GeminiRequest
    {
        [JsonPropertyName("systemInstruction")]
        public GeminiContent SystemInstruction { get; set; } = new();

        [JsonPropertyName("contents")]
        public GeminiContent[] Contents { get; set; } = Array.Empty<GeminiContent>();

        [JsonPropertyName("generationConfig")]
        public GeminiGenerationConfig GenerationConfig { get; set; } = new();
    }

    private class GeminiContent
    {
        [JsonPropertyName("role")]
        public string? Role { get; set; }

        [JsonPropertyName("parts")]
        public GeminiPart[] Parts { get; set; } = Array.Empty<GeminiPart>();
    }

    private class GeminiPart
    {
        [JsonPropertyName("text")]
        public string Text { get; set; } = "";
    }

    private class GeminiGenerationConfig
    {
        [JsonPropertyName("maxOutputTokens")]
        public int MaxOutputTokens { get; set; }
    }

    private class GeminiResponse
    {
        [JsonPropertyName("candidates")]
        public List<GeminiCandidate> Candidates { get; set; } = new();
    }

    private class GeminiCandidate
    {
        [JsonPropertyName("content")]
        public GeminiContent Content { get; set; } = new();
    }
}
