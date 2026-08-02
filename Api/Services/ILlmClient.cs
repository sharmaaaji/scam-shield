namespace ScamShield.Api.Services;

public interface ILlmClient
{
    Task<string> CompleteAsync(string systemPrompt, string userPrompt, CancellationToken ct = default);
}
