using ScamShield.Api.Models;

namespace ScamShield.Api.Services;

public interface IScamAnalysisService
{
    Task<AnalyzeResponse> AnalyzeAsync(string text, string source, CancellationToken ct = default);
}
