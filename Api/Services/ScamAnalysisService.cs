using System.Text;
using System.Text.Json;
using ScamShield.Api.Models;

namespace ScamShield.Api.Services;

public class ScamAnalysisService : IScamAnalysisService
{
    private readonly ILlmClient _llm;
    private readonly ILogger<ScamAnalysisService> _logger;

    public ScamAnalysisService(ILlmClient llm, ILogger<ScamAnalysisService> logger)
    {
        _llm = llm;
        _logger = logger;
    }

    public async Task<AnalyzeResponse> AnalyzeAsync(string text, string source, CancellationToken ct = default)
    {
        // Deterministic pre-processing first - plain code extracts what it can
        // reliably extract (URLs, phone numbers, amounts, urgency phrasing).
        // The LLM never has to "notice" these itself; it just has to judge them.
        var signals = MessageSignalExtractor.Extract(text);

        var (verdict, confidence, redFlags, reasoning, action) = await AskLlmAsync(text, source, signals, ct);

        return new AnalyzeResponse
        {
            Verdict = verdict,
            Confidence = confidence,
            RedFlags = redFlags,
            Reasoning = reasoning,
            RecommendedAction = action,
            Signals = signals
        };
    }

    private async Task<(string Verdict, double Confidence, List<string> RedFlags, string Reasoning, string Action)>
        AskLlmAsync(string text, string source, ExtractedSignals signals, CancellationToken ct)
    {
        const string systemPrompt = """
            You are a scam/phishing detector for personal messages (email and chat). You judge a single
            incoming message and decide how likely it is to be a scam, using both the raw text and a list
            of pre-extracted signals (URLs, phone numbers, money mentions, urgency phrases) provided to you.

            Common scam patterns to weigh (not an exhaustive list, and none of these alone proves anything):
            - Fake delivery/customs fees demanding a small payment via a link
            - Fake KYC/bank/account-verification requests asking for OTP, PIN, or card details
            - Impersonation of a bank, government agency, or well-known company using lookalike domains
            - Fake job offers or "easy money" schemes asking for an upfront payment
            - Lottery/prize/inheritance messages requiring a fee to "release" winnings
            - Urgency and fear tactics ("your account will be suspended in 24 hours")
            - Romance or relationship-based requests for money from someone never met in person
            - Tech support scams claiming your device is infected and demanding remote access or payment

            A message can be entirely legitimate even if it contains a URL, a phone number, or an urgent
            tone - judge the message as a whole, not any single signal in isolation.

            Respond with ONLY a JSON object, no prose outside it, in exactly this shape:
            {"verdict": "scam|suspicious|safe", "confidence": 0.0-1.0, "redFlags": ["short phrase", ...], "reasoning": "2-3 sentences explaining the verdict", "recommendedAction": "one short sentence on what the recipient should do"}
            """;

        var sb = new StringBuilder();
        sb.AppendLine($"SOURCE: {source}");
        sb.AppendLine("MESSAGE TEXT:");
        sb.AppendLine(text);
        sb.AppendLine();
        sb.AppendLine("PRE-EXTRACTED SIGNALS:");
        sb.AppendLine($"- URLs: {(signals.Urls.Count > 0 ? string.Join(", ", signals.Urls) : "none")}");
        sb.AppendLine($"- Phone numbers: {(signals.PhoneNumbers.Count > 0 ? string.Join(", ", signals.PhoneNumbers) : "none")}");
        sb.AppendLine($"- Money mentions: {(signals.MonetaryMentions.Count > 0 ? string.Join(", ", signals.MonetaryMentions) : "none")}");
        sb.AppendLine($"- Urgency phrases found: {(signals.UrgencyPhrases.Count > 0 ? string.Join(", ", signals.UrgencyPhrases) : "none")}");

        var raw = await _llm.CompleteAsync(systemPrompt, sb.ToString(), ct);

        try
        {
            using var doc = JsonDocument.Parse(ExtractJson(raw));
            var root = doc.RootElement;

            var verdict = root.GetProperty("verdict").GetString() ?? "unknown";
            var confidence = root.TryGetProperty("confidence", out var c) ? c.GetDouble() : 0.5;
            var redFlags = root.TryGetProperty("redFlags", out var rf)
                ? rf.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x != "").ToList()
                : new List<string>();
            var reasoning = root.TryGetProperty("reasoning", out var r) ? r.GetString() ?? "" : "";
            var action = root.TryGetProperty("recommendedAction", out var a) ? a.GetString() ?? "" : "";

            return (verdict, confidence, redFlags, reasoning, action);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "LLM response was not valid JSON, falling back to raw text.");
            return ("unknown", 0.5, new List<string>(), raw, "Review this message manually.");
        }
    }

    private static string ExtractJson(string raw)
    {
        var start = raw.IndexOf('{');
        var end = raw.LastIndexOf('}');
        return start >= 0 && end > start ? raw[start..(end + 1)] : raw;
    }
}
