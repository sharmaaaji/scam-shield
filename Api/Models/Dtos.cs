namespace ScamShield.Api.Models;

public class AnalyzeRequest
{
    public string Text { get; set; } = "";
    public string Source { get; set; } = "unknown"; // "gmail" | "whatsapp" | other
}

public class AnalyzeResponse
{
    public string Verdict { get; set; } = "unknown"; // "scam" | "suspicious" | "safe"
    public double Confidence { get; set; } // 0.0 - 1.0
    public List<string> RedFlags { get; set; } = new();
    public string Reasoning { get; set; } = "";
    public string RecommendedAction { get; set; } = "";

    // Deterministically-extracted signals, surfaced alongside the LLM verdict
    // so the extension UI can show *why* something got flagged without
    // re-deriving it client-side.
    public ExtractedSignals Signals { get; set; } = new();
}

public class ExtractedSignals
{
    public List<string> Urls { get; set; } = new();
    public List<string> PhoneNumbers { get; set; } = new();
    public List<string> MonetaryMentions { get; set; } = new();
    public List<string> UrgencyPhrases { get; set; } = new();
}
