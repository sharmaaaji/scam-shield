using System.Text.RegularExpressions;
using ScamShield.Api.Models;

namespace ScamShield.Api.Services;

// Plain deterministic parsing - same "let code do what code is good at" split used
// in IncidentIQ. These signals get handed to the LLM as hints; the LLM still makes
// the actual judgment call, since a URL or urgent tone alone doesn't prove a scam.
public static class MessageSignalExtractor
{
    private static readonly Regex UrlPattern = new(
        @"(https?:\/\/[^\s]+|www\.[^\s]+|\b[a-z0-9-]+\.(?:com|net|org|xyz|info|biz|top|club|link|in)\b[^\s]*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PhonePattern = new(
        @"(\+?\d{1,3}[-.\s]?)?\(?\d{3,5}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
        RegexOptions.Compiled);

    private static readonly Regex MoneyPattern = new(
        @"(₹|Rs\.?|INR|\$|USD)\s?[\d,]+(\.\d{1,2})?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] UrgencyKeywords =
    {
        "urgent", "act now", "immediately", "verify your account", "account suspended",
        "account blocked", "will be deactivated", "click here", "limited time",
        "expires today", "otp", "kyc", "prize", "winner", "lottery", "congratulations",
        "claim now", "final notice", "failure to", "unusual activity", "confirm your identity"
    };

    public static ExtractedSignals Extract(string text)
    {
        var signals = new ExtractedSignals
        {
            Urls = UrlPattern.Matches(text).Select(m => m.Value).Distinct().ToList(),
            PhoneNumbers = PhonePattern.Matches(text)
                .Select(m => m.Value.Trim())
                .Where(v => v.Length >= 7)
                .Distinct()
                .ToList(),
            MonetaryMentions = MoneyPattern.Matches(text).Select(m => m.Value).Distinct().ToList(),
            UrgencyPhrases = UrgencyKeywords
                .Where(k => text.Contains(k, StringComparison.OrdinalIgnoreCase))
                .ToList()
        };

        return signals;
    }
}
