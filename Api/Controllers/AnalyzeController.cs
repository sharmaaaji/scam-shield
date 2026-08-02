using Microsoft.AspNetCore.Mvc;
using ScamShield.Api.Models;
using ScamShield.Api.Services;

namespace ScamShield.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AnalyzeController : ControllerBase
{
    private readonly IScamAnalysisService _analysisService;

    public AnalyzeController(IScamAnalysisService analysisService)
    {
        _analysisService = analysisService;
    }

    [HttpPost]
    public async Task<ActionResult<AnalyzeResponse>> Analyze([FromBody] AnalyzeRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Text))
            return BadRequest("text is required.");

        // Extension shouldn't be sending huge payloads (full email threads, etc.) -
        // cap it defensively rather than trusting the client.
        var text = request.Text.Length > 4000 ? request.Text[..4000] : request.Text;

        var result = await _analysisService.AnalyzeAsync(text, request.Source);
        return Ok(result);
    }
}
