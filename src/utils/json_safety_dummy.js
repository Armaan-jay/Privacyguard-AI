
try {
    const data = await res.json()
    // ... rest of existing logic
} catch (e) {
    // If JSON parsing fails, it might be raw text from Ollama or network error
    setResult({
        status: 'unknown',
        analysis: "Raw response error: " + e.message,
        score: 0
    })
}
