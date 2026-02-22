import { useState, useEffect } from 'react'
import { AlertCircle, ShieldCheck, Shield, Smartphone, Ghost, Code, Search, RefreshCw, ChevronRight, FileCode, ShieldAlert, CheckCircle, AlertTriangle, History, Globe, Download, Sun, Moon } from 'lucide-react'

// Sub-components for new features
const GhostPageScanner = () => {
  const [url, setUrl] = useState('')
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [scanned, setScanned] = useState(false)
  const [scannedUrl, setScannedUrl] = useState('')
  const [error, setError] = useState('')

  const handleScan = async (e) => {
    e.preventDefault()
    setLoading(true)
    setResults([])
    setScanned(false)
    setError('')
    setScannedUrl(url)
    try {
      const res = await fetch('http://localhost:5000/api/scan-ghost-pages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.message || 'An unknown error occurred.')
      } else {
        setResults(data.results || [])
      }
    } catch (err) {
      setError('Could not connect to the scan server. Make sure it is running.')
    } finally {
      setLoading(false)
      setScanned(true)
    }
  }

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6">
        <h2 className="text-xl font-bold text-zinc-900 dark:text-white mb-4 flex items-center">
          <Globe className="w-5 h-5 mr-2 text-rose-500" />
          Ghost Page Hunter
        </h2>
        <p className="text-zinc-600 dark:text-zinc-400 text-sm mb-6">Scan domains for forgotten endpoints like /admin, /backup, or /test that hackers target.</p>

        <div className="flex gap-3 mb-4">
          <input
            type="text"
            placeholder="https://yourdomain.com"
            className="flex-1 bg-zinc-50 dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg px-4 py-3 text-zinc-800 dark:text-zinc-200 focus:border-rose-500 focus:ring-1 focus:ring-rose-500 outline-none"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && url && !loading && handleScan(e)}
          />
          <button
            onClick={handleScan}
            disabled={loading || !url}
            className="bg-rose-600 hover:bg-rose-500 text-white px-6 py-3 rounded-lg font-bold disabled:opacity-50 transition-colors flex items-center gap-2"
          >
            {loading ? <><RefreshCw className="w-4 h-4 animate-spin" /> Scanning...</> : 'Start Hunt'}
          </button>
        </div>

        {loading && (
          <div className="mb-4 p-3 bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-500 flex items-center gap-2 animate-pulse">
            <RefreshCw className="w-3 h-3 animate-spin text-rose-400" />
            Probing <span className="font-mono text-rose-400">{scannedUrl}</span> across 80+ paths... this may take up to 30s.
          </div>
        )}

        {!loading && error && (
          <div className="mb-4 p-4 bg-rose-950/20 border border-rose-800/40 rounded-lg flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-rose-400 mt-0.5 shrink-0" />
            <div>
              <p className="text-rose-400 font-semibold text-sm">Invalid or Unreachable URL</p>
              <p className="text-rose-300/80 text-xs mt-1">{error}</p>
            </div>
          </div>
        )}

        {results.length > 0 ? (
          <div>
            <div className="flex items-center gap-4 mb-3 text-xs text-zinc-500">
              <span>Found <span className="font-bold text-rose-400">{results.filter(r => r.risk === 'High').length}</span> High</span>
              <span><span className="font-bold text-amber-400">{results.filter(r => r.risk === 'Medium').length}</span> Medium</span>
              <span><span className="font-bold text-emerald-400">{results.filter(r => r.risk === 'Low').length}</span> Low</span>
              <span>across <span className="font-bold text-zinc-300">{results.length}</span> discovered paths.</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-zinc-600 dark:text-zinc-400">
                <thead className="bg-zinc-50 dark:bg-zinc-950 uppercase text-xs font-bold text-zinc-500">
                  <tr>
                    <th className="px-4 py-3">Path</th>
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
                  {results.map((r, i) => (
                    <tr key={i} className="hover:bg-zinc-100 dark:hover:bg-zinc-800/50">
                      <td className="px-4 py-3 font-mono text-zinc-800 dark:text-zinc-200">{r.path}</td>
                      <td className="px-4 py-3 text-zinc-500 text-xs">{r.category}</td>
                      <td className="px-4 py-3">
                        <span className="bg-emerald-950/30 text-emerald-400 px-2 py-0.5 rounded text-xs">{r.status}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${r.risk === 'High' ? 'bg-rose-950/30 text-rose-500' :
                          r.risk === 'Medium' ? 'bg-amber-950/30 text-amber-500' :
                            'bg-emerald-950/30 text-emerald-500'
                          }`}>
                          {r.risk}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : !loading && scanned && !error ? (
          <div className="text-center py-10 border border-dashed border-zinc-700 rounded-lg">
            <CheckCircle className="w-10 h-10 text-emerald-500 mx-auto mb-3 opacity-60" />
            <p className="font-semibold text-zinc-300">No exposed ghost pages found on <span className="text-emerald-400 font-mono">{scannedUrl}</span></p>
            <p className="text-xs text-zinc-500 mt-2 max-w-md mx-auto">This domain appears clean across 80+ common attack paths. Try scanning a local dev server or your own domain for realistic results.</p>
          </div>
        ) : !loading && !error && (
          <div className="text-center py-10 border border-dashed border-zinc-700 rounded-lg">
            <Globe className="w-10 h-10 text-zinc-600 mx-auto mb-3 opacity-40" />
            <p className="text-zinc-500 text-sm">Enter a target domain and press <span className="font-bold text-zinc-400">Start Hunt</span></p>
            <p className="text-xs text-zinc-600 mt-1">Try: your own website, a test server, or a domain you own</p>
          </div>
        )}
      </div>
    </div>
  )
}

const CodeScanner = () => {
  const [code, setCode] = useState('')
  const [vulns, setVulns] = useState([])

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleScan = async () => {
    if (!code.trim()) return
    setLoading(true)
    setError(null)
    setVulns([])

    try {
      const res = await fetch('http://localhost:5000/api/scan-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      })

      if (!res.ok) throw new Error('Failed to scan code')

      const data = await res.json()
      setVulns(data.vulnerabilities || [])
      if (data.vulnerabilities?.length === 0) setError("No vulnerabilities found!") // visual feedback
    } catch (err) {
      console.error(err)
      setError("Scan failed. Ensure server is running.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid lg:grid-cols-2 gap-8">
      <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6 flex flex-col h-[500px]">
        <h2 className="text-xl font-bold text-zinc-900 dark:text-white mb-4 flex items-center">
          <Code className="w-5 h-5 mr-2 text-rose-500" />
          Source Code
        </h2>
        <textarea
          className="flex-1 bg-zinc-50 dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg p-4 font-mono text-sm text-zinc-700 dark:text-zinc-300 focus:border-rose-500 outline-none resize-none"
          placeholder="// Paste your code here..."
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
        <button
          onClick={handleScan}
          disabled={loading || !code.trim()}
          className="mt-4 bg-rose-600 hover:bg-rose-500 text-zinc-900 dark:text-white py-3 rounded-lg font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center"
        >
          {loading ? <RefreshCw className="w-5 h-5 animate-spin" /> : 'Scan for Secrets & Bugs'}
        </button>
      </div>

      <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6 h-[500px] overflow-y-auto">
        <h2 className="text-xl font-bold text-zinc-900 dark:text-white mb-2 flex items-center">
          <ShieldAlert className="w-5 h-5 mr-2 text-rose-500" />
          Vulnerabilities
        </h2>
        {vulns.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-zinc-600">
            <FileCode className="w-12 h-12 mb-3 opacity-20" />
            <p>{error || "No issues detected."}</p>
          </div>
        ) : (
          <div className="space-y-4">
            {vulns.map((v, i) => (
              <div key={i} className="bg-rose-950/10 border border-rose-900/20 p-4 rounded-lg">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-rose-400 font-bold text-sm">{v.type}</span>
                  <span className="bg-rose-950 text-rose-500 text-xs px-2 py-0.5 rounded uppercase tracking-wider">{v.severity}</span>
                </div>
                <p className="text-zinc-700 dark:text-zinc-300 text-sm mb-2">{v.message}</p>
                <div className="bg-zinc-50 dark:bg-zinc-950 p-2 rounded border border-zinc-200 dark:border-zinc-800 font-mono text-xs text-zinc-600 dark:text-zinc-400">
                  Line {v.line}: {v.content}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

const DigitalFootprint = () => {
  const [username, setUsername] = useState('')
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)

  const handleScan = async (e) => {
    e.preventDefault()
    setLoading(true)
    setResults([])
    try {
      const res = await fetch('http://localhost:5000/api/osint-search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      })
      const data = await res.json()
      setResults(data.results || [])
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6">
        <h2 className="text-xl font-bold text-zinc-900 dark:text-white mb-4 flex items-center">
          <Search className="w-5 h-5 mr-2 text-rose-500" />
          Digital Footprint Scanner
        </h2>
        <p className="text-zinc-600 dark:text-zinc-400 text-sm mb-6">See how easily hackers can find your profiles across the web using just a username.</p>

        <div className="flex gap-3 mb-6">
          <input
            type="text"
            placeholder="Enter username (e.g. john.doe)"
            className="flex-1 bg-zinc-50 dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg px-4 py-3 text-zinc-800 dark:text-zinc-200 focus:border-rose-500 focus:ring-1 focus:ring-rose-500 outline-none"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <button
            onClick={handleScan}
            disabled={loading || !username}
            className="bg-rose-600 hover:bg-rose-500 text-zinc-900 dark:text-white px-6 py-3 rounded-lg font-bold disabled:opacity-50 transition-colors"
          >
            {loading ? 'Scanning...' : 'Trace Footprint'}
          </button>
        </div>

        {results.length > 0 ? (
          <div className="grid gap-4">
            {results.map((r, i) => (
              <div key={i} className="bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg p-4 hover:border-rose-500/30 transition-all">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <span className="font-bold text-zinc-800 dark:text-zinc-200 text-lg">{r.platform}</span>
                    <span className={`px - 2 py - 0.5 rounded text - xs font - bold ${r.risk === 'High' ? 'bg-rose-950/30 text-rose-500' :
                      r.risk === 'Medium' ? 'bg-amber-950/30 text-amber-500' :
                        'bg-emerald-950/30 text-emerald-500'
                      } `}>
                      {r.risk} Risk
                    </span>
                  </div>
                  <a href={r.url} target="_blank" rel="noopener noreferrer" className="text-rose-500 hover:text-rose-400 text-sm flex items-center">
                    View Profile <ChevronRight className="w-4 h-4" />
                  </a>
                </div>

                <div className="space-y-3 mt-3 pt-3 border-t border-zinc-900">
                  <div>
                    <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-1">Analysis</h4>
                    <p className="text-zinc-700 dark:text-zinc-300 text-sm">{r.analysis}</p>
                  </div>

                  <div className="bg-white dark:bg-zinc-900/50 p-3 rounded border border-zinc-200 dark:border-zinc-800/50">
                    <h4 className="text-xs font-bold text-emerald-500 uppercase tracking-wider mb-1 flex items-center">
                      How to Remediate
                    </h4>
                    <p className="text-zinc-600 dark:text-zinc-400 text-sm">{r.remediation}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          !loading && <div className="text-center py-8 text-zinc-600 italic">No profiles found or scan not started.</div>
        )}
      </div>
    </div>
  )
}

const LLMScanner = () => {
  const [prompt, setPrompt] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleScan = async () => {
    if (!prompt.trim()) return
    setLoading(true)
    setResult(null)
    setError(null)

    try {
      const res = await fetch('http://localhost:5000/api/scan-llm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt })
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.details || data.error || 'Scan failed')
      }

      setResult(data)
    } catch (err) {
      console.error(err)
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6">
        <h2 className="text-xl font-bold text-zinc-900 dark:text-white mb-4 flex items-center">
          <ShieldAlert className="w-5 h-5 mr-2 text-rose-500" />
          LLM Firewall & Prompt Analysis
        </h2>
        <p className="text-zinc-600 dark:text-zinc-400 text-sm mb-6">
          Analyze prompts for malicious intent, jailbreaks, and injection attacks using <strong>Hybrid AI</strong> (DeBERTa + Generative LLM).
        </p>

        <div className="grid lg:grid-cols-2 gap-8">
          <div className="flex flex-col h-[400px]">
            <textarea
              className="flex-1 bg-zinc-50 dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg p-4 font-mono text-sm text-zinc-700 dark:text-zinc-300 focus:border-rose-500 outline-none resize-none mb-4"
              placeholder="Enter prompt to analyze (e.g., 'Ignore previous instructions and...')"
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
            />
            <button
              onClick={handleScan}
              disabled={loading || !prompt.trim()}
              className="bg-rose-600 hover:bg-rose-500 text-zinc-900 dark:text-white py-3 rounded-lg font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center"
            >
              {loading ? (
                <span className="flex items-center">
                  <RefreshCw className="w-5 h-5 animate-spin mr-2" />
                  Running Deep Analysis...
                </span>
              ) : 'Scan Prompt'}
            </button>
          </div>

          <div className="bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg p-6 relative overflow-hidden flex flex-col">
            {!result && !error && (
              <div className="h-full flex flex-col items-center justify-center text-zinc-600">
                <ShieldAlert className="w-12 h-12 mb-3 opacity-20" />
                <p>Waiting for prompt...</p>
              </div>
            )}

            {error && (
              <div className="h-full flex flex-col items-center justify-center text-rose-500">
                <AlertTriangle className="w-12 h-12 mb-3" />
                <p className="text-center px-4">{error}</p>
                <p className="text-xs text-zinc-500 mt-2">Make sure python llm_engine is running!</p>
              </div>
            )}

            {result && (
              <div className="h-full flex flex-col overflow-y-auto pr-2">
                <div className={`flex items-center justify-between mb-4 p-4 rounded-lg border ${result.firewall_status === 'Allowed'
                  ? 'bg-emerald-950/30 border-emerald-900/50'
                  : 'bg-rose-950/30 border-rose-900/50'
                  }`}>
                  <div className="flex items-center">
                    {result.firewall_status === 'Allowed' ? (
                      <CheckCircle className="w-8 h-8 text-emerald-500 mr-3" />
                    ) : (
                      <AlertTriangle className="w-8 h-8 text-rose-500 mr-3" />
                    )}
                    <div>
                      <h3 className={`text-lg font-bold ${result.firewall_status === 'Allowed' ? 'text-emerald-400' : 'text-rose-400'
                        }`}>
                        {result.firewall_status === 'Allowed' ? 'Prompt Allowed' : 'Prompt Blocked'}
                      </h3>
                      <div className="flex items-center gap-2 text-xs text-zinc-600 dark:text-zinc-400 mt-1">
                        <span className="bg-white dark:bg-zinc-900 px-2 py-0.5 rounded border border-zinc-200 dark:border-zinc-800">
                          {result.engine || 'Standard Engine'}
                        </span>
                        <span>Confidence: {(result.score * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                  </div>
                  {/* Category Badge */}
                  {result.category && (
                    <span className={`px-3 py-1 text-xs font-bold uppercase rounded-full border ${result.category === 'Safe' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : result.category === 'Suspicious' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-rose-500/10 text-rose-400 border-rose-500/20'}`}>
                      {result.category}
                    </span>
                  )}
                </div>

                <div className="space-y-4 flex-1">

                  {/* Detailed Output Header Cards */}
                  <div className="grid grid-cols-2 gap-3 mb-2">
                    {result.threat_type && result.threat_type !== 'None detected' && result.threat_type !== 'N/A' && (
                      <div className="bg-white dark:bg-zinc-900/50 p-3 rounded border border-zinc-200 dark:border-zinc-800 text-sm">
                        <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-1">Threat Type</h4>
                        <span className="text-rose-400 font-semibold">{result.threat_type}</span>
                      </div>
                    )}
                    {result.firewall_action && result.firewall_action !== 'N/A' && (
                      <div className="bg-white dark:bg-zinc-900/50 p-3 rounded border border-zinc-200 dark:border-zinc-800 text-sm">
                        <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-1">Action Engine</h4>
                        <span className={`font-bold ${result.firewall_action.toLowerCase().includes('block') ? 'text-rose-400' : 'text-emerald-400'}`}>{result.firewall_action}</span>
                      </div>
                    )}
                  </div>

                  {/* Risky Segments */}
                  {result.risky_segments && result.risky_segments.length > 0 && (
                    <div>
                      <h4 className="text-xs font-bold text-rose-500 uppercase tracking-wider mb-2 flex items-center">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        Flagged Segments
                      </h4>
                      <div className="space-y-2">
                        {result.risky_segments.map((segment, idx) => (
                          <div key={idx} className="bg-rose-950/20 p-2 rounded border border-rose-900/30 text-rose-300 text-xs font-mono">
                            "{segment}"
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {result.intent && result.intent !== 'N/A' && (
                    <div>
                      <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-2">Estimated User Intent</h4>
                      <div className="bg-white dark:bg-zinc-900/50 p-3 rounded border border-zinc-200 dark:border-zinc-800 text-zinc-800 dark:text-zinc-300 text-sm leading-relaxed">
                        {result.intent}
                      </div>
                    </div>
                  )}

                  {result.safe_alternative_prompt && result.safe_alternative_prompt.trim() !== '' && result.safe_alternative_prompt !== 'N/A' && (
                    <div>
                      <h4 className="text-xs font-bold text-emerald-500 uppercase tracking-wider mb-2 flex items-center">
                        <CheckCircle className="w-4 h-4 mr-1" />
                        Safe Alternative Prompt
                      </h4>
                      <div className="bg-emerald-50 dark:bg-emerald-950/20 p-4 rounded border border-emerald-200 dark:border-emerald-900/40 text-emerald-800 dark:text-emerald-300 text-sm leading-relaxed font-mono">
                        {result.safe_alternative_prompt}
                      </div>
                      <p className="text-[10px] text-zinc-500 mt-1 ml-1">Try using this format instead to safely achieve your goal.</p>
                    </div>
                  )}

                  <div>
                    <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-2">Detailed Analysis</h4>
                    <div className="bg-white dark:bg-zinc-900/50 p-4 rounded border border-zinc-200 dark:border-zinc-800 text-zinc-800 dark:text-zinc-300 text-sm leading-relaxed whitespace-pre-wrap font-mono">
                      {result.detailed_analysis || result.analysis}
                    </div>
                  </div>

                  {result.risk_level && (
                    <div className="flex items-center justify-between mt-2 pt-2 border-t border-zinc-200 dark:border-zinc-800">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-zinc-500 uppercase">Computed Risk Level:</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${result.risk_level === 'High' ? 'bg-rose-500 text-zinc-900 dark:text-white' : result.risk_level === 'Medium' ? 'bg-amber-500 text-zinc-900 dark:text-white' : 'bg-emerald-500 text-zinc-900 dark:text-white'
                          }`}>
                          {result.risk_level} Risk
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function App() {
  const [activeTab, setActiveTab] = useState('llm-firewall')
  const [isLightMode, setIsLightMode] = useState(false)

  useEffect(() => {
    if (isLightMode) {
      document.documentElement.classList.remove('dark')
    } else {
      document.documentElement.classList.add('dark')
    }
  }, [isLightMode])

  const tabs = [
    { id: 'llm-firewall', label: 'LLM Firewall', icon: ShieldAlert },
    { id: 'app-scanner', label: 'App Scanner', icon: Smartphone },
    { id: 'ghost-hunter', label: 'Ghost Hunter', icon: Ghost },
    { id: 'code-lint', label: 'Code Lint', icon: Code },
    { id: 'digital-footprint', label: 'DigiPrint', icon: Search },
  ]
  // --- App Scanner State ---
  const [appId, setAppId] = useState('')
  const [appName, setAppName] = useState('')
  const [description, setDescription] = useState('')
  const [permissions, setPermissions] = useState('')
  const [result, setResult] = useState(null)
  const [urlResult, setUrlResult] = useState(null)
  const [apkResult, setApkResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [fetching, setFetching] = useState(false)
  const [error, setError] = useState(null)
  const [recentScans, setRecentScans] = useState([])

  // Detect APK filename input
  const isApkInput = (val) => val.trim().toLowerCase().endsWith('.apk')

  // Detect URL/domain input (but NOT apk files)
  // Requires minimum valid domain structure: both parts around the dot >= 2 chars
  const isUrlInput = (val) => {
    const v = val.trim()
    if (v.length < 4) return false           // too short to be a real domain
    if (isApkInput(v)) return false
    if (v.startsWith('http')) return true    // explicit protocol → definitely a URL
    // Must have a dot with at least 2 chars on each side (e.g. "go.co" not just ".")
    const dotIndex = v.indexOf('.')
    if (dotIndex < 2) return false           // TLD or domain part too short before dot
    if (dotIndex >= v.length - 2) return false // TLD part too short after dot
    // Exclude known package ID prefixes
    const pkgPrefixes = ['com.', 'org.', 'net.', 'io.', 'co.', 'app.']
    if (pkgPrefixes.some(p => v.toLowerCase().startsWith(p))) return false
    return true
  }

  // APK filename scan — calls /api/scan-apk (heuristic, NOT the URL model)
  const handleApkScan = async (filename) => {
    setFetching(true)
    setError(null)
    setApkResult(null)
    setUrlResult(null)
    setResult(null)
    try {
      const res = await fetch('http://localhost:5000/api/scan-apk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename })
      })
      const data = await res.json()
      if (!res.ok) {
        if (data.error === 'apk_not_found') {
          // Special case: app not found on Play Store
          setError(`❌ APK doesn't exist — ${data.message}`)
        } else {
          setError(data.message || data.error || 'APK scan failed')
        }
        return
      }
      setApkResult(data)
      addToHistory(filename, data.risk_level)
    } catch (err) {
      setError('Could not reach the scan server.')
    } finally {
      setFetching(false)
    }
  }

  // URL / domain scan — calls /api/scan (DistilBERT URL model)
  const handleScanUrl = async (url) => {
    setFetching(true)
    setError(null)
    setUrlResult(null)
    setApkResult(null)
    setResult(null)
    try {
      const res = await fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: url })
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'URL scan failed'); return }
      setUrlResult(data)
      addToHistory(url, data.risk_level)
    } catch (err) {
      setError('Could not reach the scan server.')
    } finally {
      setFetching(false)
    }
  }

  const handleFetchApp = async (e) => {
    e.preventDefault()
    if (!appId) return

    const trimmed = appId.trim()

    // Reject empty or suspiciously short inputs before any routing
    if (!trimmed || trimmed.length < 2) {
      setError('Please enter a valid URL, APK filename (.apk), or Play Store package ID (e.g. com.whatsapp).')
      return
    }

    // Route 1: APK filename (.apk extension)
    if (isApkInput(trimmed)) {
      handleApkScan(trimmed)
      return
    }

    // Route 2: URL / domain
    if (isUrlInput(trimmed)) {
      handleScanUrl(trimmed)
      return
    }

    // Route 3: Play Store package ID (com.xxx / org.xxx etc.)
    const isPackageId = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/i.test(trimmed)
    if (!isPackageId && !trimmed.includes('play.google.com')) {
      setError('Invalid input. Please enter:\n• A URL or domain to scan (e.g. example.com)\n• An APK filename ending in .apk (e.g. WhatsApp.apk)\n• A Play Store package ID (e.g. com.whatsapp)')
      return
    }


    setFetching(true)
    setError(null)

    // Extract package ID if a full Play Store URL is pasted
    let idToFetch = appId.trim()
    if (idToFetch.includes('play.google.com')) {
      try {
        const urlObj = new URL(idToFetch)
        idToFetch = urlObj.searchParams.get('id') || ''
      } catch (e) { /* ignore parse error */ }
    }

    if (!idToFetch) {
      setError('Invalid Play Store URL or package ID. Enter something like: com.whatsapp')
      setFetching(false)
      return
    }

    try {
      const response = await fetch('http://localhost:5000/api/fetch-app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appId: idToFetch }),
      })

      const data = await response.json()

      if (!response.ok) {
        // Show the real error from the server + hint about manual input
        setError((data.error || 'Failed to fetch app') + ' You can still fill in the fields manually below and click Assess Risk.')
        setFetching(false)
        return
      }

      setAppName(data.name || '')
      setDescription(data.description || '')
      setPermissions(data.permissions || '')
      setResult(null)
    } catch (err) {
      setError('Could not reach the scan server. Make sure node server/server.js is running.')
    } finally {
      setFetching(false)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch('http://localhost:5000/api/assess', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: appName,
          description,
          permissions,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to assess risk')
      }

      const data = await response.json()

      // Artificial delay for UX
      setTimeout(() => {
        setResult(data)
        setLoading(false)
        addToHistory(appName, data.risk_level)
      }, 800)
    } catch (err) {
      setError(err.message)
      setLoading(false)
    }
  }

  const addToHistory = (name, risk) => {
    setRecentScans(prev => [
      { name, risk, time: new Date().toLocaleTimeString() },
      ...prev.slice(0, 4)
    ])
  }

  const getRiskColor = (level) => {
    switch (level) {
      case 'Low': return 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20'
      case 'Medium': return 'text-amber-400 bg-amber-400/10 border-amber-400/20'
      case 'High': return 'text-rose-500 bg-rose-500/10 border-rose-500/20'
      default: return 'text-slate-400 bg-slate-400/10 border-slate-400/20'
    }
  }

  const getRiskIcon = (level) => {
    switch (level) {
      case 'Low': return <ShieldCheck className="w-12 h-12 text-emerald-400" />
      case 'Medium': return <ShieldAlert className="w-12 h-12 text-amber-400" />
      case 'High': return <AlertCircle className="w-12 h-12 text-rose-500" />
      default: return <Shield className="w-12 h-12 text-slate-400" />
    }
  }

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 font-sans selection:bg-rose-500/30">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-zinc-100 dark:from-zinc-800 via-zinc-50 dark:via-zinc-950 to-zinc-50 dark:to-zinc-950 opacity-50 pointer-events-none"></div>

      <div className="relative flex flex-col items-center min-h-screen px-4 sm:px-6 lg:px-8 py-12">

        {/* Header */}
        <div className="w-full max-w-5xl mb-8 flex flex-col md:flex-row justify-between items-end border-b border-zinc-200 dark:border-zinc-800 pb-6">
          <div>
            <div className="flex items-center space-x-2 text-rose-500 mb-2">
              <ShieldCheck className="w-6 h-6" />
              <span className="text-sm font-bold tracking-widest uppercase">PrivacyGuard AI</span>
            </div>
            <div className="flex items-center gap-4">
              <h1 className="text-3xl md:text-4xl font-bold tracking-tight text-zinc-900 dark:text-white">
                Security Suite
              </h1>
              <button
                onClick={() => setIsLightMode(!isLightMode)}
                className="p-2 ml-2 rounded bg-zinc-100 dark:bg-zinc-800/80 hover:bg-zinc-700/80 text-zinc-700 dark:text-zinc-300 transition-colors preserve-colors border border-zinc-300 dark:border-zinc-700/50"
                title="Toggle Light/Dark Mode"
              >
                {isLightMode ? <Moon className="w-5 h-5 text-zinc-900 dark:text-zinc-100" /> : <Sun className="w-5 h-5 text-yellow-400" />}
              </button>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex space-x-1 bg-white dark:bg-zinc-900 p-1 rounded-lg mt-4 md:mt-0 overflow-x-auto max-w-full scrollbar-hide">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`
                    flex items-center px-4 py-2 rounded-md text-sm font-medium transition-all whitespace-nowrap
                    ${activeTab === tab.id
                      ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-white shadow-lg ring-1 ring-white/10'
                      : 'text-zinc-600 dark:text-zinc-400 hover:text-zinc-800 dark:text-zinc-200 hover:bg-zinc-100 dark:bg-zinc-800/50'}
                  `}
                >
                  <Icon className="w-4 h-4 mr-2" />
                  {tab.label}
                </button>
              )
            })}
          </div>
        </div>

        <div className="w-full max-w-5xl">
          {activeTab === 'app-scanner' && (
            <div className="grid lg:grid-cols-3 gap-8 items-start animate-in fade-in zoom-in-95 duration-300">
              {/* Main Input Column */}
              <div className="lg:col-span-2 space-y-6">

                {/* Fetcher */}
                <div className="bg-white dark:bg-zinc-900/50 backdrop-blur-sm border border-zinc-200 dark:border-zinc-800 rounded-xl p-6">
                  <h2 className="text-lg font-semibold text-zinc-800 dark:text-zinc-200 mb-4 flex items-center">
                    <Download className="w-5 h-5 mr-2 text-zinc-500" />
                    Add APK File or URL
                  </h2>
                  <div className="flex gap-3">
                    <input
                      type="text"
                      placeholder="Paste APK URL, domain, or Play Store ID (e.g. com.whatsapp)"
                      className="flex-1 bg-zinc-50 dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-rose-500/50 focus:ring-1 focus:ring-rose-500/50 transition-all font-mono text-zinc-700 dark:text-zinc-300"
                      value={appId}
                      onChange={(e) => setAppId(e.target.value)}
                    />
                    <button
                      onClick={handleFetchApp}
                      disabled={fetching || !appId}
                      className="bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-700 text-zinc-900 dark:text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
                    >
                      {fetching ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Scan'}
                    </button>
                  </div>
                  {error && <p className="text-rose-400 text-xs mt-2">{error}</p>}
                </div>

                {/* Analysis Form */}
                <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6 sm:p-8 shadow-xl relative overflow-hidden group">
                  <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                    <ShieldCheck className="w-24 h-24" />
                  </div>

                  <form onSubmit={handleSubmit} className="space-y-5 relative z-10">
                    <div>
                      <label htmlFor="appName" className="block text-xs font-semibold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider mb-1">App Name</label>
                      <input
                        type="text"
                        id="appName"
                        required
                        className="block w-full bg-zinc-50 dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg px-4 py-3 text-zinc-800 dark:text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-rose-500/50 focus:ring-1 focus:ring-rose-500/50 transition-all font-medium"
                        placeholder="e.g. Flashlight Pro"
                        value={appName}
                        onChange={(e) => setAppName(e.target.value)}
                      />
                    </div>

                    <div>
                      <label htmlFor="description" className="block text-xs font-semibold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider mb-1">Description</label>
                      <textarea
                        id="description"
                        required
                        rows={5}
                        className="block w-full bg-zinc-50 dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg px-4 py-3 text-zinc-800 dark:text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-rose-500/50 focus:ring-1 focus:ring-rose-500/50 transition-all text-sm leading-relaxed"
                        placeholder="Briefly describe what the app does..."
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                      />
                    </div>

                    <div>
                      <label htmlFor="permissions" className="block text-xs font-semibold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider mb-1">
                        Permissions
                      </label>
                      <input
                        type="text"
                        id="permissions"
                        className="block w-full bg-zinc-50 dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg px-4 py-3 text-zinc-800 dark:text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-rose-500/50 focus:ring-1 focus:ring-rose-500/50 transition-all font-mono text-xs"
                        placeholder="CAMERA, READ_SMS (Optional)"
                        value={permissions}
                        onChange={(e) => setPermissions(e.target.value)}
                      />
                    </div>

                    <div className="pt-4">
                      <button
                        type="submit"
                        disabled={loading}
                        className="w-full flex items-center justify-center px-8 py-4 text-sm font-bold text-zinc-900 dark:text-white transition-all duration-200 bg-gradient-to-r from-rose-600 to-orange-600 hover:from-rose-500 hover:to-orange-500 rounded-lg focus:outline-none shadow-lg shadow-rose-900/20 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {loading ? 'Analyzing Neural Patterns...' : 'Run Security Scan'}
                        {!loading && <ChevronRight className="w-4 h-4 ml-1" />}
                      </button>
                    </div>
                  </form>
                </div>
              </div>

              {/* Sidebar / Results */}
              <div className="space-y-6">

                {/* APK Scan Result Card */}
                {apkResult && (
                  <div className="bg-white dark:bg-zinc-900 border border-orange-900/40 rounded-xl p-6 shadow-2xl animate-in slide-in-from-right-4 duration-500">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <h3 className="text-lg font-bold text-zinc-900 dark:text-white">APK Scan Report</h3>
                        <p className="font-mono text-xs text-zinc-500 truncate max-w-[200px]">{apkResult.app_name}</p>
                        <p className="text-xs text-zinc-600 dark:text-zinc-500 mt-0.5">Version: {apkResult.version}</p>
                      </div>
                      <span className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-wider ${apkResult.risk_level === 'High' ? 'bg-rose-950/40 text-rose-400' : apkResult.risk_level === 'Medium' ? 'bg-amber-950/40 text-amber-400' : 'bg-emerald-950/40 text-emerald-400'}`}>
                        {apkResult.risk_level} Risk
                      </span>
                    </div>

                    {/* Risk Score Bar */}
                    <div className="mb-5">
                      <div className="flex justify-between text-xs text-zinc-500 mb-1">
                        <span>Risk Score</span>
                        <span className="font-bold text-zinc-300">{apkResult.risk_score}/100</span>
                      </div>
                      <div className="w-full bg-zinc-800 rounded-full h-2">
                        <div className={`h-2 rounded-full transition-all ${apkResult.risk_score >= 55 ? 'bg-rose-500' : apkResult.risk_score >= 25 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                          style={{ width: `${apkResult.risk_score}%` }} />
                      </div>
                    </div>

                    {/* Confidence */}
                    <div className="flex gap-3 mb-5 text-xs">
                      <div className="flex-1 bg-zinc-950 rounded-lg p-2 text-center">
                        <div className="text-rose-400 font-bold">{(apkResult.confidence?.malicious * 100).toFixed(0)}%</div>
                        <div className="text-zinc-500">Malicious</div>
                      </div>
                      <div className="flex-1 bg-zinc-950 rounded-lg p-2 text-center">
                        <div className="text-emerald-400 font-bold">{(apkResult.confidence?.benign * 100).toFixed(0)}%</div>
                        <div className="text-zinc-500">Benign</div>
                      </div>
                    </div>

                    {/* Threat list */}
                    {apkResult.threats?.length > 0 ? (
                      <div className="space-y-2">
                        <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-2">Detected Signals ({apkResult.threats.length})</h4>
                        {apkResult.threats.map((t, i) => (
                          <div key={i} className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-xs">
                            <div className="flex items-center justify-between mb-1">
                              <span className="font-semibold text-zinc-200">{t.type}</span>
                              <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${t.severity === 'Critical' ? 'bg-rose-950/50 text-rose-400' : t.severity === 'High' ? 'bg-orange-950/50 text-orange-400' : t.severity === 'Medium' ? 'bg-amber-950/50 text-amber-400' : 'bg-zinc-700 text-zinc-300'}`}>
                                {t.severity}
                              </span>
                            </div>
                            <p className="text-zinc-500">{t.message}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-4">
                        <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                        <p className="text-emerald-400 text-sm font-semibold">No suspicious signals detected</p>
                        <p className="text-zinc-500 text-xs mt-1">APK filename appears clean</p>
                      </div>
                    )}
                  </div>
                )}

                {/* AI Scan Result Card (kmack/malicious-url-detection) */}
                {urlResult && (
                  <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6 shadow-2xl animate-in slide-in-from-right-4 duration-500">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <h3 className="text-lg font-bold text-zinc-900 dark:text-white">AI Scan Report</h3>
                        <p className="font-mono text-xs text-zinc-500 truncate max-w-[200px]">{urlResult.domain || urlResult.input}</p>
                        <p className="text-xs text-zinc-600 mt-0.5">Model: <span className="text-violet-400 font-medium">DistilBERT</span></p>
                      </div>
                      <span className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-wider ${urlResult.risk_level === 'High' ? 'bg-rose-950/40 text-rose-400' : urlResult.risk_level === 'Medium' ? 'bg-amber-950/40 text-amber-400' : 'bg-emerald-950/40 text-emerald-400'}`}>
                        {urlResult.risk_level} Risk
                      </span>
                    </div>

                    {/* Model Confidence Bar */}
                    <div className="mb-5">
                      <div className="flex justify-between text-xs text-zinc-500 mb-1">
                        <span>Malicious Confidence</span>
                        <span className="font-bold text-zinc-300">{((urlResult.confidence?.malicious ?? 0) * 100).toFixed(1)}%</span>
                      </div>
                      <div className="w-full bg-zinc-800 rounded-full h-2">
                        <div className={`h-2 rounded-full transition-all ${(urlResult.confidence?.malicious ?? 0) >= 0.55 ? 'bg-rose-500' : (urlResult.confidence?.malicious ?? 0) >= 0.25 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                          style={{ width: `${((urlResult.confidence?.malicious ?? 0) * 100).toFixed(1)}%` }} />
                      </div>
                    </div>

                    {/* Confidence pills */}
                    <div className="flex gap-3 mb-5 text-xs">
                      <div className="flex-1 bg-zinc-950 rounded-lg p-2 text-center">
                        <div className="text-rose-400 font-bold">{((urlResult.confidence?.malicious ?? 0) * 100).toFixed(1)}%</div>
                        <div className="text-zinc-500">Malicious</div>
                      </div>
                      <div className="flex-1 bg-zinc-950 rounded-lg p-2 text-center">
                        <div className="text-emerald-400 font-bold">{((urlResult.confidence?.benign ?? 0) * 100).toFixed(1)}%</div>
                        <div className="text-zinc-500">Benign</div>
                      </div>
                    </div>

                    {/* Model raw result */}
                    <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-xs">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-zinc-400 font-semibold">Raw Model Output</span>
                        <span className="text-zinc-500">{urlResult.ml_label}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-zinc-400">Confidence Score</span>
                        <span className="text-violet-400 font-bold">{urlResult.ml_score}</span>
                      </div>
                    </div>

                    {/* Clean result */}
                    {urlResult.risk_level === 'Low' && (
                      <div className="text-center py-3 mt-3">
                        <ShieldCheck className="w-7 h-7 text-emerald-400 mx-auto mb-1" />
                        <p className="text-emerald-400 text-sm font-semibold">URL appears safe</p>
                        <p className="text-zinc-500 text-xs mt-0.5">DistilBERT model classifies this as benign</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Result Card */}
                {result ? (
                  <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6 shadow-2xl animate-in slide-in-from-right-4 duration-500">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-lg font-bold text-zinc-900 dark:text-white">Scan Report</h3>
                      <div className={`px - 3 py - 1 rounded text - xs font - bold uppercase tracking - wider ${getRiskColor(result.risk_level)} `}>
                        {result.risk_level} Risk
                      </div>
                    </div>

                    <div className="flex justify-center mb-6">
                      <div className={`p - 4 rounded - full border - 2 ${getRiskColor(result.risk_level).replace('text-', 'border-').split(' ')[2]} bg - zinc - 950`}>
                        {getRiskIcon(result.risk_level)}
                      </div>
                    </div>

                    {/* Threat List */}
                    {result.threats && result.threats.length > 0 && (
                      <div className="mb-6 space-y-3">
                        <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider">Detected Threats</h4>
                        {result.threats.map((threat, idx) => (
                          <div key={idx} className="bg-rose-950/20 border border-rose-900/30 p-3 rounded-lg text-sm">
                            <div className="text-rose-400 font-semibold text-xs mb-1 flex items-center">
                              <AlertCircle className="w-3 h-3 mr-1" />
                              {threat.type}: {threat.value}
                            </div>
                            <div className="text-zinc-600 dark:text-zinc-400 text-xs">{threat.warning}</div>
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="space-y-3">
                      <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider">Confidence</h4>
                      {Object.entries(result.confidence).map(([level, score]) => (
                        <div key={level} className="flex items-center gap-3">
                          <span className="w-12 text-xs text-zinc-600 dark:text-zinc-400 text-right">{level}</span>
                          <div className="flex-1 bg-zinc-100 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className={`h - full rounded - full ${level === result.risk_level ? 'bg-white' : 'bg-zinc-600'} `}
                              style={{ width: `${score * 100}% ` }}
                            ></div>
                          </div>
                          <span className="w-8 text-xs font-mono text-zinc-500">{(score * 100).toFixed(0)}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-zinc-900/30 border border-zinc-200 dark:border-zinc-800/50 rounded-xl p-8 text-center text-zinc-600 border-dashed">
                    <Search className="w-12 h-12 mx-auto mb-3 opacity-20" />
                    <p className="text-sm">Ready to scan. Enter details manually or import from Play Store.</p>
                  </div>
                )}

                {/* Recent Scans */}
                <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-6">
                  <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300 mb-4 flex items-center">
                    <History className="w-4 h-4 mr-2" />
                    Recent Scans
                  </h3>
                  {recentScans.length === 0 ? (
                    <p className="text-xs text-zinc-600 italic">No history yet.</p>
                  ) : (
                    <div className="space-y-3">
                      {recentScans.map((scan, i) => (
                        <div key={i} className="flex justify-between items-center text-sm border-b border-zinc-200 dark:border-zinc-800 pb-2 last:border-0 last:pb-0">
                          <span className="text-zinc-600 dark:text-zinc-400 truncate max-w-[120px]">{scan.name}</span>
                          <span className={`text - xs px - 2 py - 0.5 rounded ${scan.risk === 'High' ? 'text-rose-400 bg-rose-950/30' :
                            scan.risk === 'Medium' ? 'text-amber-400 bg-amber-950/30' :
                              'text-emerald-400 bg-emerald-950/30'
                            } `}>
                            {scan.risk}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

              </div>
            </div>
          )}

          {activeTab === 'ghost-hunter' && (
            <div className="animate-in fade-in zoom-in-95 duration-300">
              <GhostPageScanner />
            </div>
          )}

          {activeTab === 'llm-firewall' && (
            <div className="animate-in fade-in zoom-in-95 duration-300">
              <LLMScanner />
            </div>
          )}

          {activeTab === 'code-lint' && (
            <div className="animate-in fade-in zoom-in-95 duration-300">
              <CodeScanner />
            </div>
          )}

          {activeTab === 'digital-footprint' && (
            <div className="animate-in fade-in zoom-in-95 duration-300">
              <DigitalFootprint />
            </div>
          )}
        </div>
      </div >
    </div >
  )
}

export default App
