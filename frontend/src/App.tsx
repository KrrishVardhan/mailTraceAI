import { useEffect, useRef, useState, type ChangeEvent } from "react"
import logoUrls from "virtual:mailtrace-logo-manifest"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { analyzeEmail, type AnalysisResult, type LlmAnalysis } from "@/lib/api"
import { IpLocationMap } from "@/components/IpLocationMap"
import { RelayChainTimeline } from "@/components/RelayChainTimeline"
import { useTheme } from "@/components/theme-provider"
import BlurText from "@/components/BlurText"
import ShinyText from "@/components/ShinyText"
import AnimatedContent from "@/components/AnimatedContent"
import LatticeLoader from "@/components/LatticeLoader"
import ElectricLogo from "@/components/ElectricLogo"
import { Gauge } from "@/components/charts/gauge"
import {
  Upload,
  Shield,
  MapPin,
  Network,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Moon,
  Sun,
  Loader2,
  Mail,
  Compass,
  Clock,
  Info,
  BrainCircuit,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  BarChart2,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  FileSearch,
  Fingerprint,
  Database,
} from "lucide-react"
import { cn } from "@/lib/utils"

// ── helpers ────────────────────────────────────────────────────────────────

function authStatus(result: string) {
  if (result === "pass")
    return {
      icon: <CheckCircle2 className="h-3.5 w-3.5" />,
      cls: "text-green-600 dark:text-green-400 bg-green-500/10 border-green-500/25",
    }
  if (result === "fail" || result === "softfail")
    return {
      icon: <XCircle className="h-3.5 w-3.5" />,
      cls: "text-destructive bg-destructive/10 border-destructive/25",
    }
  return {
    icon: <AlertTriangle className="h-3.5 w-3.5" />,
    cls: "text-yellow-600 dark:text-yellow-400 bg-yellow-500/10 border-yellow-500/25",
  }
}

function riskStyle(risk: string) {
  if (risk === "high" || risk === "critical")
    return {
      cls: "text-destructive bg-destructive/10 border-destructive/30",
      pulse: true,
    }
  if (risk === "medium")
    return {
      cls: "text-yellow-600 dark:text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
      pulse: true,
    }
  return {
    cls: "text-green-600 dark:text-green-400 bg-green-500/10 border-green-500/30",
    pulse: false,
  }
}

// Compact titled panel
function Panel({
  title,
  icon,
  children,
  className,
  scrollable = false,
}: {
  title: string
  icon: React.ReactNode
  children: React.ReactNode
  className?: string
  scrollable?: boolean
}) {
  return (
    <div
      className={cn(
        "flex flex-col rounded-none border bg-card text-card-foreground shadow-sm",
        className
      )}
    >
      <div className="flex shrink-0 items-center gap-2 border-b px-3 py-2">
        <span className="text-muted-foreground">{icon}</span>
        <span className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">
          {title}
        </span>
      </div>
      <div className={cn("flex-1 p-3", scrollable && "overflow-y-auto")}>
        {children}
      </div>
    </div>
  )
}

// ── LLM Error notice ──────────────────────────────────────────────────────

function LlmErrorNotice() {
  return (
    <div className="flex items-center gap-2 rounded-none border border-yellow-500/30 bg-yellow-500/8 px-3 py-2">
      <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-yellow-600 dark:text-yellow-400" />
      <p className="text-xs text-yellow-700 dark:text-yellow-300">
        AI reasoning layer unavailable — showing ML classifier result only.
      </p>
    </div>
  )
}

// ── Agreement Badge ───────────────────────────────────────────────────────

function AgreementBadge({ llmAnalysis }: { llmAnalysis: LlmAnalysis }) {
  const [expanded, setExpanded] = useState(false)

  if (llmAnalysis.ml_agreement === "unavailable") return null

  const isAgree = llmAnalysis.ml_agreement === "agree"

  return (
    <div className="flex flex-col gap-1">
      <button
        onClick={() => setExpanded((v) => !v)}
        className={cn(
          "inline-flex items-center gap-1.5 self-start rounded-none border px-2.5 py-1 text-xs font-medium transition-colors",
          isAgree
            ? "border-green-500/40 bg-green-500/10 text-green-700 dark:text-green-400 hover:bg-green-500/20"
            : "border-yellow-500/40 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 hover:bg-yellow-500/20"
        )}
      >
        {isAgree ? (
          <CheckCircle2 className="h-3 w-3" />
        ) : (
          <AlertTriangle className="h-3 w-3" />
        )}
        {isAgree ? "ML & LLM agree" : "Models disagree"}
        {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </button>

      {expanded && llmAnalysis.agreement_explanation && (
        <div
          className={cn(
            "rounded-none border px-3 py-2 text-xs leading-relaxed",
            isAgree
              ? "border-green-500/20 bg-green-500/5 text-green-800 dark:text-green-300"
              : "border-yellow-500/20 bg-yellow-500/5 text-yellow-800 dark:text-yellow-300"
          )}
        >
          {llmAnalysis.agreement_explanation}
        </div>
      )}
    </div>
  )
}

// ── Primary verdict banner (LLM-driven) ────────────────────────────────────

function VerdictBanner({
  result,
}: {
  result: AnalysisResult
}) {
  const llm = result.llm_analysis

  // If LLM errored, fall back to the existing ML-only banner behaviour
  if (llm?.llm_error) {
    return (
      <div className="flex flex-col gap-2">
        <LlmErrorNotice />
        <MlFallbackBanner
          verdict={result.phishing_analysis.verdict}
          confidence={result.phishing_analysis.confidence}
        />
      </div>
    )
  }

  const verdict = llm?.llm_verdict ?? null
  const confidence = llm?.llm_confidence ?? null
  const summary = llm?.reasoning_summary ?? ""

  if (verdict === "phishing") {
    return (
      <div className="flex flex-col gap-2">
        <div className="flex items-start gap-3 rounded-none border border-destructive/40 bg-destructive/10 px-4 py-3">
          <ShieldAlert className="mt-0.5 h-6 w-6 shrink-0 text-destructive" />
          <div className="flex-1 space-y-1">
            <div className="flex items-center gap-2">
              <p className="text-sm font-bold tracking-wide text-destructive uppercase">
                Phishing Detected
              </p>
              {confidence != null && (
                <span className="text-xs font-semibold text-destructive/80">
                  {confidence}% confident
                </span>
              )}
              <span className="relative ml-auto flex h-2.5 w-2.5 shrink-0">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-destructive opacity-50" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-destructive" />
              </span>
            </div>
            {summary && (
              <p className="text-xs leading-relaxed text-destructive/80">{summary}</p>
            )}
          </div>
        </div>
        <AgreementBadge llmAnalysis={llm} />
      </div>
    )
  }

  if (verdict === "suspicious") {
    return (
      <div className="flex flex-col gap-2">
        <div className="flex items-start gap-3 rounded-none border border-yellow-500/40 bg-yellow-500/10 px-4 py-3">
          <ShieldQuestion className="mt-0.5 h-6 w-6 shrink-0 text-yellow-600 dark:text-yellow-400" />
          <div className="flex-1 space-y-1">
            <div className="flex items-center gap-2">
              <p className="text-sm font-bold tracking-wide text-yellow-600 dark:text-yellow-400 uppercase">
                Suspicious — Review Manually
              </p>
              {confidence != null && (
                <span className="text-xs font-semibold text-yellow-600/80 dark:text-yellow-400/80">
                  {confidence}% suspicious
                </span>
              )}
              <span className="relative ml-auto flex h-2.5 w-2.5 shrink-0">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-yellow-500 opacity-50" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-yellow-500" />
              </span>
            </div>
            {summary && (
              <p className="text-xs leading-relaxed text-yellow-700/80 dark:text-yellow-300/80">
                {summary}
              </p>
            )}
          </div>
        </div>
        <AgreementBadge llmAnalysis={llm} />
      </div>
    )
  }

  if (verdict === "legitimate") {
    return (
      <div className="flex flex-col gap-2">
        <div className="flex items-start gap-3 rounded-none border border-green-500/40 bg-green-500/10 px-4 py-3">
          <ShieldCheck className="mt-0.5 h-6 w-6 shrink-0 text-green-600 dark:text-green-400" />
          <div className="flex-1 space-y-1">
            <div className="flex items-center gap-2">
              <p className="text-sm font-bold tracking-wide text-green-600 dark:text-green-400 uppercase">
                Appears Legitimate
              </p>
              {confidence != null && (
                <span className="text-xs font-semibold text-green-600/80 dark:text-green-400/80">
                  {confidence}% confident
                </span>
              )}
            </div>
            {summary && (
              <p className="text-xs leading-relaxed text-green-700/80 dark:text-green-300/80">
                {summary}
              </p>
            )}
          </div>
        </div>
        <AgreementBadge llmAnalysis={llm} />
      </div>
    )
  }

  // null / unknown verdict — fall back to ML banner
  return (
    <MlFallbackBanner
      verdict={result.phishing_analysis.verdict}
      confidence={result.phishing_analysis.confidence}
    />
  )
}

// ── ML-only fallback banner (used when LLM errored or verdict is null) ────

function MlFallbackBanner({
  verdict,
  confidence,
}: {
  verdict: string
  confidence: number | null
}) {
  if (verdict === "PHISHING") {
    return (
      <div className="flex items-center gap-3 rounded-none border border-destructive/40 bg-destructive/10 px-4 py-3">
        <ShieldAlert className="h-6 w-6 shrink-0 text-destructive" />
        <div>
          <p className="text-sm font-bold tracking-wide text-destructive uppercase">
            Phishing Detected
          </p>
          <p className="text-xs text-destructive/80">
            ML model is {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"} confident this email is malicious.
          </p>
        </div>
        <span className="relative ml-auto flex h-2.5 w-2.5 shrink-0">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-destructive opacity-50" />
          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-destructive" />
        </span>
      </div>
    )
  }
  if (verdict === "SUSPICIOUS") {
    return (
      <div className="flex items-center gap-3 rounded-none border border-yellow-500/40 bg-yellow-500/10 px-4 py-3">
        <ShieldQuestion className="h-6 w-6 shrink-0 text-yellow-600 dark:text-yellow-400" />
        <div>
          <p className="text-sm font-bold tracking-wide text-yellow-600 dark:text-yellow-400 uppercase">
            Suspicious — Review Manually
          </p>
          <p className="text-xs text-yellow-600/80 dark:text-yellow-400/80">
            ML model is uncertain ({confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"} phishing probability). Treat with caution.
          </p>
        </div>
        <span className="relative ml-auto flex h-2.5 w-2.5 shrink-0">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-yellow-500 opacity-50" />
          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-yellow-500" />
        </span>
      </div>
    )
  }
  if (verdict === "LEGITIMATE") {
    return (
      <div className="flex items-center gap-3 rounded-none border border-green-500/40 bg-green-500/10 px-4 py-3">
        <ShieldCheck className="h-6 w-6 shrink-0 text-green-600 dark:text-green-400" />
        <div>
          <p className="text-sm font-bold tracking-wide text-green-600 dark:text-green-400 uppercase">
            Appears Legitimate
          </p>
          <p className="text-xs text-green-600/80 dark:text-green-400/80">
            ML model is {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"} confident this is not phishing.
          </p>
        </div>
      </div>
    )
  }
  return (
    <div className="flex items-center gap-3 rounded-none border border-border bg-muted/30 px-4 py-3">
      <ShieldQuestion className="h-6 w-6 shrink-0 text-muted-foreground" />
      <div>
        <p className="text-sm font-bold tracking-wide text-muted-foreground uppercase">
          ML Analysis Unavailable
        </p>
        <p className="text-xs text-muted-foreground/70">Model could not be loaded.</p>
      </div>
    </div>
  )
}

// ── AI Reasoning card ─────────────────────────────────────────────────────

function AiReasoningCard({ llmAnalysis }: { llmAnalysis: LlmAnalysis }) {
  if (llmAnalysis.llm_error) return null

  const hasEvidence =
    llmAnalysis.evidence.length > 0 &&
    !(llmAnalysis.evidence.length === 1 && llmAnalysis.evidence[0] === "no significant indicators found")

  return (
    <Panel title="AI Reasoning" icon={<BrainCircuit className="h-3.5 w-3.5" />}>
      <ul className="space-y-1.5">
        {hasEvidence ? (
          llmAnalysis.evidence.map((item, i) => (
            <li key={i} className="flex items-start gap-2 text-xs text-foreground">
              <span className="mt-0.5 shrink-0 text-muted-foreground">•</span>
              <span>{item}</span>
            </li>
          ))
        ) : (
          <li className="flex items-start gap-2 text-xs text-muted-foreground">
            <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-green-500" />
            No significant indicators found
          </li>
        )}
      </ul>
    </Panel>
  )
}

// ── Synthesis footer ──────────────────────────────────────────────────────

function SynthesisFooter({ result }: { result: AnalysisResult }) {
  const llm = result.llm_analysis
  if (llm?.llm_error || !llm?.agreement_explanation) return null

  // Look for a geolocation masking note to include
  const maskingNote = result.geolocation
    .find((g) => g.status === "success" && g.masking?.likely_masked)
    ?.masking?.note

  const agreementLabel =
    llm.ml_agreement === "agree"
      ? `LLM and ML agree (${llm.llm_confidence ?? "—"}%)`
      : llm.ml_agreement === "partial"
        ? `LLM and ML partially agree (${llm.llm_confidence ?? "—"}%)`
        : `LLM and ML disagree (${llm.llm_confidence ?? "—"}% LLM confidence)`

  const parts = [agreementLabel]
  if (maskingNote) parts.push(maskingNote)

  return (
    <div className="flex items-start gap-2 border-t pt-2">
      <Info className="mt-0.5 h-3 w-3 shrink-0 text-muted-foreground" />
      <p className="text-[11px] leading-relaxed text-muted-foreground">
        {parts.join("; ")}
      </p>
    </div>
  )
}

// ── Probability bar ────────────────────────────────────────────────────────

function ProbBar({
  label,
  value,
  colorClass,
}: {
  label: string
  value: number | null
  colorClass: string
}) {
  const pct = value != null ? Math.round(value * 100) : 0
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">{label}</span>
        <span className="text-xs font-semibold tabular-nums">{pct}%</span>
      </div>
      <div className="h-1.5 w-full rounded-none bg-muted overflow-hidden">
        <div
          className={cn("h-full transition-all duration-700", colorClass)}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}

const electricLogoPalettes = [
  { color: "#84CC16", glowColor: "#84CC16" },
  { color: "#22C55E", glowColor: "#16A34A" },
  { color: "#14B8A6", glowColor: "#0D9488" },
  { color: "#06B6D4", glowColor: "#0891B2" },
  { color: "#A3E635", glowColor: "#65A30D" },
]

function RotatingElectricLogo({ isDark }: { isDark: boolean }) {
  const [logoIndex, setLogoIndex] = useState(0)
  const [paletteIndex, setPaletteIndex] = useState(0)

  useEffect(() => {
    if (logoUrls.length < 2) return

    const interval = window.setInterval(() => {
      setLogoIndex((current) => (current + 1) % logoUrls.length)
      setPaletteIndex(
        (current) => (current + 1) % electricLogoPalettes.length
      )
    }, 3000)

    return () => window.clearInterval(interval)
  }, [])

  const palette = electricLogoPalettes[paletteIndex]

  return (
    <ElectricLogo
      src={logoUrls[logoIndex]}
      color={palette.color}
      glowColor={palette.glowColor}
      scale={0.7}
      strands={3}
      bend={0.6}
      crackle={1.5}
      arcs={0}
      speed={1.5}
      interactive
      intensity={1}
      glow={0.3}
      thickness={0.5}
      flicker={0.1}
      fill={0}
      cursorIntensity={0.75}
      cursorRadius={100}
      theme={isDark ? "dark" : "light"}
    />
  )
}

function LandingPage({
  isDark,
  onThemeToggle,
  onOpenAnalyzer,
  onGoHome,
}: {
  isDark: boolean
  onThemeToggle: () => void
  onOpenAnalyzer: () => void
  onGoHome: () => void
}) {
  return (
    <div className="min-h-screen overflow-auto bg-background text-foreground">
      <header className="mx-auto flex h-16 max-w-6xl items-center justify-between border-b px-5 lg:px-8">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center bg-foreground text-background">
            <Mail className="h-4 w-4" />
          </div>
          <button
            type="button"
            onClick={onGoHome}
            className="text-sm font-semibold tracking-tight"
          >
            mailTraceAI
          </button>
        </div>
        <Button variant="ghost" size="icon" onClick={onThemeToggle} aria-label="Toggle theme">
          {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </header>

      <main className="mx-auto max-w-6xl px-5 py-16 lg:px-8 lg:py-24">
        <div className="grid items-center gap-10 lg:grid-cols-[1fr_0.85fr]">
          <section className="max-w-2xl">
            <div className="mb-5 inline-flex items-center gap-2 border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground">
              <ShieldCheck className="h-3.5 w-3.5 text-green-600 dark:text-green-400" />
              Email forensics, made clear
            </div>
            <h1 className="text-4xl leading-tight font-semibold tracking-tight sm:text-5xl lg:text-6xl">
              Trace the signals behind every email.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-muted-foreground">
              mailTraceAI turns a raw <span className="font-mono text-sm">.eml</span> file into a focused investigation. Inspect authentication, relay infrastructure, phishing signals, and AI reasoning in one place.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button size="lg" onClick={onOpenAnalyzer}>
                Open analyzer
                <ArrowRight className="h-4 w-4" />
              </Button>
              <span className="text-xs text-muted-foreground">Upload stays in your investigation workspace</span>
            </div>
          </section>

          <div className="h-72 w-full sm:h-96 lg:h-105">
            <RotatingElectricLogo isDark={isDark} />
          </div>
        </div>

        <Card className="mt-14 border-border bg-card shadow-lg">
            <CardHeader className="border-b">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs tracking-widest text-muted-foreground uppercase">
                  Investigation flow
                </CardTitle>
                <span className="h-2 w-2 animate-pulse bg-green-500" />
              </div>
            </CardHeader>
            <CardContent className="space-y-3 pt-5">
              {[
                { icon: FileSearch, label: "Parse the raw message", detail: "Headers, MIME body, and received hops" },
                { icon: Fingerprint, label: "Verify the evidence", detail: "SPF, DKIM, DMARC, and origin signals" },
                { icon: BrainCircuit, label: "Synthesize a verdict", detail: "ML probability plus Groq-powered reasoning" },
                { icon: Database, label: "Keep the case available", detail: "Cached results and investigation history" },
              ].map(({ icon: Icon, label, detail }, index) => (
                <div key={label} className="flex items-start gap-3 border-b pb-3 last:border-0 last:pb-0">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center border bg-background text-muted-foreground">
                    <Icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium">
                      <span className="mr-2 font-mono text-xs text-muted-foreground">0{index + 1}</span>
                      {label}
                    </p>
                    <p className="mt-0.5 text-xs text-muted-foreground">{detail}</p>
                  </div>
                </div>
              ))}
            </CardContent>
        </Card>

        <div className="mt-20 grid gap-3 border-t pt-6 sm:grid-cols-3">
          <div>
            <p className="text-sm font-medium">Header intelligence</p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">Understand where a message travelled and which checks passed.</p>
          </div>
          <div>
            <p className="text-sm font-medium">Two-layer analysis</p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">Compare the local phishing classifier with an LLM investigation.</p>
          </div>
          <div>
            <p className="text-sm font-medium">Built for review</p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">Return to previous cases without running the analysis again.</p>
          </div>
        </div>
      </main>
    </div>
  )
}

// ── main component ─────────────────────────────────────────────────────────

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [route, setRoute] = useState(() => window.location.pathname)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const { theme, setTheme } = useTheme()

  const isDark =
    theme === "dark" ||
    (theme === "system" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches)

  useEffect(() => {
    const handlePopState = () => setRoute(window.location.pathname)
    window.addEventListener("popstate", handlePopState)
    return () => window.removeEventListener("popstate", handlePopState)
  }, [])

  const navigate = (path: string) => {
    window.history.pushState({}, "", path)
    setRoute(path)
  }

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    setFile(e.target.files?.[0] ?? null)
    setResult(null)
    setError(null)
  }

  const handleAnalyze = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      const data = await analyzeEmail(file)
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong")
    } finally {
      setLoading(false)
    }
  }

  const risk = result ? riskStyle(result.authentication.risk_level) : null

  if (route === "/" || route === "") {
    return (
      <LandingPage
        isDark={isDark}
        onThemeToggle={() => setTheme(isDark ? "light" : "dark")}
        onOpenAnalyzer={() => navigate("/analyse")}
        onGoHome={() => navigate("/")}
      />
    )
  }

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-background text-foreground">
      {/* ── top bar ─────────────────────────────────────────────────────── */}
      <header className="flex h-12 shrink-0 items-center justify-between gap-3 border-b bg-card px-4">
        <div className="flex items-center gap-2.5">
        <button
          type="button"
          onClick={() => navigate("/")}
          className="flex items-center gap-2.5"
          aria-label="Go to mailTraceAI home"
        >
          <div className="flex h-7 w-7 items-center justify-center rounded-none bg-foreground text-background">
            <Mail className="h-4 w-4" />
          </div>
          <BlurText
            text="mailTraceAI"
            className="text-sm font-semibold tracking-tight"
            animateBy="letters"
            delay={60}
            direction="top"
          />
        </button>
          <span className="hidden sm:flex">
            <ShinyText
              text="Forensics Dashboard"
              className="text-xs text-muted-foreground"
              speed={4}
              color="currentColor"
              shineColor="white"
              spread={90}
            />
          </span>
        </div>

        <div className="flex items-center gap-2">
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml"
            onChange={handleFileChange}
            className="hidden"
          />
          <Button
            variant="outline"
            size="sm"
            className="h-7 gap-1.5 text-xs"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="h-3.5 w-3.5" />
            {file ? (
              <span className="max-w-35 truncate">{file.name}</span>
            ) : (
              "Upload .eml"
            )}
          </Button>
          <Button
            size="sm"
            className="h-7 text-xs"
            disabled={!file || loading}
            onClick={handleAnalyze}
          >
            {loading ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> Analyzing…
              </>
            ) : (
              "Analyze"
            )}
          </Button>

          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => setTheme(isDark ? "light" : "dark")}
          >
            {isDark ? (
              <Sun className="h-3.5 w-3.5" />
            ) : (
              <Moon className="h-3.5 w-3.5" />
            )}
          </Button>
        </div>
      </header>

      {/* ── body ────────────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">

        {/* ════════════════════════════════════════════════════════════════
            LEFT SIDEBAR — technical evidence
            ════════════════════════════════════════════════════════════════ */}
        <aside className="flex w-64 shrink-0 flex-col gap-2 overflow-y-auto border-r p-2">
          {result ? (
            <>
              {/* Email metadata */}
              <AnimatedContent distance={20} direction="horizontal" reverse duration={0.4} delay={0} threshold={0}>
                <Panel title="Email" icon={<Mail className="h-3.5 w-3.5" />} className="flex-none">
                  <div className="space-y-1.5">
                    <div>
                      <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">Subject</p>
                      <p className="line-clamp-2 text-xs leading-tight font-medium">
                        {result.headers.subject || "(no subject)"}
                      </p>
                    </div>
                    <div>
                      <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">From</p>
                      <p className="truncate text-xs text-muted-foreground">{result.headers.from ?? "—"}</p>
                    </div>
                    {result.headers.reply_to && result.headers.reply_to !== result.headers.from && (
                      <div>
                        <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">Reply-To</p>
                        <p className="truncate text-xs text-muted-foreground">{result.headers.reply_to}</p>
                      </div>
                    )}
                    {result.headers.return_path && (
                      <div>
                        <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">Return-Path</p>
                        <p className="truncate text-xs text-muted-foreground">{result.headers.return_path}</p>
                      </div>
                    )}
                  </div>
                </Panel>
              </AnimatedContent>

              {/* Authentication */}
              <AnimatedContent distance={20} direction="horizontal" reverse duration={0.4} delay={0.05} threshold={0}>
                <Panel title="Authentication" icon={<Shield className="h-3.5 w-3.5" />} className="flex-none">
                  <div className="space-y-2">
                    <div className="flex items-center gap-1.5">
                      <span className={cn(
                        "inline-flex items-center gap-1.5 rounded-none border px-2.5 py-0.5 text-xs font-semibold tracking-wide uppercase",
                        risk?.cls
                      )}>
                        {risk?.pulse && (
                          <span className="relative flex h-2 w-2 shrink-0">
                            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-50" />
                            <span className="relative inline-flex h-2 w-2 rounded-full bg-current" />
                          </span>
                        )}
                        {result.authentication.risk_level} risk
                      </span>
                    </div>
                    {(["spf", "dkim", "dmarc"] as const).map((key) => {
                      const val = result.authentication[key]
                      const s = authStatus(val)
                      return (
                        <div key={key} className="flex items-center justify-between">
                          <span className="text-xs font-medium tracking-wider text-muted-foreground uppercase">{key}</span>
                          <span className={cn("inline-flex items-center gap-1 rounded-none border px-2 py-0.5 text-xs font-medium", s.cls)}>
                            {s.icon}{val}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </Panel>
              </AnimatedContent>

              {/* Red flags */}
              {result.red_flags.length > 0 && (
                <AnimatedContent distance={20} direction="horizontal" reverse duration={0.4} delay={0.1} threshold={0}>
                  <Panel
                    title="Red Flags"
                    icon={<AlertTriangle className="h-3.5 w-3.5 text-destructive" />}
                    className="flex-none bg-destructive/10"
                  >
                    <ul className="space-y-1">
                      {result.red_flags.map((flag, i) => (
                        <li key={i} className="flex items-start gap-1.5 text-xs text-destructive">
                          <XCircle className="mt-0.5 h-3 w-3 shrink-0" />{flag}
                        </li>
                      ))}
                    </ul>
                  </Panel>
                </AnimatedContent>
              )}

              {/* Origin IPs */}
              <AnimatedContent distance={20} direction="horizontal" reverse duration={0.4} delay={0.15} threshold={0}>
                <Panel title="Origin IPs" icon={<MapPin className="h-3.5 w-3.5" />} className="flex-none">
                  {result.probable_origin_ips.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {result.probable_origin_ips.map((ip) => (
                        <Badge key={ip} variant="outline" className="font-mono text-xs">{ip}</Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">No IP found in relay chain</p>
                  )}
                </Panel>
              </AnimatedContent>

              {/* Origin Intelligence */}
              {(result.geolocation.some((g) => g.status === "success") || result.sender_timezone) && (
                <AnimatedContent distance={20} direction="horizontal" reverse duration={0.4} delay={0.2} threshold={0}>
                  <Panel title="Origin Intelligence" icon={<Compass className="h-3.5 w-3.5" />} className="flex-none">
                    <div className="space-y-2">
                      {result.geolocation
                        .filter((g) => g.status === "success")
                        .slice(0, 1)
                        .map((geo) => (
                          <div key={geo.query} className="space-y-1.5">
                            <div>
                              <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">IP Address</p>
                              <p className="font-mono text-xs text-foreground">{geo.query}</p>
                            </div>
                            {(geo.city || geo.regionName || geo.country) && (
                              <div>
                                <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">Geolocation</p>
                                <p className="text-xs text-foreground">
                                  {[geo.city, geo.regionName, geo.country].filter(Boolean).join(", ")}
                                </p>
                              </div>
                            )}
                            {(geo.org || geo.isp || geo.as) && (
                              <div>
                                <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">Network / Provider</p>
                                <p className="text-xs text-foreground break-words">{geo.org || geo.isp}</p>
                                {geo.as && (
                                  <p className="font-mono text-[10px] text-muted-foreground">{geo.as}</p>
                                )}
                              </div>
                            )}
                            <div>
                              <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">Provider Infrastructure</p>
                              <p className="text-xs text-foreground">
                                {geo.masking?.likely_masked
                                  ? "Yes — IP belongs to provider relay infrastructure"
                                  : geo.hosting
                                    ? "Datacenter / hosting IP"
                                    : "Not identified as provider infrastructure"}
                              </p>
                            </div>
                          </div>
                        ))}
                      {result.sender_timezone && (
                        <div className={cn(
                          "flex items-start gap-1.5",
                          result.geolocation.some((g) => g.status === "success") && "border-t pt-2"
                        )}>
                          <Clock className="mt-0.5 h-3 w-3 shrink-0 text-muted-foreground" />
                          <div>
                            <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">Observed Timezone</p>
                            <p className="text-xs text-foreground">
                              UTC{result.sender_timezone.utc_offset}
                              {result.sender_timezone.plausible_regions.length > 0 &&
                                ` · ${result.sender_timezone.plausible_regions.join(", ")}`}
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  </Panel>
                </AnimatedContent>
              )}
            </>
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-3 px-4 text-center text-muted-foreground">
              <Upload className="h-8 w-8 opacity-30" />
              <p className="text-xs opacity-60">Upload a .eml file and click Analyze to inspect it.</p>
            </div>
          )}
        </aside>

        {/* ════════════════════════════════════════════════════════════════
            CENTER — LLM + ML investigation results
            ════════════════════════════════════════════════════════════════ */}
        <main className="flex min-w-0 flex-1 flex-col gap-2 overflow-y-auto p-2">
          {error && (
            <Alert variant="destructive" className="shrink-0 py-2">
              <AlertDescription className="text-xs">{error}</AlertDescription>
            </Alert>
          )}

          {loading ? (
            <div className="flex flex-1 items-center justify-center">
              <LatticeLoader
                label="Thinking..."
                pattern="rain"
                glow
                showTimer={true}
                grid={4}
                color="currentColor"
                className="text-muted-foreground"
              />
            </div>
          ) : !result ? (
            <div className="flex flex-1 items-center justify-center text-center">
              <AnimatedContent distance={24} direction="vertical" duration={0.5} threshold={0}>
                <div className="space-y-3">
                  <div className="mx-auto flex h-14 w-14 items-center justify-center border-2 border-dashed opacity-20">
                    <Mail className="h-7 w-7" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">No analysis yet</p>
                    <p className="mt-1 text-xs text-muted-foreground/60">
                      Upload a .eml and hit Analyze to trace its origin.
                    </p>
                  </div>
                </div>
              </AnimatedContent>
            </div>
          ) : (
            <AnimatedContent distance={16} direction="vertical" duration={0.4} delay={0.1} threshold={0} className="flex flex-col gap-2">

              {/* ── Primary verdict banner (LLM-driven, ML fallback) ── */}
              {result.phishing_analysis && (
                <VerdictBanner result={result} />
              )}

              {/* ── AI Reasoning card (evidence bullet points) ── */}
              {result.llm_analysis && !result.llm_analysis.llm_error && (
                <AiReasoningCard llmAnalysis={result.llm_analysis} />
              )}

              {/* ── ML Classifier (supporting signal) ── */}
              {result.phishing_analysis && result.phishing_analysis.verdict !== "UNAVAILABLE" && (
                <Panel title="ML Classifier (supporting signal)" icon={<BarChart2 className="h-3.5 w-3.5" />}>
                  <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)] md:items-center">
                    {result.phishing_analysis.phishing_probability != null && (
                      <div className="mx-auto w-full max-w-[220px]">
                        <Gauge
                          width={220}
                          height={168}
                          value={result.phishing_analysis.phishing_probability * 100}
                          centerValue={result.phishing_analysis.phishing_probability * 100}
                          defaultLabel={result.phishing_analysis.verdict}
                          suffix="%"
                          activeGradient={
                            result.phishing_analysis.phishing_probability > 0.7
                              ? ["#ef4444", "#ef4444"]
                              : result.phishing_analysis.phishing_probability > 0.3
                                ? ["#eab308", "#eab308"]
                                : ["#22c55e", "#22c55e"]
                          }
                          inactiveGradient={
                            result.phishing_analysis.phishing_probability > 0.7
                              ? ["#ef4444", "#ef4444"]
                              : result.phishing_analysis.phishing_probability > 0.3
                                ? ["#eab308", "#eab308"]
                                : ["#22c55e", "#22c55e"]
                          }
                          inactiveFillOpacity={0.4}
                          useGradient
                        />
                      </div>
                    )}
                    <div className="min-w-0 space-y-3">
                      <ProbBar
                        label="Phishing probability"
                        value={result.phishing_analysis.phishing_probability}
                        colorClass="bg-destructive"
                      />
                      <ProbBar
                        label="Legitimate probability"
                        value={result.phishing_analysis.legitimate_probability}
                        colorClass="bg-green-500"
                      />
                      {result.phishing_analysis.threshold_used && (
                        <div className="flex flex-wrap gap-x-4 gap-y-1 border-t pt-2">
                          <p className="text-[10px] text-muted-foreground">
                            <span className="font-medium">Phishing threshold:</span>{" "}
                            ≥ {(result.phishing_analysis.threshold_used.phishing_above * 100).toFixed(0)}%
                          </p>
                          <p className="text-[10px] text-muted-foreground">
                            <span className="font-medium">Legitimate threshold:</span>{" "}
                            ≤ {(result.phishing_analysis.threshold_used.legitimate_below * 100).toFixed(0)}%
                          </p>
                          <p className="text-[10px] text-muted-foreground">
                            Between thresholds → <span className="font-medium text-yellow-600 dark:text-yellow-400">SUSPICIOUS</span>
                          </p>
                        </div>
                      )}

                      {/* Synthesis footer */}
                      <SynthesisFooter result={result} />
                    </div>
                  </div>
                </Panel>
              )}

              {/* ── Geolocation metadata (non-map) ── */}
              {result.geolocation.some((g) => g.status === "success") && (
                <Panel title="Geolocation Details" icon={<MapPin className="h-3.5 w-3.5" />}>
                  <div className="space-y-2">
                    {result.geolocation
                      .filter((g) => g.status === "success")
                      .map((geo) => (
                        <div key={geo.query} className="flex flex-wrap items-center gap-2">
                          <Badge variant="outline" className="font-mono text-xs">{geo.query}</Badge>
                          <span className="text-xs text-muted-foreground">
                            {[geo.city, geo.regionName, geo.country].filter(Boolean).join(", ")}
                          </span>
                          {(geo.isp || geo.org) && (
                            <span className="text-xs text-muted-foreground">· {geo.org ?? geo.isp}</span>
                          )}
                          {geo.hosting && <Badge variant="secondary" className="text-xs">datacenter</Badge>}
                          {geo.proxy && <Badge variant="destructive" className="text-xs">proxy/VPN</Badge>}
                          {geo.masking?.likely_masked && (
                            <Badge
                              variant="outline"
                              className="gap-1 border-yellow-500/40 text-xs text-yellow-600 dark:text-yellow-400"
                              title={geo.masking.note ?? undefined}
                            >
                              <Info className="h-3 w-3" />
                              provider infra — not sender location
                            </Badge>
                          )}
                        </div>
                      ))}
                  </div>
                </Panel>
              )}

            </AnimatedContent>
          )}
        </main>

        {/* ════════════════════════════════════════════════════════════════
            RIGHT SIDEBAR — Relay Chain + compact map
            ════════════════════════════════════════════════════════════════ */}
        {result && (
          <aside className="flex w-80 shrink-0 flex-col gap-2 overflow-hidden border-l p-2">

            {/* Relay Chain — grows to fill available space */}
            <AnimatedContent distance={16} direction="horizontal" duration={0.4} delay={0.2} threshold={0} className="flex min-h-0 flex-1 flex-col overflow-hidden">
              <Panel
                title={`Relay Chain · ${result.relay_chain.length} hops`}
                icon={<Network className="h-3.5 w-3.5" />}
                className="flex-1 overflow-hidden"
                scrollable
              >
                <RelayChainTimeline
                  relayChain={result.relay_chain}
                  geoResults={result.geolocation}
                />
              </Panel>
            </AnimatedContent>

            {/* Compact map — fixed height at bottom of right sidebar */}
            {result.geolocation.some(
              (g) => g.status === "success" && g.lat != null && g.lon != null
            ) && (
              <AnimatedContent distance={16} direction="horizontal" duration={0.4} delay={0.3} threshold={0} className="shrink-0">
                {result.geolocation
                  .filter((g) => g.status === "success" && g.lat != null && g.lon != null)
                  .slice(0, 1)
                  .map((geo) => (
                    <div key={geo.query} className="flex flex-col overflow-hidden border">
                      <div className="flex items-center gap-1.5 border-b bg-card px-3 py-1.5">
                        <MapPin className="h-3 w-3 text-muted-foreground" />
                        <span className="text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">
                          Origin Map
                        </span>
                        <span className="ml-auto font-mono text-[10px] text-muted-foreground">{geo.query}</span>
                      </div>
                      <div className="h-44 w-full">
                        <IpLocationMap
                          lat={geo.lat!}
                          lon={geo.lon!}
                          label={`${geo.query} — ${geo.org ?? geo.isp ?? "Unknown"}`}
                        />
                      </div>
                    </div>
                  ))}
              </AnimatedContent>
            )}

          </aside>
        )}
      </div>
    </div>
  )
}
