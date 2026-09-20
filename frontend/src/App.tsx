import { useRef, useState, type ChangeEvent } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { analyzeEmail, type AnalysisResult } from "@/lib/api"
import { IpLocationMap } from "@/components/IpLocationMap"
import { useTheme } from "@/components/theme-provider"
import BlurText from "@/components/BlurText"
import ShinyText from "@/components/ShinyText"
import AnimatedContent from "@/components/AnimatedContent"
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
  CornerDownRight,
  Compass,
  Clock,
  Info,
  BrainCircuit,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  BarChart2,
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
  if (risk === "high")
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

function confidenceStyle(confidence: string) {
  if (confidence === "high")
    return "text-green-600 dark:text-green-400 bg-green-500/10 border-green-500/25"
  if (confidence === "medium")
    return "text-yellow-600 dark:text-yellow-400 bg-yellow-500/10 border-yellow-500/25"
  if (confidence === "low")
    return "text-orange-600 dark:text-orange-400 bg-orange-500/10 border-orange-500/25"
  return "text-muted-foreground bg-muted border-border"
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

// ── Phishing verdict banner ────────────────────────────────────────────────

function PhishingBanner({ verdict, confidence }: { verdict: string; confidence: number | null }) {
  if (verdict === "PHISHING") {
    return (
      <div className="flex items-center gap-3 rounded-none border border-destructive/40 bg-destructive/10 px-4 py-3">
        <ShieldAlert className="h-6 w-6 shrink-0 text-destructive" />
        <div>
          <p className="text-sm font-bold tracking-wide text-destructive uppercase">
            Phishing Detected
          </p>
          <p className="text-xs text-destructive/80">
            Model is {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"} confident this email is malicious.
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
            Model is uncertain ({confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"} phishing probability). Treat with caution.
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
            Model is {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"} confident this is not phishing.
          </p>
        </div>
      </div>
    )
  }
  // UNAVAILABLE
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

// ── main component ─────────────────────────────────────────────────────────

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const { theme, setTheme } = useTheme()

  const isDark =
    theme === "dark" ||
    (theme === "system" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches)

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

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-background text-foreground">
      {/* ── top bar ─────────────────────────────────────────────────────── */}
      <header className="flex h-12 shrink-0 items-center justify-between gap-3 border-b bg-card px-4">
        <div className="flex items-center gap-2.5">
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

              {/* Origin Assessment */}
              {result.origin_assessment && (
                <AnimatedContent distance={20} direction="horizontal" reverse duration={0.4} delay={0.2} threshold={0}>
                  <Panel title="Origin Assessment" icon={<Compass className="h-3.5 w-3.5" />} className="flex-none">
                    <div className="space-y-2">
                      <span className={cn(
                        "inline-flex items-center gap-1.5 rounded-none border px-2.5 py-0.5 text-xs font-semibold tracking-wide uppercase",
                        confidenceStyle(result.origin_assessment.confidence)
                      )}>
                        {result.origin_assessment.confidence} confidence
                      </span>
                      <p className="text-xs leading-relaxed text-muted-foreground">
                        {result.origin_assessment.verdict}
                      </p>
                      {result.sender_timezone && (
                        <div className="flex items-center gap-1.5 border-t pt-2">
                          <Clock className="h-3 w-3 shrink-0 text-muted-foreground" />
                          <span className="text-xs text-muted-foreground">
                            Device timezone: UTC{result.sender_timezone.utc_offset}
                            {result.sender_timezone.plausible_regions.length > 0 &&
                              ` (${result.sender_timezone.plausible_regions.join(", ")})`}
                          </span>
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
            CENTER — ML investigation results
            ════════════════════════════════════════════════════════════════ */}
        <main className="flex min-w-0 flex-1 flex-col gap-2 overflow-y-auto p-2">
          {error && (
            <Alert variant="destructive" className="shrink-0 py-2">
              <AlertDescription className="text-xs">{error}</AlertDescription>
            </Alert>
          )}

          {!result ? (
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

              {/* ── Verdict banner ── */}
              {result.phishing_analysis && (
                <PhishingBanner
                  verdict={result.phishing_analysis.verdict}
                  confidence={result.phishing_analysis.confidence}
                />
              )}

              {/* ── ML probability breakdown ── */}
              {result.phishing_analysis && result.phishing_analysis.verdict !== "UNAVAILABLE" && (
                <Panel title="ML Confidence Breakdown" icon={<BarChart2 className="h-3.5 w-3.5" />}>
                  <div className="space-y-3">
                    {result.phishing_analysis.phishing_probability != null && (
                      <div className="mx-auto w-full max-w-sm">
                        <Gauge
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
                  </div>
                </Panel>
              )}

              {/* ── Model info ── 
              <Panel title="Model" icon={<BrainCircuit className="h-3.5 w-3.5" />}>
                <div className="space-y-2 text-xs text-muted-foreground">
                  <p>
                    Logistic Regression trained on{" "}
                    <span className="font-medium text-foreground">82,486 emails</span> from 6 datasets
                    (CEAS, Enron, Ling, Nazario, SpamAssassin, Nigerian Fraud).
                  </p>
                  <p>
                    Uses a hybrid feature matrix:{" "}
                    <span className="font-medium text-foreground">TF-IDF</span> (10k token n-grams) +{" "}
                    <span className="font-medium text-foreground">32 structural signals</span> including
                    URL count, urgency phrase density, sender domain mismatch, HTML tag analysis,
                    and SPF/DKIM behavioral indicators.
                  </p>
                  <p className="border-t pt-2 text-[10px]">
                    <span className="font-medium">Test-set accuracy: 99%</span> · The model does not replace
                    manual forensic review — treat the SUSPICIOUS band as a prompt for deeper analysis.
                  </p>
                </div>
              </Panel>*/}

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
                <div className="space-y-2.5">
                  {result.relay_chain.map((hop, idx) => (
                    <div key={hop.hop} className="relative pl-4">
                      {idx < result.relay_chain.length - 1 && (
                        <span className="absolute top-5 left-1.5 h-[calc(100%+0.5rem)] w-px bg-border" />
                      )}
                      <span className={cn(
                        "absolute top-1 left-0 h-3 w-3 rounded-full border-2 bg-background",
                        idx === 0 ? "border-foreground" : "border-muted-foreground/40"
                      )} />
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-semibold">Hop {hop.hop}</span>
                          {hop.ip_candidates.map((ip) => (
                            <span key={ip} className="font-mono text-[10px] text-muted-foreground">{ip}</span>
                          ))}
                          {idx === 0 && (
                            <span className="ml-auto">
                              <CornerDownRight className="h-3 w-3 text-muted-foreground/50" />
                            </span>
                          )}
                        </div>
                        <p className="line-clamp-2 text-[10px] leading-tight break-all text-muted-foreground">
                          {hop.raw}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
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
