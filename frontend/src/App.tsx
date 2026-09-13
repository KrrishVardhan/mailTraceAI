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

// Confidence styling for the Origin Assessment panel — reuses the same
// visual language as risk badges (green/yellow/destructive/muted) so it
// reads as part of the same system rather than a one-off.
function confidenceStyle(confidence: string) {
  if (confidence === "high")
    return "text-green-600 dark:text-green-400 bg-green-500/10 border-green-500/25"
  if (confidence === "medium")
    return "text-yellow-600 dark:text-yellow-400 bg-yellow-500/10 border-yellow-500/25"
  if (confidence === "low")
    return "text-orange-600 dark:text-orange-400 bg-orange-500/10 border-orange-500/25"
  return "text-muted-foreground bg-muted border-border"
}

// Compact titled panel — replaces shadcn Card so we control padding tightly
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
          {/* File picker */}
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
              <span className="max-w-[140px] truncate">{file.name}</span>
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

          {/* Dark mode toggle */}
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
        {/* ── left sidebar ──────────────────────────────────────────────── */}
        <aside className="flex w-64 shrink-0 flex-col gap-2 overflow-y-auto border-r p-2">
          {/* Email metadata */}
          {result ? (
            <AnimatedContent
              distance={20}
              direction="horizontal"
              reverse
              duration={0.4}
              delay={0}
              threshold={0}
            >
              <Panel
                title="Email"
                icon={<Mail className="h-3.5 w-3.5" />}
                className="flex-none"
              >
                <div className="space-y-1.5">
                  <div>
                    <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">
                      Subject
                    </p>
                    <p className="line-clamp-2 text-xs leading-tight font-medium">
                      {result.headers.subject || "(no subject)"}
                    </p>
                  </div>
                  <div>
                    <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">
                      From
                    </p>
                    <p className="truncate text-xs text-muted-foreground">
                      {result.headers.from ?? "—"}
                    </p>
                  </div>
                  {result.headers.reply_to &&
                    result.headers.reply_to !== result.headers.from && (
                      <div>
                        <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">
                          Reply-To
                        </p>
                        <p className="truncate text-xs text-muted-foreground">
                          {result.headers.reply_to}
                        </p>
                      </div>
                    )}
                  {result.headers.return_path && (
                    <div>
                      <p className="mb-0.5 text-[10px] tracking-wider text-muted-foreground uppercase">
                        Return-Path
                      </p>
                      <p className="truncate text-xs text-muted-foreground">
                        {result.headers.return_path}
                      </p>
                    </div>
                  )}
                </div>
              </Panel>
            </AnimatedContent>
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-3 px-4 text-center text-muted-foreground">
              <Upload className="h-8 w-8 opacity-30" />
              <p className="text-xs opacity-60">
                Upload a .eml file and click Analyze to inspect it.
              </p>
            </div>
          )}

          {/* Authentication */}
          {result && (
            <AnimatedContent
              distance={20}
              direction="horizontal"
              reverse
              duration={0.4}
              delay={0.05}
              threshold={0}
            >
              <Panel
                title="Authentication"
                icon={<Shield className="h-3.5 w-3.5" />}
                className="flex-none"
              >
                <div className="space-y-2">
                  {/* Risk badge */}
                  <div className="flex items-center gap-1.5">
                    <span
                      className={cn(
                        "inline-flex items-center gap-1.5 rounded-none border px-2.5 py-0.5 text-xs font-semibold tracking-wide uppercase",
                        risk?.cls
                      )}
                    >
                      {risk?.pulse && (
                        <span className="relative flex h-2 w-2 shrink-0">
                          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-50" />
                          <span className="relative inline-flex h-2 w-2 rounded-full bg-current" />
                        </span>
                      )}
                      {result.authentication.risk_level} risk
                    </span>
                  </div>

                  {/* SPF / DKIM / DMARC */}
                  {(["spf", "dkim", "dmarc"] as const).map((key) => {
                    const val = result.authentication[key]
                    const s = authStatus(val)
                    return (
                      <div
                        key={key}
                        className="flex items-center justify-between"
                      >
                        <span className="text-xs font-medium tracking-wider text-muted-foreground uppercase">
                          {key}
                        </span>
                        <span
                          className={cn(
                            "inline-flex items-center gap-1 rounded-none border px-2 py-0.5 text-xs font-medium",
                            s.cls
                          )}
                        >
                          {s.icon}
                          {val}
                        </span>
                      </div>
                    )
                  })}
                </div>
              </Panel>
            </AnimatedContent>
          )}

          {/* Red flags */}
          {result && result.red_flags.length > 0 && (
            <AnimatedContent
              distance={20}
              direction="horizontal"
              reverse
              duration={0.4}
              delay={0.1}
              threshold={0}
            >
              <Panel
                title="Red Flags"
                icon={
                  <AlertTriangle className="h-3.5 w-3.5 text-destructive" />
                }
                className="flex-none border-destructive/30"
              >
                <ul className="space-y-1">
                  {result.red_flags.map((flag, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-1.5 text-xs text-destructive"
                    >
                      <XCircle className="mt-0.5 h-3 w-3 shrink-0" />
                      {flag}
                    </li>
                  ))}
                </ul>
              </Panel>
            </AnimatedContent>
          )}

          {/* Origin IPs */}
          {result && (
            <AnimatedContent
              distance={20}
              direction="horizontal"
              reverse
              duration={0.4}
              delay={0.15}
              threshold={0}
            >
              <Panel
                title="Origin IPs"
                icon={<MapPin className="h-3.5 w-3.5" />}
                className="flex-none"
              >
                {result.probable_origin_ips.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {result.probable_origin_ips.map((ip) => (
                      <Badge
                        key={ip}
                        variant="outline"
                        className="font-mono text-xs"
                      >
                        {ip}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    No IP found in relay chain
                  </p>
                )}
              </Panel>
            </AnimatedContent>
          )}

          {/* Origin Assessment — synthesizes geolocation + timezone into
              one verdict with a confidence level, rather than leaving the
              user to mentally reconcile a masked IP against a timezone hint
              themselves. */}
          {result && result.origin_assessment && (
            <AnimatedContent
              distance={20}
              direction="horizontal"
              reverse
              duration={0.4}
              delay={0.2}
              threshold={0}
            >
              <Panel
                title="Origin Assessment"
                icon={<Compass className="h-3.5 w-3.5" />}
                className="flex-none"
              >
                <div className="space-y-2">
                  <span
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded-none border px-2.5 py-0.5 text-xs font-semibold tracking-wide uppercase",
                      confidenceStyle(result.origin_assessment.confidence)
                    )}
                  >
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
        </aside>

        {/* ── main content ──────────────────────────────────────────────── */}
        <main className="flex min-w-0 flex-1 flex-col gap-2 overflow-hidden p-2">
          {error && (
            <Alert variant="destructive" className="shrink-0 py-2">
              <AlertDescription className="text-xs">{error}</AlertDescription>
            </Alert>
          )}

          {!result ? (
            /* Empty state */
            <div className="flex flex-1 items-center justify-center text-center">
              <AnimatedContent
                distance={24}
                direction="vertical"
                duration={0.5}
                threshold={0}
              >
                <div className="space-y-3">
                  <div className="mx-auto flex h-14 w-14 items-center justify-center border-2 border-dashed opacity-20">
                    <Mail className="h-7 w-7" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">
                      No analysis yet
                    </p>
                    <p className="mt-1 text-xs text-muted-foreground/60">
                      Upload a .eml and hit Analyze to trace its origin.
                    </p>
                  </div>
                </div>
              </AnimatedContent>
            </div>
          ) : (
            /* Results — 2-column grid, map fills remaining height */
            <div className="flex flex-1 flex-col gap-2 overflow-hidden">
              {/* Top row: geo info + relay chain side by side */}
              <div className="flex min-h-0 flex-1 gap-2 overflow-hidden">
                {/* Geolocation + map */}
                <AnimatedContent
                  distance={16}
                  direction="vertical"
                  duration={0.4}
                  delay={0.1}
                  threshold={0}
                  className="flex min-w-0 flex-1 flex-col gap-2 overflow-hidden"
                >
                  {result.geolocation.length > 0 &&
                  result.geolocation.some((g) => g.status === "success") ? (
                    result.geolocation
                      .filter((g) => g.status === "success")
                      .map((geo) => (
                        <div
                          key={geo.query}
                          className="flex flex-1 flex-col gap-2 overflow-hidden"
                        >
                          {/* Geo metadata bar */}
                          <div className="flex shrink-0 flex-wrap items-center gap-2 px-1">
                            <Badge
                              variant="outline"
                              className="font-mono text-xs"
                            >
                              {geo.query}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {[geo.city, geo.regionName, geo.country]
                                .filter(Boolean)
                                .join(", ")}
                            </span>
                            {geo.isp || geo.org ? (
                              <span className="text-xs text-muted-foreground">
                                · {geo.org ?? geo.isp}
                              </span>
                            ) : null}
                            {geo.hosting && (
                              <Badge variant="secondary" className="text-xs">
                                datacenter
                              </Badge>
                            )}
                            {geo.proxy && (
                              <Badge variant="destructive" className="text-xs">
                                proxy/VPN
                              </Badge>
                            )}
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
                          {/* Map fills remaining */}
                          {geo.lat != null && geo.lon != null && (
                            <div className="min-h-0 flex-1 overflow-hidden border">
                              <IpLocationMap
                                lat={geo.lat}
                                lon={geo.lon}
                                label={`${geo.query} — ${geo.org ?? geo.isp ?? "Unknown"}`}
                              />
                            </div>
                          )}
                        </div>
                      ))
                  ) : (
                    <div className="flex flex-1 items-center justify-center border border-dashed text-xs text-muted-foreground">
                      No geolocation data
                    </div>
                  )}
                </AnimatedContent>

                {/* Relay chain */}
                <AnimatedContent
                  distance={16}
                  direction="vertical"
                  duration={0.4}
                  delay={0.2}
                  threshold={0}
                  className="flex w-72 shrink-0 flex-col overflow-hidden"
                >
                  <Panel
                    title={`Relay Chain · ${result.relay_chain.length} hops`}
                    icon={<Network className="h-3.5 w-3.5" />}
                    className="flex-1 overflow-hidden"
                    scrollable
                  >
                    <div className="space-y-2.5">
                      {result.relay_chain.map((hop, idx) => (
                        <div key={hop.hop} className="relative pl-4">
                          {/* Vertical connector line */}
                          {idx < result.relay_chain.length - 1 && (
                            <span className="absolute top-5 left-1.5 h-[calc(100%+0.5rem)] w-px bg-border" />
                          )}
                          {/* Dot */}
                          <span
                            className={cn(
                              "absolute top-1 left-0 h-3 w-3 rounded-full border-2 bg-background",
                              idx === 0
                                ? "border-foreground"
                                : "border-muted-foreground/40"
                            )}
                          />
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-1.5">
                              <span className="text-xs font-semibold">
                                Hop {hop.hop}
                              </span>
                              {hop.ip_candidates.map((ip) => (
                                <span
                                  key={ip}
                                  className="font-mono text-[10px] text-muted-foreground"
                                >
                                  {ip}
                                </span>
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
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
