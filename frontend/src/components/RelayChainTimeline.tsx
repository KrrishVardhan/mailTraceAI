/**
 * RelayChainTimeline
 *
 * Forensic-style vertical timeline for the email relay chain.
 * Parses each hop's raw Received: header to extract:
 *   - from-hostname, by-hostname, protocol, timestamp
 * Cross-references geolocation data by IP.
 * Each hop is independently expandable; clicking highlights the hop.
 *
 * Data contract (matches api.ts):
 *   relay_chain: { hop: number; raw: string; ip_candidates: string[] }[]
 *   geolocation:  GeolocationResult[]
 */

import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import {
  ChevronDown,
  ChevronRight,
  Globe,
  Mail,
  Server,
  Network,
  MapPin,
  Clock,
  ArrowDown,
  Inbox,
} from "lucide-react"
import { cn } from "@/lib/utils"
import type { GeolocationResult } from "@/lib/api"

// ── types ──────────────────────────────────────────────────────────────────

interface RelayHop {
  hop: number
  raw: string
  ip_candidates: string[]
}

interface ParsedHop {
  fromHost: string | null
  byHost: string | null
  protocol: string | null
  timestamp: string | null
}

// ── raw-header parser ──────────────────────────────────────────────────────
// Received headers look roughly like:
//   from mail.example.net (mail.example.net [77.32.149.34])
//          by mx.google.com with ESMTPS id abc123
//          ; Thu, 20 Sep 2026 11:42:03 +0000
//
// We extract each field with targeted regexes. All fields are optional
// so we never surface data that isn't actually there.

function parseReceivedHeader(raw: string): ParsedHop {
  // "from <hostname>" — first word after "from" before space or "("
  const fromMatch = raw.match(/\bfrom\s+([\w.\-[\]]+)/i)
  const fromHost = fromMatch?.[1]?.replace(/^\[|\]$/g, "") ?? null

  // "by <hostname>"
  const byMatch = raw.match(/\bby\s+([\w.\-]+)/i)
  const byHost = byMatch?.[1] ?? null

  // "with <protocol>"
  const withMatch = raw.match(/\bwith\s+([A-Z0-9]+(?:TPS?|SSL|S)?)/i)
  const protocol = withMatch?.[1]?.toUpperCase() ?? null

  // Timestamp — after final ";"
  // e.g. "Thu, 20 Sep 2026 11:42:03 +0000 (UTC)"
  const tsMatch = raw.match(/;\s*([A-Za-z,\s\d:+\-]+?)(?:\s*\([^)]+\))?\s*$/)
  let timestamp: string | null = null
  if (tsMatch?.[1]) {
    const trimmed = tsMatch[1].trim()
    // Try to produce a compact readable date
    try {
      const d = new Date(trimmed)
      if (!isNaN(d.getTime())) {
        timestamp = d.toUTCString().replace(" GMT", " UTC")
      } else {
        timestamp = trimmed
      }
    } catch {
      timestamp = trimmed
    }
  }

  return { fromHost, byHost, protocol, timestamp }
}

// ── per-hop icon ───────────────────────────────────────────────────────────

function hopIcon(idx: number, total: number, hasIp: boolean) {
  if (idx === 0) return <Mail className="h-3 w-3" />          // first = likely sender infrastructure
  if (idx === total - 1) return <Inbox className="h-3 w-3" /> // last  = recipient MX
  if (hasIp) return <Server className="h-3 w-3" />            // intermediate with IP = relay
  return <Network className="h-3 w-3" />                       // no IP = internal hop
}

// ── geo lookup helper ──────────────────────────────────────────────────────

function geoForIp(
  ip: string,
  geoResults: GeolocationResult[]
): GeolocationResult | null {
  return geoResults.find((g) => g.status === "success" && g.query === ip) ?? null
}

// ── single hop card ────────────────────────────────────────────────────────

function HopCard({
  hop,
  idx,
  total,
  geoResults,
  isSelected,
  isExpanded,
  onSelect,
  onToggle,
}: {
  hop: RelayHop
  idx: number
  total: number
  geoResults: GeolocationResult[]
  isSelected: boolean
  isExpanded: boolean
  onSelect: () => void
  onToggle: () => void
}) {
  const parsed = parseReceivedHeader(hop.raw)
  const primaryIp = hop.ip_candidates[0] ?? null
  const geo = primaryIp ? geoForIp(primaryIp, geoResults) : null
  const isLast = idx === total - 1
  const isFirst = idx === 0
  const hasIp = hop.ip_candidates.length > 0

  const location =
    geo
      ? [geo.city, geo.regionName, geo.country].filter(Boolean).join(", ")
      : null

  const provider = geo?.org ?? geo?.isp ?? null

  return (
    <div className="relative">
      {/* ── vertical connector line ─────────────────────────────────── */}
      {!isLast && (
        <span
          aria-hidden
          className="absolute left-[11px] top-[22px] w-px bg-border"
          style={{ height: "calc(100% - 2px)" }}
        />
      )}

      {/* ── node + collapsed row ────────────────────────────────────── */}
      <button
        type="button"
        onClick={() => { onSelect(); onToggle() }}
        className={cn(
          "relative flex w-full items-start gap-2.5 rounded-none px-0 py-1 text-left transition-colors",
          "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
          isSelected
            ? "text-foreground"
            : "text-muted-foreground hover:text-foreground"
        )}
      >
        {/* Node circle */}
        <span
          className={cn(
            "relative z-10 mt-0.5 flex h-5.5 w-5.5 shrink-0 items-center justify-center rounded-full border bg-background transition-colors",
            isSelected
              ? isFirst
                ? "border-foreground text-foreground"
                : "border-primary text-primary"
              : isFirst
                ? "border-muted-foreground/60 text-muted-foreground"
                : "border-muted-foreground/30 text-muted-foreground/50"
          )}
          style={{ width: "22px", height: "22px" }}
        >
          {hopIcon(idx, total, hasIp)}
        </span>

        {/* Collapsed summary */}
        <div className="min-w-0 flex-1 pt-0.5">
          <div className="flex items-center gap-1.5">
            <span
              className={cn(
                "text-[10px] font-semibold tracking-widest uppercase",
                isSelected ? "text-foreground" : "text-muted-foreground"
              )}
            >
              Hop {hop.hop}
            </span>
            {isFirst && (
              <Badge
                variant="outline"
                className="h-3.5 rounded-none border-muted-foreground/30 px-1 text-[9px] uppercase tracking-wide text-muted-foreground"
              >
                origin
              </Badge>
            )}
            {isLast && (
              <Badge
                variant="outline"
                className="h-3.5 rounded-none border-muted-foreground/30 px-1 text-[9px] uppercase tracking-wide text-muted-foreground"
              >
                recipient
              </Badge>
            )}
            <span className="ml-auto shrink-0 text-muted-foreground/40">
              {isExpanded ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
            </span>
          </div>

          {/* Always-visible summary line */}
          {primaryIp && (
            <p className="mt-0.5 font-mono text-[11px] leading-tight text-foreground/80">
              {primaryIp}
            </p>
          )}
          {!primaryIp && parsed.byHost && (
            <p className="mt-0.5 truncate text-[10px] leading-tight text-muted-foreground">
              {parsed.byHost}
            </p>
          )}
          {location && (
            <p className="mt-0.5 truncate text-[10px] leading-tight text-muted-foreground">
              {location}
            </p>
          )}
        </div>
      </button>

      {/* ── expanded detail ──────────────────────────────────────────── */}
      {isExpanded && (
        <div className="ml-[34px] mb-2 space-y-2 border-l border-border/50 pl-3">

          {/* Observed IP(s) */}
          {hop.ip_candidates.length > 0 && (
            <div>
              <p className="mb-0.5 text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                Observed IP
              </p>
              <div className="flex flex-wrap gap-1">
                {hop.ip_candidates.map((ip) => (
                  <code
                    key={ip}
                    className="rounded-none border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-foreground"
                  >
                    {ip}
                  </code>
                ))}
              </div>
            </div>
          )}

          {/* From / By hosts */}
          {(parsed.fromHost || parsed.byHost) && (
            <div className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5">
              {parsed.fromHost && (
                <>
                  <span className="text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/70 pt-0.5">
                    From
                  </span>
                  <span className="break-all font-mono text-[10px] text-foreground/80">
                    {parsed.fromHost}
                  </span>
                </>
              )}
              {parsed.byHost && (
                <>
                  <span className="text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/70 pt-0.5">
                    By
                  </span>
                  <span className="break-all font-mono text-[10px] text-foreground/80">
                    {parsed.byHost}
                  </span>
                </>
              )}
              {parsed.protocol && (
                <>
                  <span className="text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/70 pt-0.5">
                    Protocol
                  </span>
                  <span className="font-mono text-[10px] text-foreground/80">
                    {parsed.protocol}
                  </span>
                </>
              )}
            </div>
          )}

          {/* Geo data */}
          {geo && (
            <div>
              <p className="mb-0.5 text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                Observed Location
              </p>
              <div className="space-y-0.5">
                {location && (
                  <div className="flex items-start gap-1">
                    <MapPin className="mt-0.5 h-2.5 w-2.5 shrink-0 text-muted-foreground/50" />
                    <span className="text-[10px] text-foreground/80">{location}</span>
                  </div>
                )}
                {provider && (
                  <div className="flex items-start gap-1">
                    <Network className="mt-0.5 h-2.5 w-2.5 shrink-0 text-muted-foreground/50" />
                    <span className="break-words text-[10px] text-foreground/80">{provider}</span>
                  </div>
                )}
                {geo.as && (
                  <p className="font-mono text-[9px] text-muted-foreground/60 pl-3.5">{geo.as}</p>
                )}
                <div className="flex flex-wrap gap-1 pt-0.5">
                  {geo.masking?.likely_masked && (
                    <Badge
                      variant="outline"
                      className="h-3.5 rounded-none border-yellow-500/40 px-1 text-[9px] text-yellow-600 dark:text-yellow-400"
                    >
                      provider infra
                    </Badge>
                  )}
                  {geo.hosting && !geo.masking?.likely_masked && (
                    <Badge
                      variant="outline"
                      className="h-3.5 rounded-none px-1 text-[9px] text-muted-foreground"
                    >
                      datacenter
                    </Badge>
                  )}
                  {geo.proxy && (
                    <Badge
                      variant="outline"
                      className="h-3.5 rounded-none border-destructive/40 px-1 text-[9px] text-destructive"
                    >
                      proxy / VPN
                    </Badge>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Timestamp */}
          {parsed.timestamp && (
            <div className="flex items-start gap-1">
              <Clock className="mt-0.5 h-2.5 w-2.5 shrink-0 text-muted-foreground/50" />
              <div>
                <p className="mb-0.5 text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                  Received Timestamp
                </p>
                <p className="font-mono text-[10px] text-foreground/80">{parsed.timestamp}</p>
              </div>
            </div>
          )}

          {/* Raw header */}
          <div>
            <p className="mb-0.5 text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/70">
              Raw Header
            </p>
            <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-none border border-border bg-muted px-2 py-1.5 font-mono text-[9px] leading-relaxed text-muted-foreground">
              {hop.raw}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}

// ── main component ─────────────────────────────────────────────────────────

export interface RelayChainTimelineProps {
  relayChain: RelayHop[]
  geoResults: GeolocationResult[]
}

export function RelayChainTimeline({
  relayChain,
  geoResults,
}: RelayChainTimelineProps) {
  const [selectedHop, setSelectedHop] = useState<number | null>(null)
  const [expandedHops, setExpandedHops] = useState<Set<number>>(new Set())

  function toggleExpand(hop: number) {
    setExpandedHops((prev) => {
      const next = new Set(prev)
      if (next.has(hop)) {
        next.delete(hop)
      } else {
        next.add(hop)
      }
      return next
    })
  }

  if (relayChain.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">No relay hops found in headers.</p>
    )
  }

  return (
    <div className="space-y-0">
      {relayChain.map((hop, idx) => (
        <HopCard
          key={hop.hop}
          hop={hop}
          idx={idx}
          total={relayChain.length}
          geoResults={geoResults}
          isSelected={selectedHop === hop.hop}
          isExpanded={expandedHops.has(hop.hop)}
          onSelect={() =>
            setSelectedHop((prev) => (prev === hop.hop ? null : hop.hop))
          }
          onToggle={() => toggleExpand(hop.hop)}
        />
      ))}

      {/* Terminal marker */}
      <div className="relative flex items-center gap-2.5 pt-0.5">
        <span
          className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-dashed border-muted-foreground/30 bg-background text-muted-foreground/40"
          style={{ width: "22px", height: "22px" }}
        >
          <ArrowDown className="h-2.5 w-2.5" />
        </span>
        <span className="text-[9px] font-semibold uppercase tracking-widest text-muted-foreground/40">
          Delivered
        </span>
      </div>
    </div>
  )
}
