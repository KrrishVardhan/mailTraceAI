import type { CSSProperties, ReactElement } from "react"

export interface ElectricLogoProps {
  src?: string
  color?: string
  glowColor?: string
  scale?: number
  intensity?: number
  glow?: number
  thickness?: number
  strands?: number
  bend?: number
  crackle?: number
  arcs?: number
  flicker?: number
  fill?: number
  speed?: number
  interactive?: boolean
  cursorIntensity?: number
  cursorRadius?: number
  theme?: "light" | "dark"
  className?: string
  style?: CSSProperties
}

declare const ElectricLogo: (props: ElectricLogoProps) => ReactElement

export default ElectricLogo
