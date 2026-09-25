import fs from "fs"
import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig, type Plugin } from "vite"

const logoManifestId = "virtual:mailtrace-logo-manifest"
const resolvedLogoManifestId = `\0${logoManifestId}`

function logoManifestPlugin(): Plugin {
  const getLogoUrls = () =>
    fs
      .readdirSync(path.resolve(__dirname, "public/logos"), { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".svg"))
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((entry) => `/logos/${encodeURIComponent(entry.name)}`)

  return {
    name: "mailtrace-logo-manifest",
    resolveId(id) {
      return id === logoManifestId ? resolvedLogoManifestId : undefined
    },
    load(id) {
      if (id !== resolvedLogoManifestId) return undefined
      return `export default ${JSON.stringify(getLogoUrls())}`
    },
    handleHotUpdate({ file, server }) {
      if (file.startsWith(path.resolve(__dirname, "public/logos"))) {
        server.ws.send({ type: "full-reload" })
      }
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [logoManifestPlugin(), react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})
