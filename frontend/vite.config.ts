import fs from "fs"
import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig, type Plugin } from "vite"

const logoManifestId = "virtual:mailtrace-logo-manifest"
const resolvedLogoManifestId = `\0${logoManifestId}`
const logoDirectories = ["public/logos", "public/logo"]

function logoManifestPlugin(): Plugin {
  const getLogoUrls = () =>
    logoDirectories.flatMap((directory) => {
      const absoluteDirectory = path.resolve(__dirname, directory)
      if (!fs.existsSync(absoluteDirectory)) return []

      return fs
        .readdirSync(absoluteDirectory, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".svg"))
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((entry) => `/${directory.replace("public/", "")}/${encodeURIComponent(entry.name)}`)
    })

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
      if (
        logoDirectories.some((directory) =>
          file.startsWith(path.resolve(__dirname, directory))
        )
      ) {
        const manifestModule = server.moduleGraph.getModuleById(
          resolvedLogoManifestId
        )
        if (manifestModule) {
          server.moduleGraph.invalidateModule(manifestModule)
        }
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
