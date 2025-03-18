import path from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
    test: {
        alias: {
            '@features/': path.resolve(import.meta.dirname, 'src', 'features') + '/',
            '@services/': path.resolve(import.meta.dirname, 'src', 'services') + '/',
            '@infra/': path.resolve(import.meta.dirname, 'src', 'infra') + '/'
        }
    }
})