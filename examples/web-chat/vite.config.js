// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { defineConfig, searchForWorkspaceRoot } from 'vite';
import basicSsl from '@vitejs/plugin-basic-ssl';

// HTTPS (basic-ssl) is required: phones on the LAN are a non-localhost
// origin, and the SDK's OPFS storage + WebCrypto need a secure context.
//
// COOP/COEP: NOT needed. Verified against @xmtp/browser-sdk 7.0.0's shipped
// bundle — it spawns dedicated module Workers and uses OPFS sync access
// handles; there is no SharedArrayBuffer anywhere, so the page does not have
// to be cross-origin isolated. (Confirmed empirically by the e2e run.)
export default defineConfig({
  plugins: [basicSsl()],
  optimizeDeps: {
    // Per the SDK README: these packages load workers/wasm via
    // import.meta.url and must not be pre-bundled by the dev server.
    exclude: ['@xmtp/browser-sdk', '@xmtp/wasm-bindings'],
  },
  server: {
    host: true, // listen on the LAN so phones can reach us
    fs: {
      // @open-wallet-messaging/core is imported by relative path from two levels up.
      allow: [searchForWorkspaceRoot(process.cwd())],
    },
  },
  preview: {
    host: true, // basic-ssl applies to `vite preview` as well
  },
});
