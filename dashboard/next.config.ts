import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Self-contained server bundle so the Docker runner stage needs no node_modules.
  output: "standalone",
};

export default nextConfig;
