import type { NextConfig } from "next";

const apiUrl = process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "");

const nextConfig: NextConfig = {
  async rewrites() {
    if (!apiUrl) return [];
    return [{ source: "/backend/:path*", destination: `${apiUrl}/:path*` }];
  },
};

export default nextConfig;

